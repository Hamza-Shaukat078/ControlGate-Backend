"""Automatic source-route discovery (bridge.discover_routes_from_source)
wired into _run_dynamic_checks's hybrid path via the repo_root kwarg —
closes the gap where an API-only target (no crawlable HTML, no published
OpenAPI spec) gave the dynamic engine no way to discover its own endpoints.

Uses real files on disk (tmp_path) for discover_routes_from_source itself —
same "leave the real thing real" precedent as
test_scan_service_bridge_wiring.py — and mocks run_payload_checks/crawl to
inspect what check_urls it actually received.
"""
import socket
from unittest.mock import AsyncMock, patch

import pytest
from mongomock_motor import AsyncMongoMockClient

from app.domain.analysis.dast.crawler import CrawlResult
from app.services.scan_service import ScanService

TARGET = "https://example.com"

FLASK_API_SOURCE = """\
from flask import Flask
app = Flask(__name__)


@app.route("/api/orders/<int:order_id>", methods=["DELETE"])
def delete_order(order_id):
    ...
"""


@pytest.fixture(autouse=True)
def _mock_dns(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))],
    )


class _FakeSessionPair:
    last_config = None

    def __init__(self, config):
        _FakeSessionPair.last_config = config
        self.primary = object()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False


async def _make_service():
    db = AsyncMongoMockClient()["test"]
    return ScanService(db), db


class TestSourceRouteDiscoveryWiring:
    @pytest.mark.asyncio
    async def test_repo_root_none_never_calls_discovery(self, tmp_path):
        svc, db = await _make_service()
        discover_mock = AsyncMock()  # would be a plain function, AsyncMock just to assert call count
        run_checks_mock = AsyncMock(return_value=[])
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult(urls=[TARGET]))), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", run_checks_mock), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.bridge.discover_routes_from_source", discover_mock):
            await svc._run_dynamic_checks("scan-src-1", TARGET)  # repo_root defaults to None

        discover_mock.assert_not_called()

    @pytest.mark.asyncio
    async def test_repo_root_set_discovers_and_folds_urls_into_check_urls(self, tmp_path):
        svc, db = await _make_service()
        (tmp_path / "app.py").write_text(FLASK_API_SOURCE, encoding="utf-8")
        run_checks_mock = AsyncMock(return_value=[])
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult(urls=[TARGET]))), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", run_checks_mock), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)):
            await svc._run_dynamic_checks("scan-src-2", TARGET, repo_root=tmp_path)

        called_urls = run_checks_mock.call_args.args[1]
        assert f"{TARGET}/api/orders/1" in called_urls

    @pytest.mark.asyncio
    async def test_no_truncation_for_a_repo_with_many_routes(self, tmp_path):
        # Regression: scan_service.py used to re-truncate discover_routes_
        # from_source's own (already-uncapped) output down to 15 at the
        # merge step — explicit user request to remove that too.
        svc, db = await _make_service()
        lines = []
        for i in range(25):
            lines.append(f"@app.route('/r{i}')")
            lines.append(f"def r{i}():\n    ...\n")
        (tmp_path / "app.py").write_text(
            "from flask import Flask\napp = Flask(__name__)\n\n" + "\n".join(lines), encoding="utf-8",
        )
        run_checks_mock = AsyncMock(return_value=[])
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult(urls=[TARGET]))), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", run_checks_mock), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)):
            await svc._run_dynamic_checks("scan-src-5", TARGET, repo_root=tmp_path)

        called_urls = run_checks_mock.call_args.args[1]
        discovered = [u for u in called_urls if u.startswith(f"{TARGET}/r")]
        assert len(discovered) == 25

    @pytest.mark.asyncio
    async def test_discovery_failure_does_not_abort_scan(self, tmp_path):
        svc, db = await _make_service()
        run_checks_mock = AsyncMock(return_value=[])
        await db.scans.insert_one({"scan_id": "scan-src-3", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult(urls=[TARGET]))), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", run_checks_mock), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.bridge.discover_routes_from_source",
                   side_effect=RuntimeError("disk read failed")):
            await svc._run_dynamic_checks("scan-src-3", TARGET, repo_root=tmp_path)

        doc = await db.scans.find_one({"scan_id": "scan-src-3"})
        # _run_dynamic_checks doesn't itself flip scan state (its caller
        # does) — the real assertion here is that it returned normally
        # rather than propagating the exception.
        called_urls = run_checks_mock.call_args.args[1]
        assert called_urls == [TARGET]

    @pytest.mark.asyncio
    async def test_repository_scan_passes_its_own_repo_root_through(self, tmp_path):
        svc, db = await _make_service()
        scan_id = "scan-src-4"
        await db.scans.insert_one({"scan_id": scan_id, "state": "PENDING"})

        def fake_clone(self, url, branch, token, dest_dir):
            dest_dir.mkdir(parents=True, exist_ok=True)
            (dest_dir / "app.py").write_text(FLASK_API_SOURCE, encoding="utf-8")

        # _run_repository_scan deletes its temp clone dir in a finally block
        # once it returns — capture whether app.py was visible *during* the
        # call (from inside the mock, before cleanup), not after.
        seen = {}

        async def _fake_run_dynamic_checks(*args, **kwargs):
            repo_root = kwargs.get("repo_root")
            seen["repo_root_had_app_py"] = bool(repo_root and (repo_root / "app.py").exists())
            return [], []

        run_dynamic_checks_mock = AsyncMock(side_effect=_fake_run_dynamic_checks)
        from unittest.mock import MagicMock
        from semantic_engine.pipeline import AnalysisResult

        static_result = AnalysisResult(
            filename="repository", language="multi", lines_of_code=10,
            analysis_time_seconds=0.1, graph_nodes=1, graph_edges=1, rules_executed=1,
            slices_found=0, vulnerabilities_found=0,
            vulnerabilities=[], graph_data=None, warnings=[], errors=[], success=True,
            config_findings=[], dependency_findings=[], dependency_control_result=None,
            capability_findings=[],
        )
        with patch.object(ScanService, "_clone_repo", fake_clone), \
             patch("app.services.scan_service.get_pipeline") as mock_get_pipeline, \
             patch.object(ScanService, "_run_dynamic_checks", run_dynamic_checks_mock):
            mock_pipeline = MagicMock()
            mock_pipeline.analyze_repository = AsyncMock(return_value=static_result)
            mock_get_pipeline.return_value = mock_pipeline

            await svc._run_repository_scan(
                scan_id, repo_id=1, branch="main", scan_mode="DEEP",
                repo_url="https://git.example/repo.git", repo_provider="GIT", repo_token=None,
                file_paths=None, target_url=TARGET, scan_type="hybrid",
            )

        run_dynamic_checks_mock.assert_awaited_once()
        assert run_dynamic_checks_mock.await_args.kwargs["repo_root"] is not None
        assert seen["repo_root_had_app_py"] is True
