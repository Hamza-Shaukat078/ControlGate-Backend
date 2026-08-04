"""Bridge wiring (app/domain/analysis/dast/bridge.py) into _run_repository_scan's
hybrid path — verifies build_dynamic_targets() runs against the real cloned repo
and that a FAIL from a bridge-originated dynamic finding marks the exact static
finding it re-tested as confirmed, not just any finding sharing the control id.

Mocks the repo clone and static pipeline (same pattern as test_scan_service_hybrid.py)
but leaves build_dynamic_targets() itself real — this is the one place bridge.py's
route resolution runs against an actual file on disk instead of a hand-built dict.
"""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mongomock_motor import AsyncMongoMockClient

from app.services.scan_service import ScanService
from semantic_engine.pipeline import AnalysisResult

TARGET = "https://example.com"

FLASK_APP_SOURCE = """\
from flask import Flask, request, redirect

app = Flask(__name__)


@app.route("/go")
def go():
    target = request.args.get("next")
    return redirect(target)
"""


def _fake_analysis_result(vulnerabilities):
    return AnalysisResult(
        filename="repository", language="multi", lines_of_code=10,
        analysis_time_seconds=0.1, graph_nodes=1, graph_edges=1, rules_executed=1,
        slices_found=len(vulnerabilities), vulnerabilities_found=len(vulnerabilities),
        vulnerabilities=vulnerabilities, graph_data=None, warnings=[], errors=[], success=True,
        config_findings=[], dependency_findings=[], dependency_control_result=None,
        capability_findings=[],
    )


async def _make_service_with_flask_repo():
    db = AsyncMongoMockClient()["test"]
    svc = ScanService(db)
    scan_id = "scan-bridge-1"
    await db.scans.insert_one({"scan_id": scan_id, "state": "PENDING"})

    def _fake_clone(self, url, branch, token, dest_dir):
        dest_dir.mkdir(parents=True, exist_ok=True)
        (dest_dir / "app.py").write_text(FLASK_APP_SOURCE, encoding="utf-8")

    return svc, db, scan_id, _fake_clone


class TestBridgeTargetsComputedForHybridScan:
    @pytest.mark.asyncio
    async def test_bridge_target_passed_to_dynamic_checks(self):
        svc, db, scan_id, fake_clone = await _make_service_with_flask_repo()
        static_vuln = {
            "id": "vuln-1", "type": "UNVALIDATED_REDIRECT", "severity": "medium",
            "asvs_controls": ["V3.7.2"],
            "location": {"file": "app.py", "start_line": 8, "end_line": 9},
        }
        static_result = _fake_analysis_result([dict(static_vuln)])
        run_dynamic_checks_mock = AsyncMock(return_value=([], []))

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
        bridge_targets = run_dynamic_checks_mock.await_args.args[-1]
        assert len(bridge_targets) == 1
        target = bridge_targets[0]
        assert target.dynamic_rule_id == "OPEN_REDIRECT_LIVE"
        assert target.static_rule_id == "UNVALIDATED_REDIRECT"
        assert target.static_finding_id == "vuln-1"
        assert target.url == f"{TARGET}/go"

    @pytest.mark.asyncio
    async def test_no_bridge_targets_for_unmapped_rule(self):
        svc, db, scan_id, fake_clone = await _make_service_with_flask_repo()
        static_vuln = {
            "id": "vuln-2", "type": "SQL_INJECTION", "severity": "high",
            "asvs_controls": ["V5.3.4"],
            "location": {"file": "app.py", "start_line": 8, "end_line": 9},
        }
        static_result = _fake_analysis_result([dict(static_vuln)])
        run_dynamic_checks_mock = AsyncMock(return_value=([], []))

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

        bridge_targets = run_dynamic_checks_mock.await_args.args[-1]
        assert bridge_targets == []

    @pytest.mark.asyncio
    async def test_bridge_fail_marks_exact_static_finding_confirmed(self):
        svc, db, scan_id, fake_clone = await _make_service_with_flask_repo()
        static_vuln = {
            "id": "vuln-1", "type": "UNVALIDATED_REDIRECT", "severity": "medium",
            "asvs_controls": ["V3.7.2"],
            "location": {"file": "app.py", "start_line": 8, "end_line": 9},
        }
        static_result = _fake_analysis_result([dict(static_vuln)])
        dynamic_findings = [{
            "control_id": "V3.7.2", "verdict": "fail", "rule_id": "OPEN_REDIRECT_LIVE",
            "url": f"{TARGET}/go", "method": "GET", "note": "confirmed live",
            "severity": "medium", "confidence": 0.8,
            "evidence": "bridge:vuln-1:app.py:8",
        }]

        with patch.object(ScanService, "_clone_repo", fake_clone), \
             patch("app.services.scan_service.get_pipeline") as mock_get_pipeline, \
             patch.object(ScanService, "_run_dynamic_checks",
                          AsyncMock(return_value=(dynamic_findings, []))):
            mock_pipeline = MagicMock()
            mock_pipeline.analyze_repository = AsyncMock(return_value=static_result)
            mock_get_pipeline.return_value = mock_pipeline

            await svc._run_repository_scan(
                scan_id, repo_id=1, branch="main", scan_mode="DEEP",
                repo_url="https://git.example/repo.git", repo_provider="GIT", repo_token=None,
                file_paths=None, target_url=TARGET, scan_type="hybrid",
            )

        doc = await db.scans.find_one({"scan_id": scan_id})
        vuln = doc["summary"]["vulnerabilities"][0]
        assert vuln["dynamic_confirmed"] is True
        assert vuln["bridge_confirmed"] is True

    @pytest.mark.asyncio
    async def test_static_only_scan_never_computes_bridge_targets(self):
        svc, db, scan_id, fake_clone = await _make_service_with_flask_repo()
        static_vuln = {
            "id": "vuln-1", "type": "UNVALIDATED_REDIRECT", "severity": "medium",
            "asvs_controls": ["V3.7.2"],
            "location": {"file": "app.py", "start_line": 8, "end_line": 9},
        }
        static_result = _fake_analysis_result([dict(static_vuln)])
        run_dynamic_checks_mock = AsyncMock(return_value=([], []))

        with patch.object(ScanService, "_clone_repo", fake_clone), \
             patch("app.services.scan_service.get_pipeline") as mock_get_pipeline, \
             patch.object(ScanService, "_run_dynamic_checks", run_dynamic_checks_mock):
            mock_pipeline = MagicMock()
            mock_pipeline.analyze_repository = AsyncMock(return_value=static_result)
            mock_get_pipeline.return_value = mock_pipeline

            await svc._run_repository_scan(
                scan_id, repo_id=1, branch="main", scan_mode="DEEP",
                repo_url="https://git.example/repo.git", repo_provider="GIT", repo_token=None,
                file_paths=None, target_url=TARGET, scan_type="static",
            )

        run_dynamic_checks_mock.assert_not_called()
