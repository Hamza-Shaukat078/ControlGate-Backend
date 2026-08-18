"""ScanStart.enable_llm threaded through ScanService into the PipelineConfig
each scan worker builds — added after a real Juice Shop static scan showed
LLM classification (all providers failing/rate-limited) dominating wall-clock
time on a large repo with no way to skip it. Mocks get_pipeline/
analyze_repository — this tests only that the right enable_llm value reaches
PipelineConfig, not the pipeline itself.
"""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mongomock_motor import AsyncMongoMockClient

from app.services.scan_service import ScanService
from semantic_engine.pipeline import AnalysisResult


def _fake_analysis_result():
    return AnalysisResult(
        filename="repository", language="multi", lines_of_code=10,
        analysis_time_seconds=0.1, graph_nodes=1, graph_edges=1, rules_executed=1,
        slices_found=0, vulnerabilities_found=0,
        vulnerabilities=[], graph_data=None, warnings=[], errors=[], success=True,
        config_findings=[], dependency_findings=[], dependency_control_result=None,
        capability_findings=[],
    )


async def _make_service():
    db = AsyncMongoMockClient()["test"]
    return ScanService(db), db


class TestRepositoryScanLlmToggle:
    @pytest.mark.asyncio
    async def test_enable_llm_true_by_default(self):
        svc, db = await _make_service()
        scan_id = "scan-llm-1"
        await db.scans.insert_one({"scan_id": scan_id, "state": "PENDING"})

        def fake_clone(self, url, branch, token, dest_dir):
            dest_dir.mkdir(parents=True, exist_ok=True)
            (dest_dir / "app.py").write_text("print('hi')\n", encoding="utf-8")

        mock_get_pipeline = MagicMock()
        mock_pipeline = MagicMock()
        mock_pipeline.analyze_repository = AsyncMock(return_value=_fake_analysis_result())
        mock_get_pipeline.return_value = mock_pipeline

        with patch.object(ScanService, "_clone_repo", fake_clone), \
             patch("app.services.scan_service.get_pipeline", mock_get_pipeline):
            await svc._run_repository_scan(
                scan_id, repo_id=1, branch="main", scan_mode="DEEP",
                repo_url="https://git.example/repo.git", repo_provider="GIT", repo_token=None,
                file_paths=None, target_url=None, scan_type="static",
            )

        config_passed = mock_get_pipeline.call_args.args[0]
        assert config_passed.enable_llm is True

    @pytest.mark.asyncio
    async def test_enable_llm_false_reaches_pipeline_config(self):
        svc, db = await _make_service()
        scan_id = "scan-llm-2"
        await db.scans.insert_one({"scan_id": scan_id, "state": "PENDING"})

        def fake_clone(self, url, branch, token, dest_dir):
            dest_dir.mkdir(parents=True, exist_ok=True)
            (dest_dir / "app.py").write_text("print('hi')\n", encoding="utf-8")

        mock_get_pipeline = MagicMock()
        mock_pipeline = MagicMock()
        mock_pipeline.analyze_repository = AsyncMock(return_value=_fake_analysis_result())
        mock_get_pipeline.return_value = mock_pipeline

        with patch.object(ScanService, "_clone_repo", fake_clone), \
             patch("app.services.scan_service.get_pipeline", mock_get_pipeline):
            await svc._run_repository_scan(
                scan_id, repo_id=1, branch="main", scan_mode="DEEP",
                repo_url="https://git.example/repo.git", repo_provider="GIT", repo_token=None,
                file_paths=None, target_url=None, scan_type="static",
                enable_llm=False,
            )

        config_passed = mock_get_pipeline.call_args.args[0]
        assert config_passed.enable_llm is False

    @pytest.mark.asyncio
    async def test_start_forwards_enable_llm_to_repository_worker(self):
        svc, db = await _make_service()
        run_repo_scan_mock = AsyncMock()
        with patch.object(ScanService, "_run_repository_scan", run_repo_scan_mock):
            scan_id, _ = await svc.start(
                user_id="507f1f77bcf86cd799439011", repo_id=1, enable_llm=False,
            )
            for _ in range(20):
                doc = await db.scans.find_one({"scan_id": scan_id})
                if doc:
                    break

        run_repo_scan_mock.assert_called_once()
        # start()'s dispatch into _run_repository_scan is keyword-only (see
        # scan_service.py's comment there) — enable_llm is a kwarg now, not
        # the last positional arg.
        assert run_repo_scan_mock.call_args.kwargs["enable_llm"] is False


class TestDirectCodeScanLlmToggle:
    @pytest.mark.asyncio
    async def test_enable_llm_false_reaches_pipeline_config(self):
        svc, db = await _make_service()
        scan_id = "scan-llm-3"
        await db.scans.insert_one({"scan_id": scan_id, "state": "PENDING"})

        mock_get_pipeline = MagicMock()
        mock_pipeline = MagicMock()
        mock_pipeline.analyze_code = AsyncMock(return_value=_fake_analysis_result())
        mock_get_pipeline.return_value = mock_pipeline

        with patch("app.services.scan_service.get_pipeline", mock_get_pipeline):
            await svc._run_direct_code_scan(
                scan_id, "print(1)", "python", "app.py", "DEEP", enable_llm=False,
            )

        config_passed = mock_get_pipeline.call_args.args[0]
        assert config_passed.enable_llm is False
