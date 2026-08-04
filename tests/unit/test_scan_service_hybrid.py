"""Phase 5 — scan_type="hybrid" on _run_repository_scan: runs the static
pipeline and the full DAST engine together, then does basic control-ID
correlation between the two result sets.

Mocks the repo clone (writes one dummy file instead of really cloning),
the static pipeline's analyze_repository, and _run_dynamic_checks — this
tests the hybrid glue (merging + correlation), not the static pipeline or
DAST engine themselves (covered elsewhere already).
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mongomock_motor import AsyncMongoMockClient

from app.services.scan_service import ScanService
from semantic_engine.pipeline import AnalysisResult

TARGET = "https://example.com"  # DNS-resolvable, matches other test files' convention


def _fake_analysis_result(vulnerabilities):
    return AnalysisResult(
        filename="repository", language="multi", lines_of_code=10,
        analysis_time_seconds=0.1, graph_nodes=1, graph_edges=1, rules_executed=1,
        slices_found=len(vulnerabilities), vulnerabilities_found=len(vulnerabilities),
        vulnerabilities=vulnerabilities, graph_data=None, warnings=[], errors=[], success=True,
        config_findings=[], dependency_findings=[], dependency_control_result=None,
        capability_findings=[],
    )


async def _make_service_with_repo(tmp_path):
    db = AsyncMongoMockClient()["test"]
    svc = ScanService(db)
    scan_id = "scan-hybrid-1"
    await db.scans.insert_one({"scan_id": scan_id, "state": "PENDING"})

    def _fake_clone(self, url, branch, token, dest_dir):
        dest_dir.mkdir(parents=True, exist_ok=True)
        (dest_dir / "app.py").write_text("print('hello')\n", encoding="utf-8")

    return svc, db, scan_id, _fake_clone


class TestHybridScan:
    @pytest.mark.asyncio
    async def test_dynamic_findings_and_forms_reach_summary(self, tmp_path):
        svc, db, scan_id, fake_clone = await _make_service_with_repo(tmp_path)
        static_result = _fake_analysis_result([])
        dynamic_findings = [{
            "control_id": "V3.7.2", "verdict": "fail", "rule_id": "OPEN_REDIRECT_LIVE",
            "url": f"{TARGET}/next-link", "method": "GET", "note": "redirect", "severity": "medium",
            "confidence": 0.8,
        }]
        discovered_forms = [{"action_url": f"{TARGET}/search", "method": "GET", "fields": ["q"]}]

        with patch.object(ScanService, "_clone_repo", fake_clone), \
             patch("app.services.scan_service.get_pipeline") as mock_get_pipeline, \
             patch.object(ScanService, "_run_dynamic_checks",
                          AsyncMock(return_value=(dynamic_findings, discovered_forms))):
            mock_pipeline = MagicMock()
            mock_pipeline.analyze_repository = AsyncMock(return_value=static_result)
            mock_get_pipeline.return_value = mock_pipeline

            await svc._run_repository_scan(
                scan_id, repo_id=1, branch="main", scan_mode="DEEP",
                repo_url="https://git.example/repo.git", repo_provider="GIT", repo_token=None,
                file_paths=None, target_url=TARGET, scan_type="hybrid",
            )

        doc = await db.scans.find_one({"scan_id": scan_id})
        summary = doc["summary"]
        assert summary["dynamic_findings"] == dynamic_findings
        assert summary["discovered_forms"] == discovered_forms
        assert summary["vulnerabilities_found"] == 1  # 0 static + 1 dynamic fail
        assert summary["by_severity"]["medium"] == 1

    @pytest.mark.asyncio
    async def test_static_finding_gets_dynamic_confirmed_when_controls_match(self, tmp_path):
        svc, db, scan_id, fake_clone = await _make_service_with_repo(tmp_path)
        static_vuln = {
            "type": "UNVALIDATED_REDIRECT", "severity": "medium", "asvs_controls": ["V3.7.2"],
            "location": {"file": "app.py", "start_line": 5, "end_line": 5},
        }
        static_result = _fake_analysis_result([dict(static_vuln)])
        dynamic_findings = [{
            "control_id": "V3.7.2", "verdict": "fail", "rule_id": "OPEN_REDIRECT_LIVE",
            "url": f"{TARGET}/next-link", "method": "GET", "note": "redirect", "severity": "medium",
            "confidence": 0.8,
        }]

        with patch.object(ScanService, "_clone_repo", fake_clone), \
             patch("app.services.scan_service.get_pipeline") as mock_get_pipeline, \
             patch.object(ScanService, "_run_dynamic_checks", AsyncMock(return_value=(dynamic_findings, []))):
            mock_pipeline = MagicMock()
            mock_pipeline.analyze_repository = AsyncMock(return_value=static_result)
            mock_get_pipeline.return_value = mock_pipeline

            await svc._run_repository_scan(
                scan_id, repo_id=1, branch="main", scan_mode="DEEP",
                repo_url="https://git.example/repo.git", repo_provider="GIT", repo_token=None,
                file_paths=None, target_url=TARGET, scan_type="hybrid",
            )

        doc = await db.scans.find_one({"scan_id": scan_id})
        summary = doc["summary"]
        assert summary["vulnerabilities"][0]["dynamic_confirmed"] is True
        assert summary["dynamic_findings"][0]["corroborates_static_finding"] is True

    @pytest.mark.asyncio
    async def test_no_correlation_when_controls_differ(self, tmp_path):
        svc, db, scan_id, fake_clone = await _make_service_with_repo(tmp_path)
        static_vuln = {
            "type": "SQL_INJECTION", "severity": "high", "asvs_controls": ["V5.3.4"],
            "location": {"file": "app.py", "start_line": 1, "end_line": 1},
        }
        static_result = _fake_analysis_result([dict(static_vuln)])
        dynamic_findings = [{
            "control_id": "V3.7.2", "verdict": "fail", "rule_id": "OPEN_REDIRECT_LIVE",
            "url": f"{TARGET}/next-link", "method": "GET", "note": "redirect", "severity": "medium",
            "confidence": 0.8,
        }]

        with patch.object(ScanService, "_clone_repo", fake_clone), \
             patch("app.services.scan_service.get_pipeline") as mock_get_pipeline, \
             patch.object(ScanService, "_run_dynamic_checks", AsyncMock(return_value=(dynamic_findings, []))):
            mock_pipeline = MagicMock()
            mock_pipeline.analyze_repository = AsyncMock(return_value=static_result)
            mock_get_pipeline.return_value = mock_pipeline

            await svc._run_repository_scan(
                scan_id, repo_id=1, branch="main", scan_mode="DEEP",
                repo_url="https://git.example/repo.git", repo_provider="GIT", repo_token=None,
                file_paths=None, target_url=TARGET, scan_type="hybrid",
            )

        doc = await db.scans.find_one({"scan_id": scan_id})
        summary = doc["summary"]
        assert "dynamic_confirmed" not in summary["vulnerabilities"][0]
        assert "corroborates_static_finding" not in summary["dynamic_findings"][0]

    @pytest.mark.asyncio
    async def test_static_only_scan_does_not_invoke_dynamic_engine(self, tmp_path):
        svc, db, scan_id, fake_clone = await _make_service_with_repo(tmp_path)
        static_result = _fake_analysis_result([])
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
        doc = await db.scans.find_one({"scan_id": scan_id})
        assert doc["summary"]["dynamic_findings"] == []
