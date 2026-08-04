"""ScanService.summary() previously built its merged dict from an explicit
allowlist of keys that never included config_findings/dependency_findings/
dependency_control_result/capability_findings/scanned_files (pre-existing,
predates the DAST work) or dynamic_findings/discovered_forms (new) — so all
of these were silently dropped from the API response even though the scan
worker wrote them into Mongo. This locks in that they now actually pass
through ScanSummary end to end.
"""
import pytest
from mongomock_motor import AsyncMongoMockClient

from app.services.scan_service import ScanService


@pytest.mark.asyncio
async def test_summary_includes_all_finding_fields():
    db = AsyncMongoMockClient()["test"]
    scan_id = "scan-summary-test"
    await db.scans.insert_one({
        "scan_id": scan_id,
        "user_id": "507f1f77bcf86cd799439011",
        "state": "COMPLETED",
        "input_type": "REPOSITORY",
        "summary": {
            "status": "COMPLETED",
            "input_type": "REPOSITORY",
            "total_files": 3,
            "files_scanned": 3,
            "vulnerabilities_found": 1,
            "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0},
            "duration_seconds": 1.2,
            "created_at": "2026-01-01T00:00:00",
            "completed_at": "2026-01-01T00:00:05",
            "vulnerabilities": [{"rule_id": "SQL_INJECTION"}],
            "scanned_files": ["app.py", "utils.py"],
            "config_findings": [{"control_id": "V14.4.1"}],
            "dependency_findings": [{"package": "flask", "cve": "CVE-XXXX"}],
            "dependency_control_result": {"verdict": "fail"},
            "capability_findings": [{"control_id": "V6.2.2"}],
            "dynamic_findings": [{"rule_id": "OPEN_REDIRECT_LIVE", "verdict": "fail"}],
            "discovered_forms": [{"action_url": "https://x/search", "method": "GET", "fields": ["q"]}],
        },
    })

    svc = ScanService(db)
    result = await svc.summary(scan_id)

    assert result.scanned_files == ["app.py", "utils.py"]
    assert result.config_findings == [{"control_id": "V14.4.1"}]
    assert result.dependency_findings == [{"package": "flask", "cve": "CVE-XXXX"}]
    assert result.dependency_control_result == {"verdict": "fail"}
    assert result.capability_findings == [{"control_id": "V6.2.2"}]
    assert result.dynamic_findings == [{"rule_id": "OPEN_REDIRECT_LIVE", "verdict": "fail"}]
    assert result.discovered_forms[0]["action_url"] == "https://x/search"


@pytest.mark.asyncio
async def test_summary_fields_default_to_none_when_absent():
    db = AsyncMongoMockClient()["test"]
    scan_id = "scan-summary-minimal"
    await db.scans.insert_one({
        "scan_id": scan_id,
        "user_id": "507f1f77bcf86cd799439011",
        "state": "COMPLETED",
        "summary": {
            "status": "COMPLETED", "input_type": "DIRECT_CODE",
            "total_files": 1, "files_scanned": 1, "vulnerabilities_found": 0,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "duration_seconds": 0.5, "created_at": "2026-01-01T00:00:00",
            "vulnerabilities": [],
        },
    })

    svc = ScanService(db)
    result = await svc.summary(scan_id)

    assert result.dynamic_findings is None
    assert result.discovered_forms is None
    assert result.config_findings is None
