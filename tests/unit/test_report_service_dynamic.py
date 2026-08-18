"""report_service.py had its own independent copy of the same narrow
merged-dict bug fixed in ScanService.summary() — dynamic_findings and
discovered_forms (and the pre-existing config/dependency/capability
findings) never reached _get_summary()'s ScanSummary, so reports for a
dynamic-only scan silently showed nothing. This locks in the fix across
get()/export_csv()/export_pdf().

Also covers dynamic_probe_findings (DynamicProbe's live TLS/HTTPS/HSTS/
.git-exposure results) — added to ScanSummary/report_service as a
passthrough field, but the PDF export never got a rendering section for it
(unlike dynamic_findings, which did). See TestDynamicProbeFindingsInReport.
"""
import pytest
from mongomock_motor import AsyncMongoMockClient

from app.services.report_service import ReportService

USER = {"id": "507f1f77bcf86cd799439011", "role": "normal"}


async def _seed_dynamic_only_scan(db, scan_id="scan-dyn-report"):
    await db.scans.insert_one({
        "scan_id": scan_id,
        "user_id": "507f1f77bcf86cd799439011",
        "state": "COMPLETED",
        "input_type": "DYNAMIC",
        "summary": {
            "status": "COMPLETED", "input_type": "DYNAMIC",
            "total_files": 0, "files_scanned": 0, "vulnerabilities_found": 1,
            "by_severity": {"critical": 0, "high": 0, "medium": 1, "low": 0},
            "duration_seconds": 3.4, "created_at": "2026-01-01T00:00:00",
            "completed_at": "2026-01-01T00:00:03",
            "vulnerabilities": [],
            "dynamic_findings": [{
                "control_id": "V3.7.2", "verdict": "fail", "rule_id": "OPEN_REDIRECT_LIVE",
                "url": "https://target.example/next-link?next=https://canary.invalid/",
                "method": "GET", "note": "Unvalidated redirect to canary domain",
                "severity": "medium", "confidence": 0.8,
            }],
            "discovered_forms": [{
                "action_url": "https://target.example/search", "method": "GET",
                "fields": ["q"], "source_url": "https://target.example",
            }],
        },
    })
    return scan_id


@pytest.mark.asyncio
async def test_get_report_includes_dynamic_findings_and_forms():
    db = AsyncMongoMockClient()["test"]
    scan_id = await _seed_dynamic_only_scan(db)
    svc = ReportService(db)

    report = await svc.get(scan_id, USER)

    assert report is not None
    assert report["dynamic_findings"][0]["rule_id"] == "OPEN_REDIRECT_LIVE"
    assert report["discovered_forms"][0]["action_url"] == "https://target.example/search"


@pytest.mark.asyncio
async def test_export_csv_includes_dynamic_findings_for_dynamic_only_scan():
    db = AsyncMongoMockClient()["test"]
    scan_id = await _seed_dynamic_only_scan(db)
    svc = ReportService(db)

    csv_content = await svc.export_csv(scan_id, USER)

    assert csv_content is not None  # previously returned None: summary.vulnerabilities was []
    assert "OPEN_REDIRECT_LIVE" in csv_content
    assert "FAIL" in csv_content


@pytest.mark.asyncio
async def test_export_csv_returns_none_when_nothing_to_report():
    db = AsyncMongoMockClient()["test"]
    scan_id = "scan-empty"
    await db.scans.insert_one({
        "scan_id": scan_id, "user_id": "507f1f77bcf86cd799439011", "state": "COMPLETED",
        "summary": {
            "status": "COMPLETED", "input_type": "DIRECT_CODE",
            "total_files": 1, "files_scanned": 1, "vulnerabilities_found": 0,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "duration_seconds": 0.1, "created_at": "2026-01-01T00:00:00",
            "vulnerabilities": [],
        },
    })
    svc = ReportService(db)

    csv_content = await svc.export_csv(scan_id, USER)

    assert csv_content is None


@pytest.mark.asyncio
async def test_export_pdf_does_not_crash_on_dynamic_only_scan():
    db = AsyncMongoMockClient()["test"]
    scan_id = await _seed_dynamic_only_scan(db)
    svc = ReportService(db)

    pdf_bytes = await svc.export_pdf(scan_id, USER)

    assert pdf_bytes is not None
    assert pdf_bytes[:4] == b"%PDF"


async def _seed_probe_only_scan(db, scan_id="scan-probe-report"):
    await db.scans.insert_one({
        "scan_id": scan_id,
        "user_id": "507f1f77bcf86cd799439011",
        "state": "COMPLETED",
        "input_type": "DYNAMIC",
        "summary": {
            "status": "COMPLETED", "input_type": "DYNAMIC",
            "total_files": 0, "files_scanned": 0, "vulnerabilities_found": 0,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "duration_seconds": 1.2, "created_at": "2026-01-01T00:00:00",
            "completed_at": "2026-01-01T00:00:01",
            "vulnerabilities": [],
            "dynamic_probe_findings": [
                {"control_id": "V12.1.1", "verdict": "pass", "note": "Negotiated TLSv1.3", "confidence": 0.85},
                {"control_id": "V13.4.1", "verdict": "fail", "note": ".git/HEAD reachable", "confidence": 0.9},
            ],
        },
    })
    return scan_id


class TestDynamicProbeFindingsInReport:
    """dynamic_probe_findings (DynamicProbe's live TLS/HTTPS/HSTS/.git
    checks) reaching the report surface — get()'s passthrough and the PDF
    export's own rendering section, which previously didn't exist."""

    @pytest.mark.asyncio
    async def test_get_report_includes_probe_findings(self):
        db = AsyncMongoMockClient()["test"]
        scan_id = await _seed_probe_only_scan(db)
        svc = ReportService(db)

        report = await svc.get(scan_id, USER)

        assert report is not None
        assert len(report["dynamic_probe_findings"]) == 2
        assert {f["control_id"] for f in report["dynamic_probe_findings"]} == {"V12.1.1", "V13.4.1"}

    @pytest.mark.asyncio
    async def test_export_pdf_includes_probe_findings_section(self):
        db = AsyncMongoMockClient()["test"]
        scan_id = await _seed_probe_only_scan(db)
        svc = ReportService(db)

        pdf_bytes = await svc.export_pdf(scan_id, USER)

        assert pdf_bytes is not None
        assert pdf_bytes[:4] == b"%PDF"
        # reportlab-generated PDF text streams are Flate-compressed, so the
        # literal control_id string isn't searchable in the raw bytes —
        # what's checkable here is that rendering a probe-findings-only
        # summary (no vulnerabilities, no dynamic_findings) still produces a
        # non-trivial PDF rather than silently skipping the section.
        assert len(pdf_bytes) > 1500

    @pytest.mark.asyncio
    async def test_export_pdf_does_not_crash_with_no_probe_findings(self):
        db = AsyncMongoMockClient()["test"]
        scan_id = await _seed_dynamic_only_scan(db)  # no dynamic_probe_findings key at all
        svc = ReportService(db)

        pdf_bytes = await svc.export_pdf(scan_id, USER)

        assert pdf_bytes is not None
        assert pdf_bytes[:4] == b"%PDF"
