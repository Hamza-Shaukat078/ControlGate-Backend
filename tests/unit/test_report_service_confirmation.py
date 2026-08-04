"""Phase 6 — report_service.py surfaces the two dynamic-confirmation tiers
scan_service.py sets on hybrid-scan results (see _run_repository_scan's
hybrid block): bridge_confirmed (an exact route was re-tested live) vs.
plain dynamic_confirmed (only correlated by shared ASVS control). The JSON
export already passed these through unmodified (ScanSummary.vulnerabilities/
dynamic_findings are untyped lists of dicts) — this locks in that the CSV/PDF
renderers, which build their own rows/paragraphs field-by-field, don't
silently drop them.
"""
import csv
import io

import pytest
from mongomock_motor import AsyncMongoMockClient

from app.services.report_service import ReportService

USER = {"id": "507f1f77bcf86cd799439011", "role": "normal"}


async def _seed_hybrid_scan(db, scan_id="scan-hybrid-report"):
    await db.scans.insert_one({
        "scan_id": scan_id,
        "user_id": "507f1f77bcf86cd799439011",
        "state": "COMPLETED",
        "input_type": "REPOSITORY",
        "summary": {
            "status": "COMPLETED", "input_type": "REPOSITORY",
            "total_files": 1, "files_scanned": 1, "vulnerabilities_found": 2,
            "by_severity": {"critical": 0, "high": 2, "medium": 0, "low": 0},
            "duration_seconds": 5.0, "created_at": "2026-01-01T00:00:00",
            "completed_at": "2026-01-01T00:00:05",
            "vulnerabilities": [
                {
                    "id": "vuln-bridge", "type": "UNVALIDATED_REDIRECT", "severity": "high",
                    "asvs_controls": ["V3.7.2"], "location": {"file": "app.py", "start_line": 10, "end_line": 10},
                    "dynamic_confirmed": True, "bridge_confirmed": True,
                },
                {
                    "id": "vuln-coarse", "type": "SQL_INJECTION", "severity": "high",
                    "asvs_controls": ["V5.3.4"], "location": {"file": "db.py", "start_line": 20, "end_line": 20},
                    "dynamic_confirmed": True,
                },
            ],
            "dynamic_findings": [
                {
                    "control_id": "V3.7.2", "verdict": "fail", "rule_id": "OPEN_REDIRECT_LIVE",
                    "url": "https://target.example/go", "method": "GET", "note": "confirmed live",
                    "severity": "high", "confidence": 0.8,
                    "evidence": "bridge:vuln-bridge:app.py:10",
                },
                {
                    "control_id": "V5.3.4", "verdict": "fail", "rule_id": "SOME_OTHER_CHECK",
                    "url": "https://target.example/query", "method": "GET", "note": "matched control",
                    "severity": "high", "confidence": 0.5,
                    "corroborates_static_finding": True,
                },
            ],
        },
    })
    return scan_id


@pytest.mark.asyncio
async def test_csv_marks_bridge_confirmed_vulnerability():
    db = AsyncMongoMockClient()["test"]
    scan_id = await _seed_hybrid_scan(db)
    svc = ReportService(db)

    csv_content = await svc.export_csv(scan_id, USER)

    assert "Confirmed live" in csv_content


@pytest.mark.asyncio
async def test_csv_marks_coarsely_confirmed_vulnerability():
    db = AsyncMongoMockClient()["test"]
    scan_id = await _seed_hybrid_scan(db)
    svc = ReportService(db)

    csv_content = await svc.export_csv(scan_id, USER)

    assert "Corroborated" in csv_content


@pytest.mark.asyncio
async def test_csv_marks_bridge_origin_dynamic_finding():
    db = AsyncMongoMockClient()["test"]
    scan_id = await _seed_hybrid_scan(db)
    svc = ReportService(db)

    csv_content = await svc.export_csv(scan_id, USER)

    assert "Re-test of the static finding at app.py:10" in csv_content


@pytest.mark.asyncio
async def test_csv_marks_corroborating_dynamic_finding():
    db = AsyncMongoMockClient()["test"]
    scan_id = await _seed_hybrid_scan(db)
    svc = ReportService(db)

    csv_content = await svc.export_csv(scan_id, USER)

    assert "Corroborates static finding" in csv_content


@pytest.mark.asyncio
async def test_csv_has_no_confirmation_for_unconfirmed_finding():
    db = AsyncMongoMockClient()["test"]
    scan_id = "scan-unconfirmed"
    await db.scans.insert_one({
        "scan_id": scan_id, "user_id": "507f1f77bcf86cd799439011", "state": "COMPLETED",
        "summary": {
            "status": "COMPLETED", "input_type": "REPOSITORY",
            "total_files": 1, "files_scanned": 1, "vulnerabilities_found": 1,
            "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0},
            "duration_seconds": 1.0, "created_at": "2026-01-01T00:00:00",
            "vulnerabilities": [{
                "id": "vuln-static-only", "type": "XSS", "severity": "high",
                "asvs_controls": ["V1.2.1"], "location": {"file": "views.py", "start_line": 5, "end_line": 5},
            }],
        },
    })
    svc = ReportService(db)

    csv_content = await svc.export_csv(scan_id, USER)

    reader = csv.DictReader(io.StringIO(csv_content))
    row = next(r for r in reader if r["Type"] == "XSS")
    assert row["Confirmation"] == ""


@pytest.mark.asyncio
async def test_export_pdf_does_not_crash_with_confirmation_fields():
    db = AsyncMongoMockClient()["test"]
    scan_id = await _seed_hybrid_scan(db)
    svc = ReportService(db)

    pdf_bytes = await svc.export_pdf(scan_id, USER)

    assert pdf_bytes is not None
    assert pdf_bytes[:4] == b"%PDF"
