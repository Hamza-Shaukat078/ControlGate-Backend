"""CVE/CVSS reporting — Known-Vulnerable Dependencies section in the PDF/
JSON report, driven by dependency_findings' cve_ids/cve_details (populated
by dependency_scanner.py's OSV query + NVD enrichment).
"""
import pytest
from mongomock_motor import AsyncMongoMockClient

from app.services.report_service import ReportService

USER = {"id": "507f1f77bcf86cd799439011", "role": "normal"}


async def _seed_scan_with_cve(db, scan_id="scan-cve-report"):
    await db.scans.insert_one({
        "scan_id": scan_id, "user_id": "507f1f77bcf86cd799439011", "state": "COMPLETED",
        "input_type": "REPOSITORY",
        "summary": {
            "status": "COMPLETED", "input_type": "REPOSITORY",
            "total_files": 5, "files_scanned": 5, "vulnerabilities_found": 0,
            "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0},
            "duration_seconds": 4.1, "created_at": "2026-01-01T00:00:00",
            "completed_at": "2026-01-01T00:00:04",
            "vulnerabilities": [],
            "dependency_findings": [{
                "package": "flask", "version": "0.12", "ecosystem": "PyPI",
                "vuln_id": "GHSA-562c-5r94-xh97", "severity": "HIGH",
                "summary": "OSV summary text", "published": "2018-01-01T00:00:00Z",
                "days_since_published": 2900, "sla_days": 30, "breached_sla": True,
                "cve_ids": ["CVE-2018-1000656"],
                "cve_details": [{
                    "cve_id": "CVE-2018-1000656", "cvss_score": 7.5, "cvss_severity": "HIGH",
                    "cvss_version": "3.1", "description": "Improper input validation in flask.",
                    "references": ["https://example.com/advisory"], "published": "2018-01-01T00:00:00.000",
                }],
            }],
        },
    })
    return scan_id


@pytest.mark.asyncio
async def test_get_report_includes_cve_details():
    db = AsyncMongoMockClient()["test"]
    scan_id = await _seed_scan_with_cve(db)
    svc = ReportService(db)

    report = await svc.get(scan_id, USER)

    dep = report["dependency_findings"][0]
    assert dep["cve_ids"] == ["CVE-2018-1000656"]
    assert dep["cve_details"][0]["cvss_score"] == 7.5


@pytest.mark.asyncio
async def test_export_pdf_renders_cve_section_without_crashing():
    db = AsyncMongoMockClient()["test"]
    scan_id = await _seed_scan_with_cve(db)
    svc = ReportService(db)

    pdf_bytes = await svc.export_pdf(scan_id, USER)

    assert pdf_bytes is not None
    assert pdf_bytes[:4] == b"%PDF"


@pytest.mark.asyncio
async def test_export_pdf_handles_unenriched_cve_gracefully():
    db = AsyncMongoMockClient()["test"]
    scan_id = "scan-cve-unenriched"
    await db.scans.insert_one({
        "scan_id": scan_id, "user_id": "507f1f77bcf86cd799439011", "state": "COMPLETED",
        "summary": {
            "status": "COMPLETED", "input_type": "REPOSITORY",
            "total_files": 1, "files_scanned": 1, "vulnerabilities_found": 0,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "duration_seconds": 1.0, "created_at": "2026-01-01T00:00:00",
            "vulnerabilities": [],
            "dependency_findings": [{
                "package": "lodash", "version": "4.17.15", "ecosystem": "npm",
                "vuln_id": "GHSA-xxxx", "severity": "MODERATE", "summary": "some vuln",
                "cve_ids": ["CVE-2020-99999"], "cve_details": [],  # NVD didn't reach it this scan
            }],
        },
    })
    svc = ReportService(db)

    pdf_bytes = await svc.export_pdf(scan_id, USER)

    assert pdf_bytes is not None
    assert pdf_bytes[:4] == b"%PDF"
