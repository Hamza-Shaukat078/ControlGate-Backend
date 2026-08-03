from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse, Response
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.api.deps import get_current_user
from app.db.mongo import get_mongo_db
from app.services.report_service import ReportService
from app.services.asvs_service import ASVSService
from app.core.permissions import can_access_resource
from io import BytesIO
import json


def _build_sarif(report: dict, scan_id: str) -> dict:
    """Convert a Vulcan scan report to SARIF 2.1.0 format."""
    vulns = []
    if isinstance(report, dict):
        vulns = report.get("vulnerabilities", []) or []
    elif hasattr(report, "vulnerabilities"):
        vulns = report.vulnerabilities or []

    rules_seen: dict = {}
    for v in vulns:
        rid = (v.get("cwe") or v.get("type") or "UNKNOWN").replace(" ", "_")
        if rid not in rules_seen:
            rules_seen[rid] = {
                "id": rid,
                "name": v.get("type", rid),
                "shortDescription": {"text": v.get("type", rid)},
                "helpUri": (
                    f"https://cwe.mitre.org/data/definitions/{rid.replace('CWE-','')}.html"
                    if rid.startswith("CWE-") else "https://owasp.org"
                ),
                "properties": {
                    "tags": [v.get("owasp", ""), rid],
                    "security-severity": str(v.get("cvss_score", 5.0)),
                },
            }

    results = []
    for v in vulns:
        rid = (v.get("cwe") or v.get("type") or "UNKNOWN").replace(" ", "_")
        loc = v.get("location", {})
        file_path  = loc.get("file", "unknown").replace("\\", "/")
        start_line = max(1, loc.get("start_line", 1))
        end_line   = max(start_line, loc.get("end_line", start_line))
        level = {"critical": "error", "high": "error",
                 "medium": "warning", "low": "note"}.get(
            (v.get("severity") or "").lower(), "warning"
        )
        snippet = (v.get("evidence") or {}).get("code_snippet", "")
        llm     = (v.get("analysis") or {}).get("llm_classification", {})
        message = (
            f"{v.get('type','Vulnerability')} — "
            f"Source: {(v.get('evidence') or {}).get('source','')} → "
            f"Sink: {(v.get('evidence') or {}).get('sink','')}. "
            f"CVSS {v.get('cvss_score','N/A')}. "
            f"{llm.get('explanation','')}"
        ).strip()

        results.append({
            "ruleId": rid,
            "level": level,
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": file_path, "uriBaseId": "%SRCROOT%"},
                    "region": {
                        "startLine": start_line,
                        "endLine": end_line,
                        **({"snippet": {"text": snippet[:500]}} if snippet else {}),
                    },
                }
            }],
            "properties": {
                "severity":   v.get("severity"),
                "confidence": v.get("confidence"),
                "cvss_score": v.get("cvss_score"),
                "cwe":        v.get("cwe"),
                "owasp":      v.get("owasp"),
            },
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Vulcan",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/HisSUS77/vulcan-backend",
                    "rules": list(rules_seen.values()),
                }
            },
            "results": results,
            "properties": {"scan_id": scan_id},
        }],
    }


router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("")
async def list_reports(
    repo_id: int | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    tag: str | None = None,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """List all completed scan reports"""
    service = ReportService(db)
    return await service.list(user, repo_id, date_from, date_to, tag)


@router.get("/{scan_id}")
async def get_report(
    scan_id: str,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """Get detailed report for a specific scan"""
    service = ReportService(db)
    report = await service.get(scan_id, user)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@router.get("/{scan_id}/export")
async def export_report(
    scan_id: str,
    format: str = "json",
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """
    Export report in specified format.
    
    Formats:
    - json: Return JSON data (default)
    - csv: Return CSV file
    - pdf: Return PDF file
    """
    if format.lower() == "pdf":
        service = ReportService(db)
        pdf_content = await service.export_pdf(scan_id, user)
        if not pdf_content:
            raise HTTPException(
                status_code=404, 
                detail="Report not found or PDF generation failed"
            )
        
        return StreamingResponse(
            BytesIO(pdf_content),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=report-{scan_id}.pdf"
            }
        )
    
    elif format.lower() == "csv":
        service = ReportService(db)
        csv_content = await service.export_csv(scan_id, user)
        if not csv_content:
            raise HTTPException(
                status_code=404,
                detail="Report not found or no data available"
            )
        
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename=report-{scan_id}.csv"
            }
        )
    
    elif format.lower() == "json":
        service = ReportService(db)
        report = await service.get(scan_id, user)
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        return report
    
    elif format.lower() == "sarif":
        service = ReportService(db)
        report = await service.get(scan_id, user)
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        sarif = _build_sarif(report, scan_id)
        return Response(
            content=json.dumps(sarif, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=vulcan-{scan_id}.sarif"},
        )

    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported format: {format}. Use 'json', 'csv', 'pdf', or 'sarif'."
        )


@router.get("/{scan_id}/compliance")
async def get_asvs_compliance(
    scan_id: str,
    framework: str = "asvs",
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """
    ASVS 5.0.0 L1 compliance summary for a scan: per-chapter verdict counts,
    per-level completion %, and the full per-control result set.
    """
    if framework != "asvs":
        raise HTTPException(status_code=400, detail="Only framework=asvs is currently supported")
    scan = await db.scans.find_one({"scan_id": scan_id})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not can_access_resource(user, str(scan.get("user_id"))):
        raise HTTPException(status_code=403, detail="Not authorized to access this scan")
    service = ASVSService(db)
    return await service.get_compliance_summary(scan_id, user=user)


@router.post("/compare")
async def compare_reports(
    payload: dict,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """Compare two scan reports"""
    scan_id_1 = payload.get("report_id_1") or payload.get("scan_id_1")
    scan_id_2 = payload.get("report_id_2") or payload.get("scan_id_2")
    
    if not scan_id_1 or not scan_id_2:
        raise HTTPException(
            status_code=400,
            detail="Both scan_id_1 and scan_id_2 are required"
        )
    
    service = ReportService(db)
    return await service.compare(scan_id_1, scan_id_2, user)
