from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from io import BytesIO
from motor.motor_asyncio import AsyncIOMotorDatabase
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.db.mongo import get_mongo_db
from app.models.repository import Repository
from app.services.asvs_service import ASVSService
from app.core.permissions import can_access_resource

router = APIRouter(prefix="/export", tags=["export"])


@router.get("/asvs-report")
async def export_asvs_report(
    scan_id: str,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
    session: AsyncSession = Depends(get_db),
):
    """Export the ASVS 5.0.0 L1 compliance report for a scan as a PDF."""
    service = ASVSService(db)

    repo_name, branch = None, None
    scan = await db.scans.find_one({"scan_id": scan_id})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not can_access_resource(user, str(scan.get("user_id"))):
        raise HTTPException(status_code=403, detail="Not authorized to export this scan")
    branch = scan.get("branch")
    repo_id = scan.get("repo_id")
    if repo_id:
        result = await session.execute(select(Repository).where(Repository.id == repo_id))
        repo = result.scalar_one_or_none()
        repo_name = repo.name if repo else None

    pdf_bytes = await service.export_pdf(scan_id, repo_name=repo_name, branch=branch, user=user)
    if not pdf_bytes:
        raise HTTPException(status_code=404, detail="Scan not found or PDF generation failed")

    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=asvs-compliance-{scan_id}.pdf"},
    )
