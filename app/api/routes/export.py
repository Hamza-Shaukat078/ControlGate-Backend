from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from io import BytesIO
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.deps import get_current_user
from app.db.mongo import get_mongo_db
from app.services.asvs_service import ASVSService

router = APIRouter(prefix="/export", tags=["export"])


@router.get("/asvs-report")
async def export_asvs_report(
    scan_id: str,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """Export the ASVS 5.0.0 L1 compliance report for a scan as a PDF."""
    service = ASVSService(db)
    pdf_bytes = await service.export_pdf(scan_id)
    if not pdf_bytes:
        raise HTTPException(status_code=404, detail="Scan not found or PDF generation failed")

    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=asvs-compliance-{scan_id}.pdf"},
    )
