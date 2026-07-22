from fastapi import APIRouter, Depends, HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.api.deps import get_current_user
from app.db.mongo import get_mongo_db
from app.enums.role import UserRole
from app.services.graph_service import GraphService


router = APIRouter(prefix="/graphs", tags=["graphs"])


@router.get("/{scan_id}/file/{file_id}")
async def file_graph(
    scan_id: str,
    file_id: str,
    type: str = "AST",
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    scan = await db.scans.find_one({"scan_id": scan_id})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if user.get("role") != UserRole.ADMIN.value and str(scan.get("user_id")) != user.get("id"):
        raise HTTPException(status_code=403, detail="Not authorized to access this scan")
    service = GraphService(db)
    return await service.graph(scan_id, file_id, type)


@router.get("/{scan_id}/nodes/{node_id}")
async def node_details(
    scan_id: str,
    node_id: str,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    scan = await db.scans.find_one({"scan_id": scan_id})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if user.get("role") != UserRole.ADMIN.value and str(scan.get("user_id")) != user.get("id"):
        raise HTTPException(status_code=403, detail="Not authorized to access this scan")
    return {"node_id": node_id, "details": {"severity": "LOW"}, "insight": "Likely benign"}


@router.get("/{scan_id}/paths/{path_id}")
async def path_details(
    scan_id: str,
    path_id: str,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    scan = await db.scans.find_one({"scan_id": scan_id})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if user.get("role") != UserRole.ADMIN.value and str(scan.get("user_id")) != user.get("id"):
        raise HTTPException(status_code=403, detail="Not authorized to access this scan")
    return {"path_id": path_id, "steps": ["source", "sanitize", "sink"], "risk": "LOW"}
