from fastapi import APIRouter, Depends, HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.db.mongo import get_mongo_db
from app.models.repository import Repository
from app.services.asvs_service import ASVSService

router = APIRouter(prefix="/asvs", tags=["asvs"])


@router.get("/controls")
async def list_controls(
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """List the full ASVS 5.0.0 L1 control catalog (70 controls)."""
    service = ASVSService(db)
    return await service.list_controls()


@router.get("/chapters")
async def list_chapters(
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """List the 15 ASVS chapters represented in the catalog, with control counts."""
    service = ASVSService(db)
    return await service.list_chapters()


@router.get("/portfolio")
async def get_portfolio_dashboard(
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
    session: AsyncSession = Depends(get_db),
):
    """
    Cross-repo compliance dashboard: latest compliance snapshot + trend per
    repo, portfolio-wide attestation coverage, and the controls failing
    across the most repos. Repos with zero completed scans are included
    with null stats so the dashboard can show a "never scanned" state.
    """
    service = ASVSService(db)
    portfolio = await service.get_portfolio_dashboard()

    result = await session.execute(select(Repository))
    all_repos = result.scalars().all()
    repo_names = {r.id: r.name for r in all_repos}

    scanned_repo_ids = set()
    for r in portfolio["repos"]:
        r["repo_name"] = repo_names.get(r["repo_id"], f"Repository {r['repo_id']}")
        scanned_repo_ids.add(r["repo_id"])

    for repo in all_repos:
        if repo.id not in scanned_repo_ids:
            portfolio["repos"].append({
                "repo_id": repo.id,
                "repo_name": repo.name,
                "latest_scan_id": None,
                "latest_scan_at": None,
                "scan_count": 0,
                "l1_pct": None,
                "passed": None,
                "total": None,
                "fail_count": None,
                "not_tested_count": None,
                "trend": [],
            })

    portfolio["repos"].sort(key=lambda r: (r["l1_pct"] is None, r["l1_pct"] if r["l1_pct"] is not None else 0))
    return portfolio


@router.get("/controls/{control_id}")
async def get_control(
    control_id: str,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """Get one control's catalog definition, plus its latest scan result if one exists."""
    service = ASVSService(db)
    control = await service.get_control(control_id)
    if not control:
        raise HTTPException(status_code=404, detail=f"Unknown control_id: {control_id}")

    result = None
    latest_scan = await db.scans.find_one({"state": "COMPLETED"}, sort=[("finished_at", -1)])
    if latest_scan:
        results = await service.build_results_for_scan(latest_scan["scan_id"])
        result = results.get(control_id)

    return {"control": control, "result": result}
