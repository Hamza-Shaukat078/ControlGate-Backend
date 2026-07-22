from fastapi import APIRouter, Depends
from motor.motor_asyncio import AsyncIOMotorDatabase
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.deps import get_current_user, get_db
from app.db.mongo import get_mongo_db, to_object_id
from app.enums.role import UserRole
from app.models.repository import Repository
from app.services.notification_service import NotificationService


router = APIRouter(prefix="/dashboard", tags=["dashboard"])
notif_service = NotificationService()


@router.get("/summary")
async def summary(
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
    session: AsyncSession = Depends(get_db),
):
    query = {}
    if user.get("role") != UserRole.ADMIN.value:
        object_id = to_object_id(user.get("id", ""))
        if object_id:
            query["user_id"] = object_id
        else:
            query["user_id"] = None

    scans = await db.scans.find(query).to_list(length=500)
    total_scans = len(scans)
    total_vulns = 0
    severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for scan in scans:
        summary = scan.get("summary") or {}
        total_vulns += summary.get("vulnerabilities_found", 0)
        by_sev = summary.get("by_severity", {})
        severity["CRITICAL"] += by_sev.get("critical", 0)
        severity["HIGH"] += by_sev.get("high", 0)
        severity["MEDIUM"] += by_sev.get("medium", 0)
        severity["LOW"] += by_sev.get("low", 0)

    repos = await session.execute(select(Repository))
    repo_count = len(list(repos.scalars().all()))

    # Risk score 0–100: weighted sum of vulns by severity, capped at 100
    # Critical=10pts, High=5pts, Medium=2pts, Low=0.5pts — saturates at 100
    raw_risk = (
        severity["CRITICAL"] * 10 +
        severity["HIGH"]     * 5  +
        severity["MEDIUM"]   * 2  +
        severity["LOW"]      * 0.5
    )
    risk_score = min(100, round(raw_risk))
    risk_label = (
        "Critical" if risk_score >= 75 else
        "High"     if risk_score >= 50 else
        "Medium"   if risk_score >= 25 else
        "Low"      if risk_score >  0  else
        "Clean"
    )

    return {
        "totals": {
            "repos": repo_count,
            "scans": total_scans,
            "vulnerabilities": total_vulns,
        },
        "severity": severity,
        "risk": {"score": risk_score, "label": risk_label},
        "trend": [],
    }


@router.get("/recent-scans")
async def recent_scans(
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
    session: AsyncSession = Depends(get_db),
):
    is_admin = user.get("role") == UserRole.ADMIN.value
    query = {}
    if not is_admin:
        object_id = to_object_id(user.get("id", ""))
        query["user_id"] = object_id if object_id else None

    cursor = db.scans.find(query).sort("created_at", -1).limit(200)
    scans = await cursor.to_list(length=200)

    repo_ids = [scan.get("repo_id") for scan in scans if scan.get("repo_id")]
    repo_map = {}
    if repo_ids:
        result = await session.execute(select(Repository).where(Repository.id.in_(repo_ids)))
        repo_map = {repo.id: repo.name for repo in result.scalars().all()}

    user_map = {}
    if is_admin:
        user_oids = list({scan.get("user_id") for scan in scans if scan.get("user_id")})
        if user_oids:
            u_cursor = db.users.find({"_id": {"$in": user_oids}}, {"full_name": 1, "email": 1})
            async for u in u_cursor:
                uid = str(u["_id"])
                user_map[uid] = u.get("full_name") or u.get("email") or uid

    items = []
    for scan in scans:
        summary = scan.get("summary") or {}
        repo_id = scan.get("repo_id")
        uid = str(scan.get("user_id")) if scan.get("user_id") else None
        items.append(
            {
                "scan_id": scan.get("scan_id"),
                "repo_id": repo_id,
                "repository_name": repo_map.get(repo_id) if repo_id else "Direct Code",
                "status": scan.get("state"),
                "created_at": summary.get("created_at") or scan.get("created_at"),
                "vulnerabilities_found": summary.get("vulnerabilities_found", 0),
                "scanned_by": user_map.get(uid) if is_admin and uid else None,
            }
        )
    return items


@router.get("/notifications")
async def notifications(
    page: int = 1,
    size: int = 10,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    return await notif_service.list(db, user, page, size)
