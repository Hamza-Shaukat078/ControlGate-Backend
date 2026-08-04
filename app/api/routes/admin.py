from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.deps import get_current_user
from app.core.permissions import require_role
from app.db.mongo import get_mongo_db, to_object_id
from app.enums.role import UserRole
from app.schemas.user import UserAdminRead, UserRoleUpdate


router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/users", response_model=list[UserAdminRead])
@require_role(UserRole.ADMIN)
async def list_users(user=Depends(get_current_user), db: AsyncIOMotorDatabase = Depends(get_mongo_db)):
    users = []
    cursor = db.users.find({})
    async for doc in cursor:
        status = "active" if doc.get("is_active", True) else "inactive"
        users.append(
            UserAdminRead(
                id=str(doc.get("_id")),
                email=doc.get("email"),
                full_name=doc.get("full_name"),
                role=doc.get("role", UserRole.NORMAL.value),
                is_active=doc.get("is_active", True),
                status=status,
                created_at=doc.get("created_at").isoformat() if doc.get("created_at") else None,
                updated_at=doc.get("updated_at").isoformat() if doc.get("updated_at") else None,
            )
        )
    return users


@router.patch("/users/{user_id}", response_model=UserAdminRead)
@require_role(UserRole.ADMIN)
async def update_user_role(
    user_id: str,
    payload: UserRoleUpdate,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    object_id = to_object_id(user_id)
    if not object_id:
        raise HTTPException(status_code=400, detail="Invalid user id")
    target = await db.users.find_one({"_id": object_id})
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    await db.users.update_one(
        {"_id": target["_id"]},
        {"$set": {"role": payload.role.value, "updated_at": now}},
    )
    target["role"] = payload.role.value
    target["updated_at"] = now
    status = "active" if target.get("is_active", True) else "inactive"
    return UserAdminRead(
        id=str(target.get("_id")),
        email=target.get("email"),
        full_name=target.get("full_name"),
        role=target.get("role", UserRole.NORMAL.value),
        is_active=target.get("is_active", True),
        status=status,
        created_at=target.get("created_at").isoformat() if target.get("created_at") else None,
        updated_at=target.get("updated_at").isoformat() if target.get("updated_at") else None,
    )
