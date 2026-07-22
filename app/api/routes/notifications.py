from fastapi import APIRouter, Depends
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.api.deps import get_current_user
from app.db.mongo import get_mongo_db
from app.services.notification_service import NotificationService


router = APIRouter(prefix="/notifications", tags=["notifications"])
service = NotificationService()


@router.get("")
async def list_notifications(
    page: int = 1,
    size: int = 10,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    return await service.list(db, user, page, size)
