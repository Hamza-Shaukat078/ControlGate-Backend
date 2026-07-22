from datetime import datetime
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.db.mongo import to_object_id
from app.enums.role import UserRole


class NotificationService:
    async def list(self, db: AsyncIOMotorDatabase, user: dict, page: int = 1, size: int = 10):
        query = {}
        if user.get("role") != UserRole.ADMIN.value:
            object_id = to_object_id(user.get("id", ""))
            query["user_id"] = object_id if object_id else None

        skip = max(page - 1, 0) * size
        cursor = db.scans.find(query).sort("created_at", -1).skip(skip).limit(size)
        scans = await cursor.to_list(length=size)

        items = []
        for scan in scans:
            status = scan.get("state", "UNKNOWN")
            created_at = scan.get("created_at") or datetime.utcnow()
            items.append(
                {
                    "id": scan.get("scan_id"),
                    "message": f"Scan {scan.get('scan_id')} {status.lower()}",
                    "level": "INFO",
                    "created_at": created_at.isoformat(),
                }
            )

        total = await db.scans.count_documents(query)
        return {"items": items, "page": page, "size": size, "total": total}
