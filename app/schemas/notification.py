from datetime import datetime
from app.schemas.common import APIModel


class NotificationRead(APIModel):
    id: int
    message: str
    level: str
    created_at: datetime | None = None
