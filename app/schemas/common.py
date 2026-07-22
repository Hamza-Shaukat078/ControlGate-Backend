from datetime import datetime
from pydantic import BaseModel, ConfigDict


class APIModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class PageParams(APIModel):
    page: int = 1
    size: int = 10


class Message(APIModel):
    detail: str


class Timestamped(APIModel):
    created_at: datetime | None = None
