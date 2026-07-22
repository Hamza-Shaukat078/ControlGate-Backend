from datetime import datetime
from pydantic import BaseModel, Field
from app.schemas.common import APIModel


class RepositoryCreate(APIModel):
    name: str
    provider: str
    url: str | None = None
    token: str | None = None
    status: str | None = None


class RepositoryRead(APIModel):
    id: int
    name: str
    provider: str
    url: str | None = None
    status: str
    default_branch: str
    created_at: datetime | None = None
