from app.schemas.common import APIModel
from pydantic import EmailStr
from app.enums.role import UserRole


class UserPublic(APIModel):
    id: str
    email: EmailStr
    full_name: str | None = None
    avatar_url: str | None = None
    role: UserRole
    is_active: bool
    is_superuser: bool = False


class UserAdminRead(APIModel):
    id: str
    email: EmailStr
    full_name: str | None = None
    avatar_url: str | None = None
    role: UserRole
    is_active: bool
    status: str
    created_at: str | None = None
    updated_at: str | None = None


class UserRoleUpdate(APIModel):
    role: UserRole


class UserProfileUpdate(APIModel):
    full_name: str | None = None
    avatar_url: str | None = None
