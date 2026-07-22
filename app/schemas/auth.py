from datetime import datetime
from pydantic import BaseModel, EmailStr, Field
from app.enums.role import UserRole
from app.schemas.common import APIModel


class UserCreate(APIModel):
    email: EmailStr
    password: str = Field(min_length=6)
    full_name: str | None = None


class UserRead(APIModel):
    id: str
    email: EmailStr
    full_name: str | None = None
    role: UserRole
    is_active: bool
    is_superuser: bool = False
    created_at: datetime | None = None


class UserLogin(APIModel):
    email: EmailStr
    password: str


class Token(APIModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class PasswordResetRequest(APIModel):
    email: EmailStr


class PasswordResetConfirm(APIModel):
    token: str
    new_password: str = Field(min_length=6)


class PasswordResetValidate(APIModel):
    token: str


class PasswordResetValidation(APIModel):
    valid: bool
    message: str


class Message(APIModel):
    message: str
