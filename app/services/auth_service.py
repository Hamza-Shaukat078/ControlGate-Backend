from datetime import datetime, timedelta
import hashlib
import secrets
from typing import Optional
from fastapi import HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.security import verify_password, get_password_hash, create_access_token
from app.core.config import settings
from app.core.exceptions import ConflictException, AuthenticationException, ResourceNotFoundException
from app.enums.role import UserRole
from app.services.email_service import EmailService


class AuthService:
    """
    Authentication service for user registration, login, and token management.
    Integrates with MongoDB for user storage and bcrypt for password hashing.
    """
    def _hash_reset_token(self, token: str) -> str:
        value = f"{token}{settings.JWT_SECRET}"
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    async def register(
        self,
        db: AsyncIOMotorDatabase,
        email: str,
        password: str,
        full_name: Optional[str],
        role: str = UserRole.NORMAL.value,
    ) -> dict:
        """
        Register a new user with email and password.
        
        Args:
            db: MongoDB database instance
            email: User email (must be unique)
            password: Plain text password (will be hashed)
            full_name: Optional full name
            role: User role (admin, premium, normal). Defaults to normal.
            
        Returns:
            dict: Created user document
            
        Raises:
            ConflictException: If email already exists
        """
        existing = await db.users.find_one({"email": email})
        if existing:
            raise ConflictException(f"Email '{email}' is already registered")

        # Validate role
        valid_roles = [r.value for r in UserRole]
        if role not in valid_roles:
            raise ValueError(f"Invalid role '{role}'. Must be one of: {', '.join(valid_roles)}")

        now = datetime.utcnow()
        user_doc = {
            "email": email,
            "hashed_password": get_password_hash(password),
            "full_name": full_name or None,
            "role": role,
            "is_active": True,
            "created_at": now,
            "updated_at": now,
        }
        result = await db.users.insert_one(user_doc)
        user_doc["_id"] = result.inserted_id
        return user_doc

    async def authenticate(self, db: AsyncIOMotorDatabase, email: str, password: str) -> dict:
        """
        Authenticate user by email and password.
        
        Args:
            db: MongoDB database instance
            email: User email
            password: Plain text password
            
        Returns:
            dict: Authenticated user document
            
        Raises:
            AuthenticationException: If credentials are invalid
        """
        user = await db.users.find_one({"email": email})
        if not user or not verify_password(password, user.get("hashed_password", "")):
            raise AuthenticationException("Invalid email or password")
        
        if not user.get("is_active", True):
            raise AuthenticationException("User account is inactive")
        
        return user

    def issue_token(self, user: dict) -> dict:
        """
        Issue JWT access token for authenticated user.
        
        Args:
            user: User document from MongoDB
            
        Returns:
            dict: Token response with access_token, token_type, expires_in
        """
        role = user.get("role") or UserRole.NORMAL.value
        subject = user.get("_id") or user.get("id")
        token = create_access_token(str(subject), extra_claims={"role": role})
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }

    def to_public(self, user: dict) -> dict:
        """
        Convert internal user document to public response format.
        
        Args:
            user: User document from MongoDB
            
        Returns:
            dict: Public user data (no sensitive info)
        """
        role = user.get("role") or UserRole.NORMAL.value
        return {
            "id": str(user["_id"]),
            "email": user.get("email"),
            "full_name": user.get("full_name"),
            "avatar_url": user.get("avatar_url"),
            "role": role,
            "is_active": user.get("is_active", True),
            "is_superuser": role == UserRole.ADMIN.value,
            "created_at": user.get("created_at"),
        }

    async def get_or_create_google_user(
        self,
        db: AsyncIOMotorDatabase,
        email: str,
        full_name: Optional[str],
        google_sub: str,
    ) -> dict:
        user = await db.users.find_one({"email": email})
        now = datetime.utcnow()
        if user:
            await db.users.update_one(
                {"_id": user["_id"]},
                {
                    "$set": {
                        "oauth_provider": "google",
                        "oauth_sub": google_sub,
                        "updated_at": now,
                    }
                },
            )
            user.update({"oauth_provider": "google", "oauth_sub": google_sub, "updated_at": now})
            return user

        user_doc = {
            "email": email,
            "hashed_password": None,
            "full_name": full_name or None,
            "role": UserRole.NORMAL.value,
            "is_active": True,
            "oauth_provider": "google",
            "oauth_sub": google_sub,
            "created_at": now,
            "updated_at": now,
        }
        result = await db.users.insert_one(user_doc)
        user_doc["_id"] = result.inserted_id
        return user_doc

    async def get_or_create_github_user(
        self,
        db: AsyncIOMotorDatabase,
        email: str,
        full_name: Optional[str],
        github_id: str,
    ) -> dict:
        user = await db.users.find_one({"email": email})
        now = datetime.utcnow()
        if user:
            await db.users.update_one(
                {"_id": user["_id"]},
                {
                    "$set": {
                        "oauth_provider": "github",
                        "oauth_sub": github_id,
                        "updated_at": now,
                    }
                },
            )
            user.update({"oauth_provider": "github", "oauth_sub": github_id, "updated_at": now})
            return user

        user_doc = {
            "email": email,
            "hashed_password": None,
            "full_name": full_name or None,
            "role": UserRole.NORMAL.value,
            "is_active": True,
            "oauth_provider": "github",
            "oauth_sub": github_id,
            "created_at": now,
            "updated_at": now,
        }
        result = await db.users.insert_one(user_doc)
        user_doc["_id"] = result.inserted_id
        return user_doc

    async def request_password_reset(self, db: AsyncIOMotorDatabase, email: str) -> None:
        user = await db.users.find_one({"email": email})
        if not user:
            return

        token = secrets.token_urlsafe(32)
        token_hash = self._hash_reset_token(token)
        now = datetime.utcnow()
        expires_at = now + timedelta(minutes=settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES)

        await db.password_resets.insert_one(
            {
                "user_id": user["_id"],
                "token_hash": token_hash,
                "created_at": now,
                "expires_at": expires_at,
                "used_at": None,
            }
        )

        reset_link = f"{settings.FRONTEND_BASE_URL.rstrip('/')}/reset-password?token={token}"
        subject = "Reset your VULCAN password"
        body_text = (
            "We received a request to reset your password.\n\n"
            f"Reset your password using this link:\n{reset_link}\n\n"
            "If you did not request this, you can ignore this email."
        )
        body_html = f"""
            <p>We received a request to reset your password.</p>
            <p><a href="{reset_link}">Reset your password</a></p>
            <p>If you did not request this, you can ignore this email.</p>
        """

        email_service = EmailService()
        await email_service.send_email(user.get("email"), subject, body_text, body_html)

    async def reset_password(self, db: AsyncIOMotorDatabase, token: str, new_password: str) -> None:
        now = datetime.utcnow()
        token_hash = self._hash_reset_token(token)
        reset_doc = await db.password_resets.find_one(
            {
                "token_hash": token_hash,
                "used_at": None,
                "expires_at": {"$gt": now},
            }
        )
        if not reset_doc:
            raise AuthenticationException("Invalid or expired reset token")

        await db.users.update_one(
            {"_id": reset_doc["user_id"]},
            {"$set": {"hashed_password": get_password_hash(new_password), "updated_at": now}},
        )
        await db.password_resets.update_one({"_id": reset_doc["_id"]}, {"$set": {"used_at": now}})

    async def validate_reset_token(self, db: AsyncIOMotorDatabase, token: str) -> bool:
        now = datetime.utcnow()
        token_hash = self._hash_reset_token(token)
        reset_doc = await db.password_resets.find_one(
            {
                "token_hash": token_hash,
                "used_at": None,
                "expires_at": {"$gt": now},
            }
        )
        return bool(reset_doc)
