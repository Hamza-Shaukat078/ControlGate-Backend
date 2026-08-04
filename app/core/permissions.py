"""
Role-based permission system.
Provides decorators and utilities for role-based access control.
"""

from datetime import datetime, timezone
from fastapi import Depends, HTTPException, status
from functools import wraps
from app.enums.role import UserRole
from app.core.exceptions import AuthorizationException

# Monthly scan quota per role (C1-C5 from business rules)
SCAN_QUOTA: dict[str, int | None] = {
    UserRole.NORMAL.value:  5,
    UserRole.PREMIUM.value: 50,
    UserRole.ADMIN.value:   None,  # unlimited
}


def require_role(*allowed_roles: UserRole):
    """
    Decorator to enforce role-based access control.
    
    Usage:
        @require_role(UserRole.ADMIN)
        async def admin_only_endpoint(user=Depends(get_current_user)):
            pass
        
        @require_role(UserRole.ADMIN, UserRole.PREMIUM)
        async def premium_and_admin_endpoint(user=Depends(get_current_user)):
            pass
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # The 'user' parameter should be in kwargs from FastAPI dependency injection
            user = kwargs.get('user')
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not authenticated"
                )
            
            user_role = user.get('role')
            role_values = [role.value for role in allowed_roles]
            
            if user_role not in role_values:
                raise AuthorizationException(
                    f"User role '{user_role}' is not authorized for this action. "
                    f"Required roles: {', '.join(role_values)}"
                ).to_http_exception()
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def is_admin(user: dict) -> bool:
    """Check if user is admin."""
    return user.get('role') == UserRole.ADMIN.value


def is_premium(user: dict) -> bool:
    """Check if user is premium or admin."""
    role = user.get('role')
    return role in [UserRole.PREMIUM.value, UserRole.ADMIN.value]


def is_normal(user: dict) -> bool:
    """Check if user is normal, premium, or admin."""
    return user.get('role') in [UserRole.NORMAL.value, UserRole.PREMIUM.value, UserRole.ADMIN.value]


def can_access_resource(user: dict, resource_owner_id: str) -> bool:
    """
    Check if user can access a resource.
    Admins can access all resources, users can only access their own.
    """
    if is_admin(user):
        return True
    return str(user.get('id')) == str(resource_owner_id)


def verify_resource_ownership(user: dict, owner_id: str):
    """
    Verify that user owns the resource.
    Raises AuthorizationException if not authorized.
    """
    if not can_access_resource(user, owner_id):
        raise AuthorizationException(
            f"User {user.get('id')} is not authorized to access resource owned by {owner_id}"
        ).to_http_exception()


async def check_scan_quota(user: dict, db) -> None:
    """
    Enforce monthly scan quota based on user role (C1-C5).

    Quota limits:
      NORMAL  →  5 scans / month
      PREMIUM → 50 scans / month
      ADMIN   →  unlimited

    Raises HTTP 429 when the user has reached their monthly limit.
    """
    role = user.get("role", UserRole.NORMAL.value)
    limit = SCAN_QUOTA.get(role)

    # Admin → unlimited (C5)
    if limit is None:
        return

    # Count scans started by this user since midnight today (UTC)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    midnight = datetime(now.year, now.month, now.day, 0, 0, 0)

    from app.db.mongo import to_object_id
    user_oid = to_object_id(user.get("id"))

    user_values = [str(user.get("id"))]
    if user_oid:
        user_values.append(user_oid)
    count = await db.scans.count_documents({
        "user_id":    {"$in": user_values},
        "created_at": {"$gte": midnight},
    })

    if count >= limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Daily scan quota exceeded. "
                f"Your plan ({role}) allows {limit} scans per day. "
                f"Used: {count}/{limit}. "
                f"Quota resets at midnight (UTC)."
            ),
        )
