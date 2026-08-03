from datetime import datetime

from app.core.config import settings
from app.core.security import get_password_hash
from app.db.mongo import get_mongo_database
from app.enums.role import UserRole


async def ensure_indexes() -> None:
    """
    Create required MongoDB indexes for optimal performance.
    
    Indexes created:
    - users.email: Unique index for authentication
    - scans.scan_id: Unique index for scan lookup
    - scans.user_id: Index for user-scoped queries
    """
    db = get_mongo_database()
    
    # User indexes
    await db.users.create_index("email", unique=True)
    
    # Scan indexes
    await db.scans.create_index("scan_id", unique=True)
    await db.scans.create_index("user_id")  # For user-scoped queries

    # ASVS control catalog + per-scan results
    await db.asvs_controls.create_index("control_id", unique=True)
    await db.asvs_results.create_index([("scan_id", 1), ("control_id", 1)], unique=True)

    # Manual attestations — one current attestation per control, upserted on each submit
    try:
        await db.attestations.drop_index("control_id_1")
    except Exception:
        pass
    await db.attestations.create_index([("user_id", 1), ("control_id", 1)], unique=True)
    await db.token_revocations.create_index("jti", unique=True)
    await db.token_revocations.create_index("expires_at", expireAfterSeconds=0)


async def seed_admin() -> None:
    """
    Create default admin user if not already exists.
    This ensures the system is always accessible for initial configuration.
    
    Admin credentials from environment:
    - DEFAULT_ADMIN_EMAIL
    - DEFAULT_ADMIN_PASSWORD
    """
    db = get_mongo_database()
    
    admin = await db.users.find_one({"email": settings.DEFAULT_ADMIN_EMAIL})
    if admin:
        return  # Admin already exists
    if not settings.DEFAULT_ADMIN_PASSWORD:
        return
    if settings.ENV.lower() not in {"dev", "development", "local", "test"} and settings.DEFAULT_ADMIN_PASSWORD == "admin123!":
        raise RuntimeError("Refusing to seed a default admin with a weak production password")
    
    now = datetime.utcnow()
    await db.users.insert_one(
        {
            "email": settings.DEFAULT_ADMIN_EMAIL,
            "hashed_password": get_password_hash(settings.DEFAULT_ADMIN_PASSWORD),
            "full_name": "Admin",
            "role": UserRole.ADMIN.value,
            "is_active": True,
            "created_at": now,
            "updated_at": now,
        }
    )
