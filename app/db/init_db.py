from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import inspect, select, text

from app.db.session import engine
from app.db.base import Base
from app.models.user import User
from app.core.config import settings
from app.core.security import get_password_hash


async def init_models() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_ensure_repository_owner_column)


def _ensure_repository_owner_column(sync_conn) -> None:
    inspector = inspect(sync_conn)
    if "repositories" not in inspector.get_table_names():
        return
    columns = {column["name"] for column in inspector.get_columns("repositories")}
    if "owner_user_id" not in columns:
        sync_conn.execute(text("ALTER TABLE repositories ADD COLUMN owner_user_id VARCHAR(255)"))


async def seed_admin(session: AsyncSession) -> None:
    result = await session.execute(select(User).where(User.email == settings.DEFAULT_ADMIN_EMAIL))
    user = result.scalar_one_or_none()
    if user is None:
        if not settings.DEFAULT_ADMIN_PASSWORD:
            return
        if settings.ENV.lower() not in {"dev", "development", "local", "test"} and settings.DEFAULT_ADMIN_PASSWORD == "admin123!":
            raise RuntimeError("Refusing to seed a default admin with a weak production password")
        admin = User(
            email=settings.DEFAULT_ADMIN_EMAIL,
            hashed_password=get_password_hash(settings.DEFAULT_ADMIN_PASSWORD),
            full_name="Admin",
            role="ADMIN",
            is_active=True,
            is_superuser=True,
        )
        session.add(admin)
        await session.commit()
