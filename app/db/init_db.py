from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import engine
from app.db.base import Base
from app.models.user import User
from app.core.config import settings
from app.core.security import get_password_hash


async def init_models() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def seed_admin(session: AsyncSession) -> None:
    result = await session.execute(select(User).where(User.email == settings.DEFAULT_ADMIN_EMAIL))
    user = result.scalar_one_or_none()
    if user is None:
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
