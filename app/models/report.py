from datetime import datetime
from sqlalchemy import String, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    scan_id: Mapped[str] = mapped_column(String(64), index=True)
    repo_id: Mapped[int] = mapped_column(index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    total_vulns: Mapped[int] = mapped_column(default=0)
    critical: Mapped[int] = mapped_column(default=0)
    high: Mapped[int] = mapped_column(default=0)
    medium: Mapped[int] = mapped_column(default=0)
    low: Mapped[int] = mapped_column(default=0)
    ai_accuracy: Mapped[float] = mapped_column(default=0.0)
