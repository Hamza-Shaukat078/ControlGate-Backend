from datetime import datetime
from app.schemas.common import APIModel


class ReportItem(APIModel):
    id: int
    repo_id: int
    scan_id: str
    created_at: datetime | None = None
    total_vulns: int
    critical: int
    high: int
    medium: int
    low: int
    ai_accuracy: float
    compliance_flags: dict | None = None
