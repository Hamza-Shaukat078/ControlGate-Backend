from datetime import datetime
from typing import Optional

from app.enums.asvs import ASVSLevel, ControlVerdict, EvidenceSource
from app.schemas.common import APIModel


class ASVSControl(APIModel):
    """Catalog definition of a single ASVS requirement (source of truth: app/data/asvs_l1_controls.json)."""
    control_id: str          # e.g. "V5.3.2"
    chapter_id: str          # e.g. "V5"
    chapter: str             # e.g. "V5: File Handling"
    section_id: str          # e.g. "5.3"
    section_name: str        # e.g. "File Storage"
    level: ASVSLevel
    description: str
    detection_strategy: EvidenceSource
    check_ref: Optional[str] = None   # id of the rule/inspector that evaluates this control


class ASVSEvidenceItem(APIModel):
    file: Optional[str] = None
    line: Optional[int] = None
    note: Optional[str] = None


class ASVSControlResult(APIModel):
    """Outcome of evaluating one control against one scan."""
    control_id: str
    scan_id: str
    verdict: ControlVerdict = ControlVerdict.NOT_TESTED
    confidence: Optional[float] = None
    evidence: list[ASVSEvidenceItem] = []
    llm_explanation: Optional[str] = None
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None


class ASVSChapterSummary(APIModel):
    chapter_id: str
    title: str
    detection_strategy: Optional[str] = None
    control_count: int
    counts: dict[str, int]


class ASVSLevelCompletion(APIModel):
    total: int
    passed: int
    pct: int


class ASVSComplianceSummary(APIModel):
    scan_id: str
    chapters: list[ASVSChapterSummary]
    levels: dict[str, ASVSLevelCompletion]
    generated_at: datetime


class AttestationRecord(APIModel):
    control_id: str
    scan_id: Optional[str] = None
    answer: ControlVerdict
    evidence_url: Optional[str] = None
    attested_by: Optional[str] = None
    timestamp: datetime


class AttestationSubmit(APIModel):
    control_id: str
    answer: ControlVerdict
    evidence_url: Optional[str] = None
