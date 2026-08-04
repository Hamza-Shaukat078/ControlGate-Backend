from dataclasses import dataclass
from typing import Optional

from app.domain.analysis.dast.verdict import Verdict


@dataclass
class DynamicFinding:
    """A single DAST check result. Deliberately not shaped like the static
    file/line vulnerability dict (pipeline.py::_format_vulnerability) — this
    is HTTP-shaped, not source-shaped. Stored as its own dynamic_findings
    list in the scan summary, same precedent as dynamic_probe_findings.
    """

    control_id: str
    verdict: Verdict
    rule_id: str
    url: str
    method: str
    note: str
    severity: str = "medium"
    confidence: float = 0.6
    # Must already be redacted (DastSession.redact()) by the check that built it.
    evidence: Optional[str] = None
