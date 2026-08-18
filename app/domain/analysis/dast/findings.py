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

    # Structured proof fields (Phase 1 confirmation spine). All additive and
    # default to None — existing checks that only ever set verdict/note/
    # evidence keep working unchanged; only a check that actually reproduced
    # impact (oracles.py) sets these, which is what makes a CONFIRMED verdict
    # meaningful instead of just a stronger label on the same heuristic.
    #
    # One of "oob_callback" | "time_delay" | "data_exfil" | "js_execution" |
    # "reflection" | "response_diff" | "error_signature" — what kind of
    # proof backs this finding.
    evidence_type: Optional[str] = None
    # The exact payload used to produce the proof. Must already be redacted
    # (DastSession.redact()) by the check that built it, same rule as evidence.
    payload: Optional[str] = None
    # A curl-equivalent string a human can paste to re-trigger the finding —
    # the "receipt" that makes CONFIRMED verifiable outside this scan.
    reproduction: Optional[str] = None
    # Check-specific structured evidence, e.g. {"true_ms": 5200, "false_ms": 190}
    # for time-based SQLi, {"token": "...", "hits": 1} for OOB confirmation.
    proof: Optional[dict] = None

    # Set only for findings produced by scan_service.py's bridge loop
    # (bridge.py's BridgeTarget re-testing a specific static finding's
    # route) — the exact static finding id this result should be matched
    # back against. A direct field rather than packing this into `evidence`
    # as a colon-delimited string and parsing it back apart later (Phase
    # 2.4) — same "structured over string-encoded" preference as the rest
    # of the confirmation spine.
    bridge_static_finding_id: Optional[str] = None
