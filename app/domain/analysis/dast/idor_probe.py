"""Cross-session IDOR/BOLA probe (V8.2.1) — Phase 3's first new dynamic rule.

Static analysis has a rule for this (BROKEN_ACCESS_CONTROL, queries.json,
maps to V8.2.1/V8.2.2) but it can only flag "an ID from user input reaches a
lookup with no ownership guard nearby" — it can't confirm the guard is
actually missing at runtime. This probe can, because DastSessionPair already
gives a scan two independently authenticated actors (added for V7.4.3
cross-session checks): have actor A request a resource it legitimately owns,
then have actor B — a different account — request the exact same URL. If B
also gets a 2xx, nothing stopped it.

Same shape as race_probe.py (own small runner, not a Scenario) because the
two calls are actor-scoped rather than sequential steps against one session,
which the Scenario/Step model isn't built to express.

Whether this requires active_mode depends on config.method: a GET a second
actor was never authorized to make is still just a read, no different in
kind from the other non-active-mode payload checks; a mutating method
(POST/PUT/PATCH/DELETE) succeeding via someone else's session actually
changes the target's state and needs the same explicit authorization race
probes and smuggling already require.
"""
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.domain.analysis.dast.findings import DynamicFinding
from app.domain.analysis.dast.session import DastSessionPair
from app.domain.analysis.dast.verdict import Verdict

logger = logging.getLogger(__name__)

_DENIED_STATUS_CODES = {401, 403, 404}
_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@dataclass
class IdorProbeConfig:
    scenario_id: str
    # A URL the primary actor can legitimately reach — e.g. GET /orders/42
    # where 42 belongs to the primary actor's own account.
    owner_resource_url: str
    asvs_controls: List[str] = field(default_factory=lambda: ["V8.2.1"])
    method: str = "GET"
    params: Optional[Dict[str, Any]] = None
    data: Optional[Dict[str, Any]] = None
    headers: Optional[Dict[str, Any]] = None
    severity: str = "high"
    # None => derive from method (mutating methods need active_mode, GET/HEAD don't).
    # Explicit True/False overrides that inference for callers that know better.
    requires_active_mode: Optional[bool] = None

    def resolved_requires_active_mode(self) -> bool:
        if self.requires_active_mode is not None:
            return self.requires_active_mode
        return self.method.upper() in _MUTATING_METHODS


async def run_idor_probe(
    pair: DastSessionPair, config: IdorProbeConfig, *, active_mode: bool = False,
) -> DynamicFinding:
    control_id = config.asvs_controls[0] if config.asvs_controls else config.scenario_id

    if config.resolved_requires_active_mode() and not active_mode:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION,
            rule_id=config.scenario_id, url=config.owner_resource_url, method=config.method,
            severity=config.severity,
            note="This IDOR probe uses a state-changing method and active_mode was not enabled for this scan",
            confidence=1.0,
        )

    if pair.secondary is None:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_CONFIGURED, rule_id=config.scenario_id,
            url=config.owner_resource_url, method=config.method, severity=config.severity,
            note="IDOR probe requires a second actor session that wasn't configured for this scan",
            confidence=1.0,
        )

    kwargs: Dict[str, Any] = {}
    if config.params:
        kwargs["params"] = config.params
    if config.data:
        kwargs["data"] = config.data
    if config.headers:
        kwargs["headers"] = config.headers

    try:
        owner_resp = await pair.primary.request(config.method, config.owner_resource_url, **kwargs)
    except Exception as exc:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=config.scenario_id,
            url=config.owner_resource_url, method=config.method, severity=config.severity,
            note=f"Owning actor could not reach the resource: {pair.primary.redact(str(exc))}",
            confidence=0.2,
        )

    if not (200 <= owner_resp.status_code < 300):
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=config.scenario_id,
            url=config.owner_resource_url, method=config.method, severity=config.severity,
            note=f"Owning actor's own request returned {owner_resp.status_code} — can't establish a "
                 f"baseline of legitimate access to compare the second actor's response against",
            confidence=0.25,
        )

    try:
        other_resp = await pair.secondary.request(config.method, config.owner_resource_url, **kwargs)
    except Exception as exc:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=config.scenario_id,
            url=config.owner_resource_url, method=config.method, severity=config.severity,
            note=f"Second actor's request failed: {pair.secondary.redact(str(exc))}", confidence=0.2,
        )

    if other_resp.status_code in _DENIED_STATUS_CODES:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.PASS, rule_id=config.scenario_id,
            url=config.owner_resource_url, method=config.method, severity=config.severity,
            note=f"Second actor was denied ({other_resp.status_code}) access to the first actor's resource",
            confidence=0.6,
        )

    if 200 <= other_resp.status_code < 300:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.FAIL, rule_id=config.scenario_id,
            url=config.owner_resource_url, method=config.method, severity=config.severity,
            note=f"Second actor received {other_resp.status_code} on a resource the first actor owns — "
                 f"no ownership check appears to gate this endpoint (a single test run; the response "
                 f"body wasn't diffed against a genuine access-denied page, so treat this as a strong "
                 f"signal, not absolute proof)",
            confidence=0.65,
        )

    return DynamicFinding(
        control_id=control_id, verdict=Verdict.INCONCLUSIVE, rule_id=config.scenario_id,
        url=config.owner_resource_url, method=config.method, severity=config.severity,
        note=f"Ambiguous result: owner got {owner_resp.status_code}, second actor got {other_resp.status_code}",
        confidence=0.3,
    )
