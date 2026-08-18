"""Mass assignment probe (V15.3.3, Phase 3 item 7) — confirms an
object-update endpoint blindly binds every field in the request body
(rather than allowlisting the ones a client is actually permitted to set)
by submitting an unexpected privileged field alongside a normal-looking
update and checking whether it actually took.

Same shape as idor_probe.py/race_probe.py (own small runner, not a
Scenario or a checks.py payload function) because this needs *two*
independent, actor-scoped reads around a single mutating request — the
Scenario/Step model only ever drives one session sequentially, and
run_payload_checks' per-URL dispatch has no concept of "submit here, then
verify somewhere else with a different session" at all.

Two-actor gated, deliberately stricter than most checks in this engine:
the submitting session (primary — the low-privilege account performing
the mass-assignment attempt) reading its own change back afterward would
be self-referential evidence — plenty of frameworks echo the request body
back in the response whether or not anything was actually persisted. A
genuinely independent second session (secondary) re-reading the resource
is what turns "the server said something" into "the server's actual
state changed" — the same "don't trust the submitter's own view" reasoning
idor_probe.py's cross-session comparison already established, applied here
to state persistence instead of access control.

Always requires_active_mode: submitting an unrequested privileged field to
a real update endpoint is a real mutation with real consequences if it
works, same risk class as CSRF_TOKEN_NOT_VALIDATED/race_probe.py.
"""
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.domain.analysis.dast.findings import DynamicFinding
from app.domain.analysis.dast.session import DastSessionPair
from app.domain.analysis.dast.verdict import Verdict

logger = logging.getLogger(__name__)


@dataclass
class MassAssignmentProbeConfig:
    scenario_id: str
    # An object-update endpoint the primary (low-privilege) actor can
    # legitimately reach — e.g. PATCH /profile, PUT /account.
    update_url: str
    asvs_controls: List[str] = field(default_factory=lambda: ["V15.3.3"])
    update_method: str = "PATCH"
    # Legitimate fields to submit alongside the injected one (e.g.
    # {"display_name": "New Name"}) — keeps the request shaped like a
    # normal update, not a bare injection attempt with nothing else in it.
    baseline_fields: Optional[Dict[str, Any]] = None
    # The unexpected privileged field/value to smuggle into the update —
    # a field the client was never meant to be able to set at all.
    injected_field: str = "role"
    injected_value: Any = "admin"
    # Where to independently re-read the object afterward — defaults to
    # update_url itself (GET the same resource). Supports a dotted path
    # into a nested JSON response (e.g. "user.role") via _extract_field.
    verify_url: Optional[str] = None
    verify_field_path: Optional[str] = None
    severity: str = "high"


def _extract_field(obj: Any, field_path: str) -> Any:
    current = obj
    for part in field_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


async def run_mass_assignment_probe(
    pair: DastSessionPair, config: MassAssignmentProbeConfig, *, active_mode: bool = False,
) -> DynamicFinding:
    control_id = config.asvs_controls[0] if config.asvs_controls else config.scenario_id
    verify_url = config.verify_url or config.update_url
    field_path = config.verify_field_path or config.injected_field

    if not active_mode:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION,
            rule_id=config.scenario_id, url=config.update_url, method=config.update_method,
            severity=config.severity,
            note="Submitting an unrequested privileged field to a real update endpoint has side "
                 "effects and active_mode was not enabled for this scan",
            confidence=1.0,
        )

    if pair.secondary is None:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_CONFIGURED, rule_id=config.scenario_id,
            url=config.update_url, method=config.update_method, severity=config.severity,
            note="Mass assignment probe requires a second, independent actor session to verify the "
                 "change actually persisted (rather than trusting the submitting session's own view), "
                 "and one wasn't configured for this scan",
            confidence=1.0,
        )

    try:
        baseline_resp = await pair.secondary.request("GET", verify_url)
    except Exception as exc:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=config.scenario_id,
            url=verify_url, method="GET", severity=config.severity,
            note=f"Second actor could not read the baseline resource: {pair.secondary.redact(str(exc))}",
            confidence=0.2,
        )
    if baseline_resp.status_code == 404:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=config.scenario_id,
            url=verify_url, method="GET", severity=config.severity,
            note="Verification endpoint returned 404 — nothing here to read a baseline from",
            confidence=0.2,
        )
    try:
        baseline_json = baseline_resp.json()
    except Exception:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=config.scenario_id,
            url=verify_url, method="GET", severity=config.severity,
            note="Verification endpoint's response wasn't JSON — can't check a field's value in it",
            confidence=0.2,
        )

    baseline_value = _extract_field(baseline_json, field_path)
    if baseline_value == config.injected_value:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.INCONCLUSIVE, rule_id=config.scenario_id,
            url=verify_url, method="GET", severity=config.severity,
            note=f"'{field_path}' already equals the injected value ({config.injected_value!r}) before "
                 f"any submission — can't attribute a change to this probe",
            confidence=0.25,
        )

    submit_data = {**(config.baseline_fields or {}), config.injected_field: config.injected_value}
    try:
        submit_resp = await pair.primary.request(
            config.update_method, config.update_url, json=submit_data,
        )
    except Exception as exc:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=config.scenario_id,
            url=config.update_url, method=config.update_method, severity=config.severity,
            note=f"Primary actor's update request failed: {pair.primary.redact(str(exc))}", confidence=0.2,
        )

    try:
        after_resp = await pair.secondary.request("GET", verify_url)
        after_json = after_resp.json()
    except Exception as exc:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=config.scenario_id,
            url=verify_url, method="GET", severity=config.severity,
            note=f"Second actor could not re-read the resource after submission: "
                 f"{pair.secondary.redact(str(exc))}",
            confidence=0.2,
        )

    after_value = _extract_field(after_json, field_path)
    if after_value == config.injected_value:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.CONFIRMED, rule_id=config.scenario_id,
            url=config.update_url, method=config.update_method, severity=config.severity,
            note=f"Submitting an unrequested '{config.injected_field}' field on the update request "
                 f"changed '{field_path}' from {baseline_value!r} to {after_value!r} — independently "
                 f"confirmed by a second actor's own request (submit status "
                 f"{submit_resp.status_code}), not just the submitting session's own view. The endpoint "
                 f"binds request fields it was never meant to accept",
            confidence=0.9, evidence_type="response_diff",
            payload=pair.primary.redact(str(submit_data)),
            proof={
                "injected_field": config.injected_field, "injected_value": config.injected_value,
                "baseline_value": baseline_value, "after_value": after_value,
                "submit_status": submit_resp.status_code,
            },
            reproduction=(
                f"curl -s -X {config.update_method} '{config.update_url}' "
                f"-H 'Content-Type: application/json' --data '{submit_data}'"
            ),
        )

    return DynamicFinding(
        control_id=control_id, verdict=Verdict.PASS, rule_id=config.scenario_id,
        url=config.update_url, method=config.update_method, severity=config.severity,
        note=f"'{field_path}' was still {after_value!r} after submitting an unrequested "
             f"'{config.injected_field}' field (submit status {submit_resp.status_code}) — the endpoint "
             f"does not appear to bind it",
        confidence=0.5,
    )
