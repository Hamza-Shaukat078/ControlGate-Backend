"""Converts the ScanStart API's user-supplied scenario shape into the domain
Scenario/Step/Assertion objects scenario_runner.py executes.

Deliberately a smaller surface than the internal Scenario schema —
extraction/interpolation across steps stays code-only (as used by
logout_discovery.py's auto-built scenario) until real demand shows up for
exposing it over the API. Each API step maps to zero or more assertions
(assert_status_in, plus assert_body_contains/assert_body_not_contains/
assert_redirect_location_contains added for the V10.4.x/V10.7.1 OAuth
live-protocol checks — see DynamicScenarioStepRequest's own docstring for
why status codes alone aren't enough for those) — every non-null assert_*
field on a step becomes its own Assertion, all ANDed together by
scenario_runner.run_scenario's "every assertion in the list must pass"
loop. This is what makes app-specific checks like V7.4.3
(credential-change-invalidates-sessions) and V8.3.2
(permission-revoke-takes-effect-immediately) possible without the engine
having to guess app-specific endpoints — the scan config supplies them.
"""
from typing import Any, Dict

from app.domain.analysis.dast.scenario import Assertion, Scenario, Step

# (API field name, Assertion type) — iterated in build_scenario_from_request
# so adding another assert_* field later is a one-line addition here, not a
# new if-branch.
_ASSERTION_FIELD_MAP = (
    ("assert_status_in", "status_in"),
    ("assert_body_contains", "body_contains"),
    ("assert_body_not_contains", "body_not_contains"),
    ("assert_redirect_location_contains", "redirect_location_contains"),
)


def build_scenario_from_request(data: Dict[str, Any]) -> Scenario:
    steps = []
    for step_data in data["steps"]:
        assertions = [
            Assertion(type=assertion_type, expected=step_data[field_name])
            for field_name, assertion_type in _ASSERTION_FIELD_MAP
            if step_data.get(field_name) is not None
        ]
        steps.append(Step(
            method=step_data["method"],
            url=step_data["url"],
            session=step_data.get("session", "primary"),
            params=step_data.get("params"),
            data=step_data.get("data"),
            json_body=step_data.get("json_body"),
            headers=step_data.get("headers"),
            follow_redirects=step_data.get("follow_redirects", False),
            assertions=assertions,
            delay_seconds=step_data.get("delay_seconds"),
        ))
    return Scenario(
        scenario_id=data["scenario_id"],
        asvs_controls=data.get("asvs_controls", []),
        requires_active_mode=data.get("requires_active_mode", True),
        severity=data.get("severity", "medium"),
        description=data.get("description", ""),
        steps=steps,
    )
