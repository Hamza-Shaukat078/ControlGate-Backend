"""Converts the ScanStart API's user-supplied scenario shape into the domain
Scenario/Step/Assertion objects scenario_runner.py executes.

Deliberately a smaller surface than the internal Scenario schema —
extraction/interpolation across steps stays code-only (as used by
logout_discovery.py's auto-built scenario) until real demand shows up for
exposing it over the API. Each API step maps to at most one assertion
(assert_status_in) for now; this is what makes app-specific checks like
V7.4.3 (credential-change-invalidates-sessions) and V8.3.2
(permission-revoke-takes-effect-immediately) possible without the engine
having to guess app-specific endpoints — the scan config supplies them.
"""
from typing import Any, Dict

from app.domain.analysis.dast.scenario import Assertion, Scenario, Step


def build_scenario_from_request(data: Dict[str, Any]) -> Scenario:
    steps = []
    for step_data in data["steps"]:
        assertions = []
        if step_data.get("assert_status_in"):
            assertions.append(Assertion(type="status_in", expected=step_data["assert_status_in"]))
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
        ))
    return Scenario(
        scenario_id=data["scenario_id"],
        asvs_controls=data.get("asvs_controls", []),
        requires_active_mode=data.get("requires_active_mode", True),
        severity=data.get("severity", "medium"),
        description=data.get("description", ""),
        steps=steps,
    )
