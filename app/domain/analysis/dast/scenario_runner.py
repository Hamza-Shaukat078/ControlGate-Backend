"""Executes a Scenario (Phase 2B) against a DastSessionPair.

Unlike Phase 2A's payload checks (one request, one response, one assertion),
a scenario is a sequence of requests where later steps can depend on values
extracted from earlier ones (e.g. a session cookie, a CSRF token) — that
interpolation is the only thing this engine adds over run_payload_checks.
"""
import logging
import re
from typing import Any, Dict, Optional

from app.domain.analysis.dast.findings import DynamicFinding
from app.domain.analysis.dast.scenario import Assertion, Extractor, Scenario, Step
from app.domain.analysis.dast.session import DastSessionPair
from app.domain.analysis.dast.verdict import Verdict

logger = logging.getLogger(__name__)

_REDIRECT_STATUS_CODES = (301, 302, 303, 307, 308)


def _interpolate(template: str, context: Dict[str, str]) -> str:
    result = template
    for key, value in context.items():
        result = result.replace("{" + key + "}", value)
    return result


def _extract_value(extractor: Extractor, response) -> Optional[str]:
    if extractor.source == "header":
        return response.headers.get(extractor.name)
    if extractor.source == "cookie":
        return response.cookies.get(extractor.name)
    if extractor.source == "regex":
        m = re.search(extractor.pattern, response.text)
        return m.group(1) if m else None
    if extractor.source == "json_path":
        try:
            data = response.json()
        except Exception:
            return None
        for part in extractor.path.split("."):
            if not isinstance(data, dict) or part not in data:
                return None
            data = data[part]
        return str(data)
    raise ValueError(f"Unknown extractor source: {extractor.source}")


def _evaluate_assertion(assertion: Assertion, response) -> bool:
    if assertion.type == "status_in":
        return response.status_code in assertion.expected
    if assertion.type == "status_not_in":
        return response.status_code not in assertion.expected
    if assertion.type == "body_contains":
        return assertion.expected in response.text
    if assertion.type == "redirect_location_contains":
        location = response.headers.get("location", "")
        return response.status_code in _REDIRECT_STATUS_CODES and assertion.expected in location
    if assertion.type == "any_of":
        return any(_evaluate_assertion(sub, response) for sub in (assertion.of or []))
    if assertion.type == "all_of":
        return all(_evaluate_assertion(sub, response) for sub in (assertion.of or []))
    raise ValueError(f"Unknown assertion type: {assertion.type}")


async def run_scenario(pair: DastSessionPair, scenario: Scenario, *, active_mode: bool = False) -> DynamicFinding:
    control_id = scenario.asvs_controls[0] if scenario.asvs_controls else scenario.scenario_id

    if scenario.requires_active_mode and not active_mode:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION,
            rule_id=scenario.scenario_id, url="", method="SCENARIO", severity=scenario.severity,
            note="This scenario has side effects and active_mode was not enabled for this scan",
            confidence=1.0,
        )

    if not scenario.steps:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_CONFIGURED, rule_id=scenario.scenario_id,
            url="", method="SCENARIO", severity=scenario.severity,
            note="No steps were supplied for this scenario", confidence=1.0,
        )

    context: Dict[str, str] = {}
    last_step: Optional[Step] = None
    last_url = ""

    try:
        for step in scenario.steps:
            session = pair.primary if step.session == "primary" else pair.secondary
            if session is None:
                return DynamicFinding(
                    control_id=control_id, verdict=Verdict.NOT_CONFIGURED, rule_id=scenario.scenario_id,
                    url=step.url, method=step.method, severity=scenario.severity,
                    note=f"Scenario step requires a '{step.session}' session that wasn't configured for this scan",
                    confidence=1.0,
                )

            last_url = _interpolate(step.url, context)
            last_step = step
            kwargs: Dict[str, Any] = {"follow_redirects": step.follow_redirects}
            if step.params:
                kwargs["params"] = {k: _interpolate(v, context) for k, v in step.params.items()}
            if step.data:
                kwargs["data"] = {k: _interpolate(v, context) for k, v in step.data.items()}
            if step.json_body is not None:
                kwargs["json"] = step.json_body
            if step.headers:
                kwargs["headers"] = {k: _interpolate(v, context) for k, v in step.headers.items()}

            response = await session.request(step.method, last_url, **kwargs)

            for extractor in step.extract:
                value = _extract_value(extractor, response)
                if value is not None:
                    context[extractor.var] = value

            for assertion in step.assertions:
                if not _evaluate_assertion(assertion, response):
                    return DynamicFinding(
                        control_id=control_id, verdict=Verdict.FAIL, rule_id=scenario.scenario_id,
                        url=last_url, method=step.method, severity=scenario.severity,
                        note=f"Step assertion failed: {assertion.type} (status={response.status_code})",
                        confidence=0.7,
                    )
    except Exception as exc:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=scenario.scenario_id,
            url=last_url, method=(last_step.method if last_step else "SCENARIO"), severity=scenario.severity,
            note=f"Scenario step failed: {pair.primary.redact(str(exc))}", confidence=0.3,
        )

    return DynamicFinding(
        control_id=control_id, verdict=Verdict.PASS, rule_id=scenario.scenario_id,
        url=last_url, method=(last_step.method if last_step else "SCENARIO"), severity=scenario.severity,
        note="All scenario step assertions passed", confidence=0.65,
    )
