"""Race-condition probe (V2.3.4) — fires N concurrent requests at the same
endpoint and counts how many "succeeded" (2xx).

Deliberately not expressed as a Scenario: scenario_runner.py executes steps
strictly sequentially, but a race probe is fundamentally about concurrency —
forcing it into the sequential Step model would misrepresent what's actually
being tested. This is its own small engine, same rationale as
run_payload_checks (single-request) vs run_scenario (sequential multi-step)
being separate: different shapes need different mechanisms, not one
over-general one.

Always requires_active_mode: firing concurrent requests at a real endpoint
(double-booking, coupon redemption, etc.) has real side effects — this is
the most inherently disruptive check in the engine.
"""
import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.domain.analysis.dast.findings import DynamicFinding
from app.domain.analysis.dast.session import DastSessionPair
from app.domain.analysis.dast.verdict import Verdict

logger = logging.getLogger(__name__)


@dataclass
class RaceProbeConfig:
    scenario_id: str
    url: str
    asvs_controls: List[str] = field(default_factory=lambda: ["V2.3.4"])
    method: str = "POST"
    session: str = "primary"
    params: Optional[Dict[str, Any]] = None
    data: Optional[Dict[str, Any]] = None
    headers: Optional[Dict[str, Any]] = None
    concurrency: int = 5
    max_expected_successes: int = 1
    requires_active_mode: bool = True
    severity: str = "high"


async def run_race_probe(
    pair: DastSessionPair, config: RaceProbeConfig, *, active_mode: bool = False,
) -> DynamicFinding:
    control_id = config.asvs_controls[0] if config.asvs_controls else config.scenario_id

    if config.requires_active_mode and not active_mode:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION,
            rule_id=config.scenario_id, url=config.url, method=config.method, severity=config.severity,
            note="This race probe has side effects and active_mode was not enabled for this scan",
            confidence=1.0,
        )

    session = pair.primary if config.session == "primary" else pair.secondary
    if session is None:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_CONFIGURED, rule_id=config.scenario_id,
            url=config.url, method=config.method, severity=config.severity,
            note=f"Race probe requires a '{config.session}' session that wasn't configured for this scan",
            confidence=1.0,
        )

    kwargs: Dict[str, Any] = {}
    if config.params:
        kwargs["params"] = config.params
    if config.data:
        kwargs["data"] = config.data
    if config.headers:
        kwargs["headers"] = config.headers

    tasks = [session.request(config.method, config.url, **kwargs) for _ in range(config.concurrency)]
    responses = await asyncio.gather(*tasks, return_exceptions=True)

    reached = [r for r in responses if not isinstance(r, Exception)]
    successful = [r for r in reached if 200 <= r.status_code < 300]

    if not reached:
        sample_error = next((r for r in responses if isinstance(r, Exception)), None)
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=config.scenario_id,
            url=config.url, method=config.method, severity=config.severity,
            note=f"Could not reach the target with any of the {config.concurrency} concurrent "
                 f"requests: {session.redact(str(sample_error))}",
            confidence=0.2,
        )

    if len(successful) > config.max_expected_successes:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.FAIL, rule_id=config.scenario_id,
            url=config.url, method=config.method, severity=config.severity,
            note=f"{len(successful)} of {config.concurrency} concurrent requests succeeded (2xx), "
                 f"expected at most {config.max_expected_successes} — evidence of a race condition "
                 f"(a single test run; timing-dependent, re-running may find it intermittently)",
            confidence=0.55,
        )

    return DynamicFinding(
        control_id=control_id, verdict=Verdict.PASS, rule_id=config.scenario_id,
        url=config.url, method=config.method, severity=config.severity,
        note=f"{len(successful)} of {config.concurrency} concurrent requests succeeded, within the "
             f"expected maximum of {config.max_expected_successes} — a single clean run doesn't prove "
             f"race-safety under all timings",
        confidence=0.4,
    )
