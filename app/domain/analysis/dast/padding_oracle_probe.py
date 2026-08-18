"""Timing side-channel probe (V11.2.5) — sends two tester-supplied, fixed
payload variants at the same endpoint and checks whether the target's
response timing distinguishes them.

Deliberately not expressed as a Scenario or via scenario_runner's assertion
vocabulary: neither status code nor response body is the signal here, only
wall-clock timing across many samples — a different shape from every other
check in this engine, same reasoning race_probe.py is its own small engine
rather than forced into the sequential Step model.

This scanner has no way to generate cryptographically-valid malformed
ciphertext for a target's own encryption scheme (block size, mode, key are
all unknown to it) — variant_a/variant_b are supplied by the tester, who
already knows the target's scheme and has crafted (for example) a
valid-padding-but-wrong-content ciphertext and an invalid-padding one.
requires_active_mode defaults true: this repeatedly submits real payloads
to a decryption/verification endpoint, same side-effect posture as every
other active_mode-gated check.
"""
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.domain.analysis.dast.findings import DynamicFinding
from app.domain.analysis.dast.oracles import comparative_timing_oracle
from app.domain.analysis.dast.session import DastSessionPair
from app.domain.analysis.dast.verdict import Verdict

logger = logging.getLogger(__name__)


@dataclass
class TimingProbeVariant:
    params: Optional[Dict[str, Any]] = None
    data: Optional[Dict[str, Any]] = None
    json_body: Optional[Dict[str, Any]] = None


@dataclass
class TimingComparisonProbeConfig:
    scenario_id: str
    url: str
    variant_a: TimingProbeVariant
    variant_b: TimingProbeVariant
    asvs_controls: List[str] = field(default_factory=lambda: ["V11.2.5"])
    method: str = "POST"
    session: str = "primary"
    headers: Optional[Dict[str, Any]] = None
    samples: int = 7
    requires_active_mode: bool = True
    severity: str = "medium"


async def run_timing_comparison_probe(
    pair: DastSessionPair, config: TimingComparisonProbeConfig, *, active_mode: bool = False,
) -> DynamicFinding:
    control_id = config.asvs_controls[0] if config.asvs_controls else config.scenario_id

    if config.requires_active_mode and not active_mode:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION,
            rule_id=config.scenario_id, url=config.url, method=config.method, severity=config.severity,
            note="This timing-comparison probe repeatedly submits real payloads and "
                 "active_mode was not enabled for this scan",
            confidence=1.0,
        )

    session = pair.primary if config.session == "primary" else pair.secondary
    if session is None:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_CONFIGURED, rule_id=config.scenario_id,
            url=config.url, method=config.method, severity=config.severity,
            note=f"Timing-comparison probe requires a '{config.session}' session that "
                 f"wasn't configured for this scan",
            confidence=1.0,
        )

    async def _send(variant: TimingProbeVariant):
        kwargs: Dict[str, Any] = {}
        if variant.params:
            kwargs["params"] = variant.params
        if variant.data:
            kwargs["data"] = variant.data
        if variant.json_body is not None:
            kwargs["json"] = variant.json_body
        if config.headers:
            kwargs["headers"] = config.headers
        return await session.request(config.method, config.url, **kwargs)

    attempted = 0

    async def _send_a():
        nonlocal attempted
        attempted += 1
        return await _send(config.variant_a)

    async def _send_b():
        nonlocal attempted
        attempted += 1
        return await _send(config.variant_b)

    try:
        confirmed, proof = await comparative_timing_oracle(_send_a, _send_b, samples=config.samples)
    except Exception as exc:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=config.scenario_id,
            url=config.url, method=config.method, severity=config.severity,
            note=f"Timing-comparison probe failed before completing its {config.samples} "
                 f"sample pairs: {session.redact(str(exc))} ({attempted} request(s) sent)",
            confidence=0.2,
        )

    if confirmed:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.FAIL, rule_id=config.scenario_id,
            url=config.url, method=config.method, severity=config.severity,
            note=f"The two payload variants are distinguishable by response timing across "
                 f"{config.samples} interleaved sample pairs each (delta "
                 f"{proof['delta_ms']}ms, noise floor {proof['noise_floor_ms']}ms) — a "
                 f"measurable timing side channel, best-effort indicator (not a proven "
                 f"plaintext-recovery exploit chain; the response content/error messages "
                 f"should also be compared for the same distinction).",
            confidence=0.55, evidence_type="response_diff", proof=proof,
        )

    return DynamicFinding(
        control_id=control_id, verdict=Verdict.PASS, rule_id=config.scenario_id,
        url=config.url, method=config.method, severity=config.severity,
        note=f"No statistically significant timing difference observed between the two "
             f"payload variants across {config.samples} interleaved sample pairs each "
             f"(delta {proof['delta_ms']}ms, noise floor {proof['noise_floor_ms']}ms) — "
             f"only proves these two specific payloads aren't distinguishable this way, "
             f"not the absence of every possible timing side channel.",
        confidence=0.35, evidence_type="response_diff", proof=proof,
    )
