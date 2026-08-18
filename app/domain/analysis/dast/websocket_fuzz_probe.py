"""WebSocket signaling-server fuzz probe (V17.3.2) — sends a corpus of
malformed offer/answer/ICE-candidate-shaped messages at a WebSocket
signaling endpoint and checks whether the server stays reachable.

Deliberately not built on DastSession/httpx: neither speaks the WebSocket
protocol at all. Uses the `websockets` library directly, same "add the one
dependency this specific check actually needs" precedent padding_oracle_probe.py
set for aiortc.

Detection shape, different from every other probe in this engine: there's
no single request/response to inspect for a status code or a body string.
The signal is CONNECTION-level: does the signaling server's listener still
accept and complete a fresh WebSocket handshake immediately after being
sent a malformed message. A baseline connection is required to succeed
first (so a target that was never reachable at all degrades honestly to
NOT_TESTED, not a false FAIL) — and a liveness recheck runs after EVERY
payload, not just at the end, so a mid-corpus crash is attributed to the
payload that caused it rather than lost in an end-of-run summary.

This proves the listening process didn't crash/hang; it does NOT prove the
malformed message was safely REJECTED (vs. silently accepted and processed
incorrectly) — same "real but partial" evidence class as every other
best-effort probe in this engine (padding_oracle_probe.py, race_probe.py).
"""
import asyncio
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from app.domain.analysis.dast.findings import DynamicFinding
from app.domain.analysis.dast.verdict import Verdict

logger = logging.getLogger(__name__)

CONNECT_TIMEOUT_SECONDS = 8.0

# A deliberately varied, small corpus — one representative case per failure
# class (truncated/invalid JSON, type confusion, oversized field, embedded
# control characters, a missing required field, a wrong top-level shape,
# non-JSON raw text, an empty frame) rather than an exhaustive fuzzer. Real
# fuzzing (many thousands of mutated variants, coverage-guided) is out of
# scope for a single scan's time budget — this is a smoke test for the
# obvious failure classes, not a substitute for a dedicated fuzzing campaign.
DEFAULT_SIGNALING_FUZZ_PAYLOADS: List[str] = [
    '{"type": "offer", "sdp": "v=0\\r\\no=- 46117317 2 IN IP4 127.0.0.1',  # truncated/invalid JSON
    '{"type": "offer", "sdp": {"nested": "object-not-a-string"}}',  # type confusion
    '{"type": "offer", "sdp": "' + ("A" * 2_000_000) + '"}',  # oversized field
    '{"type": "offer", "sdp": "v=0\\u0000\\u0001\\u0002malformed"}',  # embedded control chars
    '{"type": "offer"}',  # missing required "sdp" field
    '{"type": 12345, "sdp": null}',  # wrong type for "type"
    '{"type": "candidate", "candidate": "not-a-valid-ice-candidate-string;;;;"}',  # malformed ICE candidate
    "this is not json at all {{{",  # non-JSON raw text
    "",  # empty frame
    "[1, 2, 3]",  # array instead of an object
]


@dataclass
class WebSocketFuzzProbeConfig:
    scenario_id: str
    url: str  # ws:// or wss://
    asvs_controls: List[str] = field(default_factory=lambda: ["V17.3.2"])
    payloads: List[str] = field(default_factory=lambda: list(DEFAULT_SIGNALING_FUZZ_PAYLOADS))
    headers: Optional[Dict[str, str]] = None
    requires_active_mode: bool = True
    severity: str = "high"


async def _try_handshake(url: str, headers: Optional[Dict[str, str]], timeout: float):
    """Opens and immediately closes a WebSocket connection — a completed
    handshake is proof the listener is alive and accepting new connections.
    Returns True/False; never raises (the caller only cares whether the
    handshake itself succeeded, not the reason it didn't)."""
    import websockets

    try:
        extra_headers = list((headers or {}).items())
        async with await asyncio.wait_for(
            websockets.connect(url, additional_headers=extra_headers or None, max_size=None), timeout=timeout,
        ):
            return True
    except Exception:
        return False


async def run_websocket_fuzz_probe(
    config: WebSocketFuzzProbeConfig, *, active_mode: bool = False,
) -> DynamicFinding:
    import websockets

    control_id = config.asvs_controls[0] if config.asvs_controls else config.scenario_id

    if config.requires_active_mode and not active_mode:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION,
            rule_id=config.scenario_id, url=config.url, method="WEBSOCKET", severity=config.severity,
            note="This signaling fuzz probe sends real malformed traffic at a live server and "
                 "active_mode was not enabled for this scan",
            confidence=1.0,
        )

    if not config.payloads:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_CONFIGURED, rule_id=config.scenario_id,
            url=config.url, method="WEBSOCKET", severity=config.severity,
            note="No fuzz payloads were supplied (and the default corpus was explicitly cleared)",
            confidence=1.0,
        )

    baseline_ok = await _try_handshake(config.url, config.headers, CONNECT_TIMEOUT_SECONDS)
    if not baseline_ok:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=config.scenario_id,
            url=config.url, method="WEBSOCKET", severity=config.severity,
            note=f"Could not establish a baseline WebSocket handshake with {config.url} — "
                 f"nothing to fuzz against",
            confidence=0.2,
        )

    attempted = 0
    for payload in config.payloads:
        attempted += 1
        try:
            extra_headers = list((config.headers or {}).items())
            async with await asyncio.wait_for(
                websockets.connect(config.url, additional_headers=extra_headers or None, max_size=None),
                timeout=CONNECT_TIMEOUT_SECONDS,
            ) as ws:
                await ws.send(payload)
                # Deliberately not waiting on a response here — whatever (if
                # anything) the server sends back to THIS connection isn't
                # part of the verdict either way; only the fresh-handshake
                # liveness recheck below is. Waiting on a recv() the verdict
                # never uses would just add a stall for every payload a
                # server doesn't talk back on, which is the common case.
        except Exception as exc:
            logger.debug(f"Signaling fuzz payload #{attempted} raised while sending: {exc}")

        still_alive = await _try_handshake(config.url, config.headers, CONNECT_TIMEOUT_SECONDS)
        if not still_alive:
            return DynamicFinding(
                control_id=control_id, verdict=Verdict.FAIL, rule_id=config.scenario_id,
                url=config.url, method="WEBSOCKET", severity=config.severity,
                note=(
                    f"A fresh WebSocket handshake succeeded before this probe started but failed "
                    f"immediately after sending fuzz payload #{attempted} of {len(config.payloads)} "
                    f"— evidence the signaling server crashed, hung, or stopped accepting "
                    f"connections in response to malformed input. This proves the listener stopped "
                    f"responding, not that the payload itself was mishandled in some other way; "
                    f"re-run against a fresh instance to isolate exactly which payload caused it."
                ),
                confidence=0.6, evidence_type="response_diff",
                proof={"failing_payload_index": attempted - 1, "failing_payload": payload[:500]},
            )

    return DynamicFinding(
        control_id=control_id, verdict=Verdict.PASS, rule_id=config.scenario_id,
        url=config.url, method="WEBSOCKET", severity=config.severity,
        note=(
            f"The signaling server accepted a fresh WebSocket handshake after every one of "
            f"{len(config.payloads)} malformed payloads — this is a smoke test against a small, "
            f"representative corpus, not a full fuzzing campaign, and only proves the LISTENER "
            f"stayed up, not that each payload was correctly rejected rather than silently "
            f"mis-processed."
        ),
        confidence=0.4,
    )
