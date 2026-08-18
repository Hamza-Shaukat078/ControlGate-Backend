"""Real DTLS/SRTP peer-connection probes (V17.2.3/V17.2.4/V17.2.5/V17.2.7) —
the aiortc-dependent tier of this session's WebRTC work, one step past
websocket_fuzz_probe.py's signaling-layer fuzzing into the actual media
transport.

Signaling: every target app's offer/answer exchange is custom — this
scanner has no generic way to "just connect" to an arbitrary WebRTC
service. Two supported shapes, both on WebRtcConnectionConfig:
  - signaling_url set: a WHIP-style exchange (POST the offer SDP as
    `Content-Type: application/sdp`, the response body is the answer SDP)
    — a real, standardized shape a growing number of ingest/SFU endpoints
    speak natively, not a guess.
  - remote_answer_sdp set instead: the tester already completed the
    offer/answer exchange out-of-band (a browser, their own tooling) and
    hands the resulting answer straight to this probe. Covers every other
    signaling shape at the cost of the tester doing that part by hand.
Exactly one of the two must be set.

Every verdict here degrades honestly rather than guessing: a peer
connection that never reaches "connected" is NOT_TESTED, not a false PASS
or FAIL — same posture as every other probe in this engine.
"""
import asyncio
import fractions
import logging
import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.domain.analysis.dast.findings import DynamicFinding
from app.domain.analysis.dast.verdict import Verdict

logger = logging.getLogger(__name__)

ICE_CONNECT_TIMEOUT_SECONDS = 15.0
SIGNALING_HTTP_TIMEOUT_SECONDS = 15.0


@dataclass
class WebRtcConnectionConfig:
    signaling_url: Optional[str] = None
    signaling_headers: Optional[Dict[str, str]] = None
    remote_answer_sdp: Optional[str] = None
    ice_servers: List[str] = field(default_factory=list)  # stun:/turn: URIs


class _SilentAudioTrack:
    """A minimal synthetic audio track (8kHz mono silence) — real media
    flowing on the wire, not a data channel standing in for one. Built
    on-demand (see _make_silent_audio_track) so importing this module
    doesn't require `av` to already be importable at import time in
    contexts that never actually run a probe (e.g. schema validation)."""


def _make_silent_audio_track():
    import av
    from aiortc.mediastreams import MediaStreamTrack

    class SilentAudioTrack(MediaStreamTrack):
        kind = "audio"

        def __init__(self):
            super().__init__()
            self._pts = 0
            self._sample_rate = 8000
            self._samples_per_frame = 160

        async def recv(self):
            frame = av.AudioFrame(format="s16", layout="mono", samples=self._samples_per_frame)
            for plane in frame.planes:
                plane.update(bytes(plane.buffer_size))
            frame.sample_rate = self._sample_rate
            frame.pts = self._pts
            frame.time_base = fractions.Fraction(1, self._sample_rate)
            self._pts += self._samples_per_frame
            await asyncio.sleep(self._samples_per_frame / self._sample_rate)
            return frame

    return SilentAudioTrack()


def _build_ice_configuration(ice_server_uris: List[str]):
    from aiortc import RTCConfiguration, RTCIceServer

    if not ice_server_uris:
        return None
    return RTCConfiguration(iceServers=[RTCIceServer(urls=uri) for uri in ice_server_uris])


async def _fetch_whip_answer(signaling_url: str, offer_sdp: str, headers: Optional[Dict[str, str]]) -> str:
    import httpx

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            signaling_url, content=offer_sdp,
            headers={"Content-Type": "application/sdp", **(headers or {})},
            timeout=SIGNALING_HTTP_TIMEOUT_SECONDS,
        )
        resp.raise_for_status()
        return resp.text


async def establish_connection(config: WebRtcConnectionConfig):
    """Negotiates and returns a connected RTCPeerConnection, or None if it
    never reached "connected" within ICE_CONNECT_TIMEOUT_SECONDS. Adds one
    audio transceiver (send + a slot to receive) — enough for every probe
    in this module; callers that need to actually send media replace the
    sender's track themselves.
    """
    from aiortc import RTCPeerConnection, RTCSessionDescription

    if not config.signaling_url and not config.remote_answer_sdp:
        logger.warning("WebRtcConnectionConfig needs either signaling_url or remote_answer_sdp")
        return None

    pc = RTCPeerConnection(configuration=_build_ice_configuration(config.ice_servers))
    pc.addTransceiver("audio", direction="sendrecv")

    offer = await pc.createOffer()
    await pc.setLocalDescription(offer)

    try:
        if config.signaling_url:
            answer_sdp = await _fetch_whip_answer(
                config.signaling_url, pc.localDescription.sdp, config.signaling_headers,
            )
        else:
            answer_sdp = config.remote_answer_sdp
        await pc.setRemoteDescription(RTCSessionDescription(sdp=answer_sdp, type="answer"))
    except Exception as exc:
        logger.warning(f"WebRTC signaling failed: {exc}")
        await pc.close()
        return None

    for _ in range(int(ICE_CONNECT_TIMEOUT_SECONDS * 10)):
        if pc.connectionState == "connected":
            return pc
        if pc.connectionState in ("failed", "closed"):
            await pc.close()
            return None
        await asyncio.sleep(0.1)

    await pc.close()
    return None


def _not_configured(control_id: str, scenario_id: str, severity: str, note: str) -> DynamicFinding:
    return DynamicFinding(
        control_id=control_id, verdict=Verdict.NOT_CONFIGURED, rule_id=scenario_id,
        url="", method="WEBRTC", severity=severity, note=note, confidence=1.0,
    )


def _not_tested(control_id: str, scenario_id: str, severity: str, note: str, confidence: float = 0.2) -> DynamicFinding:
    return DynamicFinding(
        control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=scenario_id,
        url="", method="WEBRTC", severity=severity, note=note, confidence=confidence,
    )


async def _outbound_packets_sent(pc) -> Optional[int]:
    stats = await pc.getStats()
    for s in stats.values():
        if getattr(s, "type", None) == "outbound-rtp":
            return s.packetsSent
    return None


async def _inbound_stat_for_ssrc(pc, ssrc: int):
    stats = await pc.getStats()
    for s in stats.values():
        if getattr(s, "type", None) == "inbound-rtp" and getattr(s, "ssrc", None) == ssrc:
            return s
    return None


# ── V17.2.5 / V17.2.7 — legitimate-media-flood resilience ───────────────────
# The two controls are, from this scanner's vantage point, the SAME test:
# hold N other real, legitimate WebRTC sessions open and confirm ONE
# control session's media keeps flowing throughout. The only difference is
# which control_id the scenario is tagged with — V17.2.5 for a general
# media server, V17.2.7 if the tester points it at a recording-enabled
# session specifically (this scanner can't tell "this session is being
# recorded" from the outside; that's the tester's context to supply, same
# as everywhere else in this session's work).

@dataclass
class MediaFloodProbeConfig:
    scenario_id: str
    control_connection: WebRtcConnectionConfig
    flood_connections: List[WebRtcConnectionConfig]
    asvs_controls: List[str] = field(default_factory=lambda: ["V17.2.5"])
    hold_seconds: float = 5.0
    requires_active_mode: bool = True
    severity: str = "high"


async def run_media_flood_probe(
    config: MediaFloodProbeConfig, *, active_mode: bool = False,
) -> DynamicFinding:
    control_id = config.asvs_controls[0] if config.asvs_controls else config.scenario_id

    if config.requires_active_mode and not active_mode:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION,
            rule_id=config.scenario_id, url="", method="WEBRTC", severity=config.severity,
            note="This probe holds real concurrent media sessions open against a live server "
                 "and active_mode was not enabled for this scan",
            confidence=1.0,
        )
    if not config.flood_connections:
        return _not_configured(
            control_id, config.scenario_id, config.severity,
            "No flood_connections were supplied — nothing to hold concurrently with the control session.",
        )

    control_pc = await establish_connection(config.control_connection)
    if control_pc is None:
        return _not_tested(
            control_id, config.scenario_id, config.severity,
            "Could not establish the control WebRTC connection — nothing to check for degradation.",
        )

    flood_pcs: List[Any] = []
    try:
        control_pc.getSenders()[0].replaceTrack(_make_silent_audio_track())
        await asyncio.sleep(config.hold_seconds / 2)
        packets_before = await _outbound_packets_sent(control_pc)

        established = await asyncio.gather(
            *(establish_connection(c) for c in config.flood_connections), return_exceptions=True,
        )
        flood_pcs = [pc for pc in established if pc is not None and not isinstance(pc, Exception)]
        for pc in flood_pcs:
            pc.getSenders()[0].replaceTrack(_make_silent_audio_track())

        await asyncio.sleep(config.hold_seconds)

        still_connected = control_pc.connectionState == "connected"
        packets_after = await _outbound_packets_sent(control_pc)
        still_flowing = (
            packets_before is not None and packets_after is not None and packets_after > packets_before
        )

        proof = {
            "flood_connections_requested": len(config.flood_connections),
            "flood_connections_established": len(flood_pcs),
            "control_connection_state_after_flood": control_pc.connectionState,
            "control_packets_sent_before": packets_before,
            "control_packets_sent_after": packets_after,
        }

        if not still_connected or not still_flowing:
            return DynamicFinding(
                control_id=control_id, verdict=Verdict.FAIL, rule_id=config.scenario_id,
                url="", method="WEBRTC", severity=config.severity,
                note=(
                    f"The control media session degraded while {len(flood_pcs)} other legitimate "
                    f"sessions were held concurrently — connectionState is now "
                    f"'{control_pc.connectionState}' and its own outbound packet count "
                    f"{'stopped increasing' if not still_flowing else 'looked fine'}. Single test "
                    f"run at this specific concurrency level, not a full load-testing campaign."
                ),
                confidence=0.5, evidence_type="response_diff", proof=proof,
            )

        return DynamicFinding(
            control_id=control_id, verdict=Verdict.PASS, rule_id=config.scenario_id,
            url="", method="WEBRTC", severity=config.severity,
            note=(
                f"The control media session kept flowing normally with {len(flood_pcs)} other "
                f"legitimate sessions held concurrently for {config.hold_seconds}s — proves this "
                f"one concurrency level and duration, not resilience at real production scale."
            ),
            confidence=0.35, evidence_type="response_diff", proof=proof,
        )
    finally:
        await control_pc.close()
        for pc in flood_pcs:
            await pc.close()


# ── V17.2.4 — malformed-packet resilience ────────────────────────────────────
# Same connection-liveness oracle websocket_fuzz_probe.py uses for the
# signaling layer, one layer down: does the media transport's listener stay
# up after receiving garbage bytes on the same UDP association SRTP/DTLS/ICE
# already share (RFC 7983 demultiplexing) — proof the process didn't
# crash/hang, not proof each payload was correctly rejected vs. silently
# mishandled.

_DEFAULT_MALFORMED_RTP_PAYLOADS: List[bytes] = [
    b"",  # empty datagram
    b"\x00",  # single byte
    b"\xff" * 172,  # garbage, RTP-packet-sized
    b"\x80" + b"\x00" * 2,  # RTP version bits set, truncated immediately after
    b"\x00" * 172,  # version bits all zero (invalid RTP version)
    secrets.token_bytes(1200),  # oversized random garbage
]


@dataclass
class MalformedPacketProbeConfig:
    scenario_id: str
    connection: WebRtcConnectionConfig
    asvs_controls: List[str] = field(default_factory=lambda: ["V17.2.4"])
    payloads: List[bytes] = field(default_factory=lambda: list(_DEFAULT_MALFORMED_RTP_PAYLOADS))
    requires_active_mode: bool = True
    severity: str = "critical"


async def run_malformed_packet_probe(
    config: MalformedPacketProbeConfig, *, active_mode: bool = False,
) -> DynamicFinding:
    control_id = config.asvs_controls[0] if config.asvs_controls else config.scenario_id

    if config.requires_active_mode and not active_mode:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION,
            rule_id=config.scenario_id, url="", method="WEBRTC", severity=config.severity,
            note="This probe sends malformed traffic at a live media server and active_mode "
                 "was not enabled for this scan",
            confidence=1.0,
        )
    if not config.payloads:
        return _not_configured(
            control_id, config.scenario_id, config.severity,
            "No fuzz payloads were supplied (and the default corpus was explicitly cleared).",
        )

    pc = await establish_connection(config.connection)
    if pc is None:
        return _not_tested(
            control_id, config.scenario_id, config.severity,
            "Could not establish a baseline WebRTC connection — nothing to fuzz against.",
        )

    try:
        transport = pc.getSenders()[0].transport
        for index, payload in enumerate(config.payloads):
            try:
                await transport.transport._send(payload)
            except Exception as exc:
                logger.debug(f"Malformed RTP payload #{index} raised while sending: {exc}")
            await asyncio.sleep(0.3)
            if pc.connectionState in ("failed", "disconnected", "closed"):
                return DynamicFinding(
                    control_id=control_id, verdict=Verdict.FAIL, rule_id=config.scenario_id,
                    url="", method="WEBRTC", severity=config.severity,
                    note=(
                        f"The media connection was healthy before this probe started but reached "
                        f"'{pc.connectionState}' immediately after malformed payload #{index} of "
                        f"{len(config.payloads)} — evidence the media server's transport handling "
                        f"crashed or hung on malformed input."
                    ),
                    confidence=0.55, evidence_type="response_diff",
                    proof={"failing_payload_index": index, "failing_payload_hex": payload[:64].hex()},
                )

        return DynamicFinding(
            control_id=control_id, verdict=Verdict.PASS, rule_id=config.scenario_id,
            url="", method="WEBRTC", severity=config.severity,
            note=(
                f"The media connection stayed healthy through all {len(config.payloads)} malformed "
                f"payloads — a smoke test against a small, representative corpus, not a full "
                f"fuzzing campaign."
            ),
            confidence=0.4,
        )
    finally:
        await pc.close()


# ── V17.2.3 — SRTP authentication actually enforced ──────────────────────────
# Structurally different from the two probes above: needs TWO connections
# (attacker + observer) because this scanner has no way to see the target
# server's own internal "did I accept this packet" state — the only
# generically observable signal is whether a forged packet gets RELAYED to
# another participant, which only means anything against an SFU/mixer-style
# target that relays media between sessions. A baseline check (does a
# validly-authenticated forged packet get relayed at all) runs FIRST and
# gates the real test — without it, a "the corrupted packet wasn't relayed"
# result is meaningless noise indistinguishable from "this target doesn't
# relay unknown SSRCs regardless of auth validity".

@dataclass
class SrtpAuthEnforcementProbeConfig:
    scenario_id: str
    attacker_connection: WebRtcConnectionConfig
    observer_connection: WebRtcConnectionConfig
    asvs_controls: List[str] = field(default_factory=lambda: ["V17.2.3"])
    requires_active_mode: bool = True
    severity: str = "high"


async def run_srtp_auth_enforcement_probe(
    config: SrtpAuthEnforcementProbeConfig, *, active_mode: bool = False,
) -> DynamicFinding:
    from aiortc.rtp import RtpPacket

    control_id = config.asvs_controls[0] if config.asvs_controls else config.scenario_id

    if config.requires_active_mode and not active_mode:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION,
            rule_id=config.scenario_id, url="", method="WEBRTC", severity=config.severity,
            note="This probe forges SRTP packets against a live media server and active_mode "
                 "was not enabled for this scan",
            confidence=1.0,
        )

    attacker_pc = await establish_connection(config.attacker_connection)
    if attacker_pc is None:
        return _not_tested(
            control_id, config.scenario_id, config.severity,
            "Could not establish the attacker WebRTC connection.",
        )
    observer_pc = await establish_connection(config.observer_connection)
    if observer_pc is None:
        await attacker_pc.close()
        return _not_tested(
            control_id, config.scenario_id, config.severity,
            "Could not establish the observer WebRTC connection (a second participant needed to "
            "see whether a forged packet gets relayed).",
        )

    try:
        transport = attacker_pc.getSenders()[0].transport

        def _forge(ssrc: int, corrupt: bool) -> bytes:
            pkt = RtpPacket(
                payload_type=0, sequence_number=secrets.randbits(16), timestamp=secrets.randbits(32),
                ssrc=ssrc, payload=secrets.token_bytes(160),
            )
            protected = transport._tx_srtp.protect(pkt.serialize())
            if corrupt:
                return protected[:-1] + bytes([protected[-1] ^ 0xFF])
            return protected

        # Baseline: a VALIDLY-authenticated forged packet, on its own fresh
        # SSRC, must actually get relayed to the observer — otherwise a
        # clean result below proves nothing (see module note above).
        baseline_ssrc = secrets.randbits(32)
        await transport.transport._send(_forge(baseline_ssrc, corrupt=False))
        await asyncio.sleep(2.0)
        baseline_relayed = await _inbound_stat_for_ssrc(observer_pc, baseline_ssrc)
        if baseline_relayed is None:
            return _not_tested(
                control_id, config.scenario_id, config.severity,
                "A validly-authenticated forged packet was never observed by the second "
                "participant — this target either doesn't relay media between sessions (not an "
                "SFU/mixer this test applies to) or relayed it too slowly/differently for this "
                "probe to detect, so a corrupted-auth result wouldn't be meaningful either.",
                confidence=0.25,
            )

        # Real test: an INVALID-auth forged packet, on a DIFFERENT fresh
        # SSRC, should be rejected by the crypto layer before ever reaching
        # anything that could relay it.
        test_ssrc = secrets.randbits(32)
        await transport.transport._send(_forge(test_ssrc, corrupt=True))
        await asyncio.sleep(2.0)
        test_relayed = await _inbound_stat_for_ssrc(observer_pc, test_ssrc)

        if test_relayed is not None:
            return DynamicFinding(
                control_id=control_id, verdict=Verdict.FAIL, rule_id=config.scenario_id,
                url="", method="WEBRTC", severity=config.severity,
                note=(
                    "A forged SRTP packet with a deliberately corrupted authentication tag was "
                    "relayed to the second participant — the baseline confirmed this target does "
                    "relay unrelated forged-but-valid packets, so this specific packet reaching "
                    "the observer despite failing authentication is real evidence SRTP "
                    "authentication is not actually enforced."
                ),
                confidence=0.65, evidence_type="response_diff",
                proof={"baseline_ssrc": baseline_ssrc, "test_ssrc": test_ssrc},
            )

        return DynamicFinding(
            control_id=control_id, verdict=Verdict.PASS, rule_id=config.scenario_id,
            url="", method="WEBRTC", severity=config.severity,
            note=(
                "The baseline (validly-authenticated) forged packet was relayed to the second "
                "participant, but the corrupted-auth-tag one was not — consistent with SRTP "
                "authentication being enforced. Single test run against one relay path, not "
                "proof against every packet-processing code path this target has."
            ),
            confidence=0.45, evidence_type="response_diff",
            proof={"baseline_ssrc": baseline_ssrc, "test_ssrc": test_ssrc},
        )
    finally:
        await attacker_pc.close()
        await observer_pc.close()
