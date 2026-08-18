"""WebSocket signaling fuzz probe (V17.3.2) — against a REAL local
websockets.serve() server rather than a mock, since the signal this probe
looks for (does a fresh handshake still complete) is a property of the
actual WebSocket protocol handshake, not something httpx.MockTransport-style
request/response mocking can stand in for.
"""
import asyncio

import pytest
import websockets

from app.domain.analysis.dast.verdict import Verdict
from app.domain.analysis.dast.websocket_fuzz_probe import (
    WebSocketFuzzProbeConfig,
    run_websocket_fuzz_probe,
)


async def _serve(handler):
    server = await websockets.serve(handler, "localhost", 0)
    port = server.sockets[0].getsockname()[1]
    return server, f"ws://localhost:{port}"


class TestGating:
    @pytest.mark.asyncio
    async def test_skipped_without_active_mode_by_default(self):
        config = WebSocketFuzzProbeConfig(scenario_id="SIGNALING_FUZZ", url="ws://localhost:1/x")
        finding = await run_websocket_fuzz_probe(config)  # active_mode defaults False
        assert finding.verdict == Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION
        assert finding.control_id == "V17.3.2"

    @pytest.mark.asyncio
    async def test_empty_payload_list_is_not_configured(self):
        config = WebSocketFuzzProbeConfig(scenario_id="SIGNALING_FUZZ", url="ws://localhost:1/x", payloads=[])
        finding = await run_websocket_fuzz_probe(config, active_mode=True)
        assert finding.verdict == Verdict.NOT_CONFIGURED

    @pytest.mark.asyncio
    async def test_unreachable_target_is_not_tested(self):
        config = WebSocketFuzzProbeConfig(
            scenario_id="SIGNALING_FUZZ", url="ws://localhost:1/nothing-listens-here",
            payloads=["{}"],
        )
        finding = await run_websocket_fuzz_probe(config, active_mode=True)
        assert finding.verdict == Verdict.NOT_TESTED


class TestFuzzing:
    @pytest.mark.asyncio
    async def test_resilient_server_passes(self):
        async def handler(ws):
            async for _ in ws:
                pass  # accepts anything, never crashes

        server, url = await _serve(handler)
        try:
            config = WebSocketFuzzProbeConfig(
                scenario_id="SIGNALING_FUZZ", url=url,
                payloads=['{"type": "offer"}', "not json", ""],
            )
            finding = await run_websocket_fuzz_probe(config, active_mode=True)
        finally:
            server.close()
            await server.wait_closed()

        assert finding.verdict == Verdict.PASS
        assert finding.control_id == "V17.3.2"

    @pytest.mark.asyncio
    async def test_server_that_stops_listening_after_a_payload_fails(self):
        # Simulates a crash: the handler closes the listening server itself
        # the moment it sees the trigger payload, so every connection
        # attempt after that point fails — exactly the signal this probe
        # is built to catch.
        trigger = "CRASH_ME"
        state = {"server": None}

        async def handler(ws):
            async for msg in ws:
                if msg == trigger:
                    state["server"].close()

        server, url = await _serve(handler)
        state["server"] = server
        try:
            config = WebSocketFuzzProbeConfig(
                scenario_id="SIGNALING_FUZZ", url=url,
                payloads=["harmless-first", trigger, "never-reached"],
            )
            finding = await run_websocket_fuzz_probe(config, active_mode=True)
        finally:
            server.close()
            await server.wait_closed()

        assert finding.verdict == Verdict.FAIL
        assert finding.proof["failing_payload_index"] == 1
        assert finding.proof["failing_payload"] == trigger

    @pytest.mark.asyncio
    async def test_default_corpus_is_used_when_none_supplied(self):
        seen = []

        async def handler(ws):
            try:
                async for msg in ws:
                    seen.append(msg)
            except Exception:
                pass  # the oversized-field payload trips this local test
                      # server's own default 1MB frame limit — realistic
                      # (plenty of real WS servers cap frame size too), and
                      # exactly what the probe's own try/except is there to
                      # tolerate; not a reason to fail this test.

        server, url = await _serve(handler)
        try:
            config = WebSocketFuzzProbeConfig(scenario_id="SIGNALING_FUZZ", url=url)
            finding = await run_websocket_fuzz_probe(config, active_mode=True)
        finally:
            server.close()
            await server.wait_closed()

        assert finding.verdict == Verdict.PASS
        assert len(config.payloads) > 5
        # The oversized-field payload legitimately never arrives intact (see
        # above); every other payload should still reach the handler.
        assert len(seen) >= len(config.payloads) - 1

    @pytest.mark.asyncio
    async def test_headers_are_sent_on_every_connection(self):
        seen_headers = []

        async def handler(ws):
            seen_headers.append(ws.request.headers.get("X-Test-Auth"))
            async for _ in ws:
                pass

        server, url = await _serve(handler)
        try:
            config = WebSocketFuzzProbeConfig(
                scenario_id="SIGNALING_FUZZ", url=url, payloads=["a", "b"],
                headers={"X-Test-Auth": "secret-token"},
            )
            await run_websocket_fuzz_probe(config, active_mode=True)
        finally:
            server.close()
            await server.wait_closed()

        # Baseline handshake + 2 payload connections + 2 liveness rechecks = 5.
        assert len(seen_headers) == 5
        assert all(h == "secret-token" for h in seen_headers)
