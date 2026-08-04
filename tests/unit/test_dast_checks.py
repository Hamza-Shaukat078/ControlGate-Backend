"""Phase 2A payload checks — DOUBLE_DECODE_BYPASS, CRLF_HEADER_REFLECTION,
OPEN_REDIRECT_LIVE. All against httpx.MockTransport, no real network calls.

REQUEST_SMUGGLING is the exception — it needs to send deliberately
ambiguous Content-Length/Transfer-Encoding headers that httpx (correctly)
won't construct, so it bypasses httpx via raw sockets. Its tests patch the
raw-socket helper directly, same pattern test_dynamic_probe.py uses for
dynamic_probe.py's raw TLS socket calls.
"""
from unittest.mock import patch

import httpx
import pytest

from app.domain.analysis.dast.checks import _check_request_smuggling, run_payload_checks
from app.domain.analysis.dast.config import ActorConfig, AuthMode
from app.domain.analysis.dast.rule_loader import load_dynamic_queries
from app.domain.analysis.dast.session import DastSession
from app.domain.analysis.dast.verdict import Verdict

RULES = load_dynamic_queries()
TARGET = "https://target.example"


def _session(handler) -> DastSession:
    return DastSession(ActorConfig(auth_mode=AuthMode.NONE), resolve=False, transport=httpx.MockTransport(handler))


async def _run_one(rule_id: str, handler):
    async with _session(handler) as session:
        findings = await run_payload_checks(session, TARGET, rules=RULES)
    return next(f for f in findings if f.rule_id == rule_id)


class TestDoubleDecodeBypass:
    @pytest.mark.asyncio
    async def test_double_encoded_bypasses_block_fails(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if "%252e" in str(request.url):
                return httpx.Response(200, text="bypassed")
            return httpx.Response(403, text="blocked")

        finding = await _run_one("DOUBLE_DECODE_BYPASS", handler)
        assert finding.verdict == Verdict.FAIL
        assert finding.control_id == "V1.1.1"

    @pytest.mark.asyncio
    async def test_both_blocked_consistently_passes(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(403, text="blocked")

        finding = await _run_one("DOUBLE_DECODE_BYPASS", handler)
        assert finding.verdict == Verdict.PASS

    @pytest.mark.asyncio
    async def test_both_404_is_not_tested(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        finding = await _run_one("DOUBLE_DECODE_BYPASS", handler)
        assert finding.verdict == Verdict.NOT_TESTED

    @pytest.mark.asyncio
    async def test_ambiguous_result_is_inconclusive(self):
        # Neither status is in the "blocked" family, so this isn't the
        # single-blocked/double-bypassed FAIL pattern — just two different,
        # inconclusive non-blocked statuses.
        def handler(request: httpx.Request) -> httpx.Response:
            if "%252e" in str(request.url):
                return httpx.Response(500)
            return httpx.Response(200)

        finding = await _run_one("DOUBLE_DECODE_BYPASS", handler)
        assert finding.verdict == Verdict.INCONCLUSIVE


class TestCrlfHeaderReflection:
    @pytest.mark.asyncio
    async def test_reflected_marker_fails(self):
        def handler(request: httpx.Request) -> httpx.Response:
            next_param = request.url.params.get("next")
            marker_prefix = "X-Dast-Probe:"
            if next_param and marker_prefix in next_param:
                marker = next_param[next_param.index(marker_prefix) + len(marker_prefix):].strip()
                return httpx.Response(200, headers={"X-Dast-Probe": marker})
            return httpx.Response(404)

        finding = await _run_one("CRLF_HEADER_REFLECTION", handler)
        assert finding.verdict == Verdict.FAIL
        assert finding.control_id == "V4.2.4"

    @pytest.mark.asyncio
    async def test_param_recognized_but_not_reflected_passes(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.params.get("next") is not None:
                return httpx.Response(200, text="ok")
            return httpx.Response(404)

        finding = await _run_one("CRLF_HEADER_REFLECTION", handler)
        assert finding.verdict == Verdict.PASS

    @pytest.mark.asyncio
    async def test_no_param_recognized_is_not_tested(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        finding = await _run_one("CRLF_HEADER_REFLECTION", handler)
        assert finding.verdict == Verdict.NOT_TESTED


class TestOpenRedirectLive:
    @pytest.mark.asyncio
    async def test_param_driven_redirect_to_canary_fails(self):
        def handler(request: httpx.Request) -> httpx.Response:
            next_param = request.url.params.get("next")
            if next_param and "dast-redirect-canary.invalid" in next_param:
                return httpx.Response(302, headers={"location": next_param})
            if request.headers.get("host") == "dast-redirect-canary.invalid":
                return httpx.Response(200)
            return httpx.Response(404)

        finding = await _run_one("OPEN_REDIRECT_LIVE", handler)
        assert finding.verdict == Verdict.FAIL
        assert finding.control_id == "V3.7.2"

    @pytest.mark.asyncio
    async def test_forged_host_header_redirect_fails(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.headers.get("host") == "dast-redirect-canary.invalid":
                return httpx.Response(302, headers={"location": "https://dast-redirect-canary.invalid/"})
            return httpx.Response(404)

        finding = await _run_one("OPEN_REDIRECT_LIVE", handler)
        assert finding.verdict == Verdict.FAIL
        assert "Host header" in finding.note

    @pytest.mark.asyncio
    async def test_no_redirect_passes(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.params.get("next") is not None:
                return httpx.Response(200)
            return httpx.Response(404)

        finding = await _run_one("OPEN_REDIRECT_LIVE", handler)
        assert finding.verdict == Verdict.PASS

    @pytest.mark.asyncio
    async def test_no_recognized_param_is_not_tested(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        finding = await _run_one("OPEN_REDIRECT_LIVE", handler)
        assert finding.verdict == Verdict.NOT_TESTED


class TestRunPayloadChecksOrchestration:
    @pytest.mark.asyncio
    async def test_all_rules_produce_a_finding(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        async with _session(handler) as session:
            findings = await run_payload_checks(session, TARGET, rules=RULES)
        assert {f.rule_id for f in findings} == {
            "DOUBLE_DECODE_BYPASS", "CRLF_HEADER_REFLECTION", "OPEN_REDIRECT_LIVE", "REQUEST_SMUGGLING",
        }

    @pytest.mark.asyncio
    async def test_request_smuggling_is_skipped_by_default(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        async with _session(handler) as session:
            findings = await run_payload_checks(session, TARGET, rules=RULES)
        smuggling_finding = next(f for f in findings if f.rule_id == "REQUEST_SMUGGLING")
        assert smuggling_finding.verdict == Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION
        assert smuggling_finding.control_id == "V4.2.2"

    @pytest.mark.asyncio
    async def test_request_smuggling_runs_when_active_mode_enabled(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        with patch(
            "app.domain.analysis.dast.checks._send_raw_smuggling_probe",
            return_value="HTTP/1.1 200 OK\r\n\r\nok",
        ):
            async with _session(handler) as session:
                findings = await run_payload_checks(session, TARGET, rules=RULES, active_mode=True)
        smuggling_finding = next(f for f in findings if f.rule_id == "REQUEST_SMUGGLING")
        assert smuggling_finding.verdict == Verdict.PASS


class TestRequestSmuggling:
    @pytest.mark.asyncio
    async def test_marker_leak_is_flagged_fail(self):
        rule = RULES["REQUEST_SMUGGLING"]

        def fake_send(host, port, is_https, payload):
            # Simulate a server/proxy pair that mishandles the ambiguous
            # framing and echoes the smuggled second request back.
            return payload.decode()

        with patch("app.domain.analysis.dast.checks._send_raw_smuggling_probe", side_effect=fake_send):
            async with _session(lambda r: httpx.Response(404)) as session:
                finding = await _check_request_smuggling(session, TARGET, rule)

        assert finding.verdict == Verdict.FAIL
        assert finding.control_id == "V4.2.2"

    @pytest.mark.asyncio
    async def test_no_marker_leak_is_pass(self):
        rule = RULES["REQUEST_SMUGGLING"]

        with patch(
            "app.domain.analysis.dast.checks._send_raw_smuggling_probe",
            return_value="HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        ):
            async with _session(lambda r: httpx.Response(404)) as session:
                finding = await _check_request_smuggling(session, TARGET, rule)

        assert finding.verdict == Verdict.PASS

    @pytest.mark.asyncio
    async def test_connection_failure_is_not_tested(self):
        rule = RULES["REQUEST_SMUGGLING"]

        with patch(
            "app.domain.analysis.dast.checks._send_raw_smuggling_probe",
            side_effect=ConnectionRefusedError("boom"),
        ):
            async with _session(lambda r: httpx.Response(404)) as session:
                finding = await _check_request_smuggling(session, TARGET, rule)

        assert finding.verdict == Verdict.NOT_TESTED
