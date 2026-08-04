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

from app.domain.analysis.dast.checks import (
    _check_csrf_token_validation,
    _check_reflected_xss,
    _check_request_smuggling,
    _check_sql_injection,
    _check_unauthenticated_access,
    run_payload_checks,
)
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
            "CSRF_TOKEN_NOT_VALIDATED", "UNAUTHENTICATED_ACCESS_ALLOWED", "REFLECTED_XSS_LIVE",
            "SQL_INJECTION_LIVE",
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


class TestCsrfTokenValidation:
    @pytest.mark.asyncio
    async def test_missing_token_accepted_fails(self):
        rule = RULES["CSRF_TOKEN_NOT_VALIDATED"]
        html = (
            "<html><body><form method='POST' action='/transfer'>"
            "<input type='hidden' name='csrf_token' value='abc123'/>"
            "<input name='amount' value='10'/>"
            "</form></body></html>"
        )

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return httpx.Response(200, text=html, headers={"content-type": "text/html"})
            return httpx.Response(200, text="ok")  # POST accepted despite missing csrf_token

        async with _session(handler) as session:
            finding = await _check_csrf_token_validation(session, TARGET, rule)
        assert finding.verdict == Verdict.FAIL
        assert finding.control_id == "V3.5.1"

    @pytest.mark.asyncio
    async def test_missing_token_rejected_passes(self):
        rule = RULES["CSRF_TOKEN_NOT_VALIDATED"]
        html = (
            "<html><body><form method='POST' action='/transfer'>"
            "<input type='hidden' name='csrf_token' value='abc123'/>"
            "</form></body></html>"
        )

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return httpx.Response(200, text=html, headers={"content-type": "text/html"})
            return httpx.Response(403, text="forbidden")

        async with _session(handler) as session:
            finding = await _check_csrf_token_validation(session, TARGET, rule)
        assert finding.verdict == Verdict.PASS

    @pytest.mark.asyncio
    async def test_form_without_csrf_field_is_not_tested(self):
        rule = RULES["CSRF_TOKEN_NOT_VALIDATED"]
        html = "<html><body><form method='POST' action='/submit'><input name='amount' value='10'/></form></body></html>"

        async with _session(lambda r: httpx.Response(200, text=html, headers={"content-type": "text/html"})) as session:
            finding = await _check_csrf_token_validation(session, TARGET, rule)
        assert finding.verdict == Verdict.NOT_TESTED

    @pytest.mark.asyncio
    async def test_no_state_changing_form_is_not_tested(self):
        rule = RULES["CSRF_TOKEN_NOT_VALIDATED"]
        html = "<html><body><form method='GET' action='/search'><input name='q'/></form></body></html>"

        async with _session(lambda r: httpx.Response(200, text=html, headers={"content-type": "text/html"})) as session:
            finding = await _check_csrf_token_validation(session, TARGET, rule)
        assert finding.verdict == Verdict.NOT_TESTED

    @pytest.mark.asyncio
    async def test_skipped_by_default_without_active_mode(self):
        async with _session(lambda r: httpx.Response(404)) as session:
            findings = await run_payload_checks(session, TARGET, rules=RULES)
        finding = next(f for f in findings if f.rule_id == "CSRF_TOKEN_NOT_VALIDATED")
        assert finding.verdict == Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION


class TestUnauthenticatedAccess:
    @pytest.mark.asyncio
    async def test_requires_authenticated_session(self):
        rule = RULES["UNAUTHENTICATED_ACCESS_ALLOWED"]
        async with _session(lambda r: httpx.Response(200)) as session:  # AuthMode.NONE
            finding = await _check_unauthenticated_access(session, TARGET, rule)
        assert finding.verdict == Verdict.NOT_CONFIGURED

    @pytest.mark.asyncio
    async def test_enforced_endpoint_passes(self):
        rule = RULES["UNAUTHENTICATED_ACCESS_ALLOWED"]

        def handler(request: httpx.Request) -> httpx.Response:
            if request.headers.get("authorization"):
                return httpx.Response(200)
            return httpx.Response(401)

        session = DastSession(
            ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="tok"),
            resolve=False, transport=httpx.MockTransport(handler),
        )
        async with session:
            finding = await _check_unauthenticated_access(session, TARGET, rule)
        assert finding.verdict == Verdict.PASS

    @pytest.mark.asyncio
    async def test_unenforced_endpoint_fails(self):
        rule = RULES["UNAUTHENTICATED_ACCESS_ALLOWED"]

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200)  # 200 regardless of auth

        session = DastSession(
            ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="tok"),
            resolve=False, transport=httpx.MockTransport(handler),
        )
        async with session:
            finding = await _check_unauthenticated_access(session, TARGET, rule)
        assert finding.verdict == Verdict.FAIL
        assert finding.control_id == "V8.2.1"

    @pytest.mark.asyncio
    async def test_authenticated_baseline_failure_is_not_tested(self):
        rule = RULES["UNAUTHENTICATED_ACCESS_ALLOWED"]

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        session = DastSession(
            ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="tok"),
            resolve=False, transport=httpx.MockTransport(handler),
        )
        async with session:
            finding = await _check_unauthenticated_access(session, TARGET, rule)
        assert finding.verdict == Verdict.NOT_TESTED

    @pytest.mark.asyncio
    async def test_not_gated_behind_active_mode(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200)

        session = DastSession(
            ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="tok"),
            resolve=False, transport=httpx.MockTransport(handler),
        )
        async with session:
            findings = await run_payload_checks(session, TARGET, rules=RULES)  # active_mode defaults False
        finding = next(f for f in findings if f.rule_id == "UNAUTHENTICATED_ACCESS_ALLOWED")
        assert finding.verdict != Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION


class TestReflectedXss:
    @pytest.mark.asyncio
    async def test_no_query_params_is_not_tested(self):
        rule = RULES["REFLECTED_XSS_LIVE"]
        async with _session(lambda r: httpx.Response(200, text="<html></html>")) as session:
            finding = await _check_reflected_xss(session, TARGET, rule)
        assert finding.verdict == Verdict.NOT_TESTED

    @pytest.mark.asyncio
    async def test_unescaped_reflection_fails(self):
        rule = RULES["REFLECTED_XSS_LIVE"]

        def handler(request: httpx.Request) -> httpx.Response:
            q = request.url.params.get("q", "")
            return httpx.Response(200, text=f"<html><body>Results for: {q}</body></html>")

        async with _session(handler) as session:
            finding = await _check_reflected_xss(session, f"{TARGET}/search?q=hello", rule)
        assert finding.verdict == Verdict.FAIL
        assert finding.control_id == "V1.2.1"
        assert "'q'" in finding.note

    @pytest.mark.asyncio
    async def test_escaped_reflection_passes(self):
        rule = RULES["REFLECTED_XSS_LIVE"]

        def handler(request: httpx.Request) -> httpx.Response:
            q = request.url.params.get("q", "")
            escaped = q.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            return httpx.Response(200, text=f"<html><body>Results for: {escaped}</body></html>")

        async with _session(handler) as session:
            finding = await _check_reflected_xss(session, f"{TARGET}/search?q=hello", rule)
        assert finding.verdict == Verdict.PASS

    @pytest.mark.asyncio
    async def test_unreachable_param_is_not_tested(self):
        rule = RULES["REFLECTED_XSS_LIVE"]

        async with _session(lambda r: httpx.Response(404)) as session:
            finding = await _check_reflected_xss(session, f"{TARGET}/search?q=hello", rule)
        assert finding.verdict == Verdict.NOT_TESTED

    @pytest.mark.asyncio
    async def test_multiple_params_only_flags_the_reflecting_one(self):
        rule = RULES["REFLECTED_XSS_LIVE"]

        def handler(request: httpx.Request) -> httpx.Response:
            q = request.url.params.get("q", "")
            other = request.url.params.get("page", "")
            # 'page' never reflects, only 'q' does.
            return httpx.Response(200, text=f"<html><body>q={q} page-safe={other!r}</body></html>")

        async with _session(handler) as session:
            finding = await _check_reflected_xss(session, f"{TARGET}/search?q=hello&page=1", rule)
        assert finding.verdict == Verdict.FAIL

    @pytest.mark.asyncio
    async def test_not_gated_behind_active_mode(self):
        async with _session(lambda r: httpx.Response(200, text="<html></html>")) as session:
            findings = await run_payload_checks(session, f"{TARGET}/search?q=hello", rules=RULES)
        finding = next(f for f in findings if f.rule_id == "REFLECTED_XSS_LIVE")
        assert finding.verdict != Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION


class TestSqlInjection:
    @pytest.mark.asyncio
    async def test_no_query_params_is_not_tested(self):
        rule = RULES["SQL_INJECTION_LIVE"]
        async with _session(lambda r: httpx.Response(200)) as session:
            finding = await _check_sql_injection(session, TARGET, rule)
        assert finding.verdict == Verdict.NOT_TESTED

    @pytest.mark.asyncio
    async def test_leaked_sql_error_fails(self):
        rule = RULES["SQL_INJECTION_LIVE"]

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.params.get("id", "").endswith("'1'='1"):
                return httpx.Response(500, text="You have an error in your SQL syntax near '''")
            return httpx.Response(200, text="no results")

        async with _session(handler) as session:
            finding = await _check_sql_injection(session, f"{TARGET}/items?id=1", rule)
        assert finding.verdict == Verdict.FAIL
        assert finding.control_id == "V1.2.4"
        assert "error" in finding.note.lower()

    @pytest.mark.asyncio
    async def test_boolean_response_length_diff_fails(self):
        rule = RULES["SQL_INJECTION_LIVE"]

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.params.get("id", "").endswith("'1'='1"):
                return httpx.Response(200, text="row " * 200)  # always-true: many rows
            return httpx.Response(200, text="no rows found")  # always-false: none

        async with _session(handler) as session:
            finding = await _check_sql_injection(session, f"{TARGET}/items?id=1", rule)
        assert finding.verdict == Verdict.FAIL
        assert "boolean" in finding.note.lower()

    @pytest.mark.asyncio
    async def test_identical_responses_pass(self):
        rule = RULES["SQL_INJECTION_LIVE"]

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="item not found")

        async with _session(handler) as session:
            finding = await _check_sql_injection(session, f"{TARGET}/items?id=1", rule)
        assert finding.verdict == Verdict.PASS

    @pytest.mark.asyncio
    async def test_both_404_is_not_tested(self):
        rule = RULES["SQL_INJECTION_LIVE"]

        async with _session(lambda r: httpx.Response(404)) as session:
            finding = await _check_sql_injection(session, f"{TARGET}/items?id=1", rule)
        assert finding.verdict == Verdict.NOT_TESTED

    @pytest.mark.asyncio
    async def test_skipped_by_default_without_active_mode(self):
        async with _session(lambda r: httpx.Response(200)) as session:
            findings = await run_payload_checks(session, f"{TARGET}/items?id=1", rules=RULES)
        finding = next(f for f in findings if f.rule_id == "SQL_INJECTION_LIVE")
        assert finding.verdict == Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION

    @pytest.mark.asyncio
    async def test_runs_when_active_mode_enabled(self):
        async with _session(lambda r: httpx.Response(200, text="same body")) as session:
            findings = await run_payload_checks(
                session, f"{TARGET}/items?id=1", rules=RULES, active_mode=True,
            )
        finding = next(f for f in findings if f.rule_id == "SQL_INJECTION_LIVE")
        assert finding.verdict != Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION
