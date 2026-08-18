"""Phase 2A payload checks — DOUBLE_DECODE_BYPASS, CRLF_HEADER_REFLECTION,
OPEN_REDIRECT_LIVE. All against httpx.MockTransport, no real network calls.

REQUEST_SMUGGLING is the exception — it needs to send deliberately
ambiguous Content-Length/Transfer-Encoding headers that httpx (correctly)
won't construct, so it bypasses httpx via raw sockets. Its tests patch the
raw-socket helper directly, same pattern test_dynamic_probe.py uses for
dynamic_probe.py's raw TLS socket calls.
"""
import re
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from app.domain.analysis.dast.checks import (
    _check_command_injection,
    _check_cors_misconfiguration,
    _check_csrf_token_validation,
    _check_nosql_injection,
    _check_reflected_xss,
    _check_request_smuggling,
    _check_sql_injection,
    _check_ssti,
    _check_unauthenticated_access,
    _check_websocket_token_not_derived_from_session,
    _check_websocket_token_requires_auth,
    _check_xxe,
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


class _FakeCollaborator:
    """Same fake used by test_dast_ssrf_probe.py — hands out predictable
    tokens ("token-1", "token-2", ...) in call order, so a test can
    precompute which attempt a given token belongs to and simulate a hit
    for exactly that one."""

    def __init__(self, hit_token: str = None):
        self._hit_token = hit_token
        self._counter = 0

    def new_token(self) -> str:
        self._counter += 1
        return f"token-{self._counter}"

    def callback_url(self, token: str) -> str:
        return f"http://collab.example/{token}"

    def hits_for(self, token: str):
        return [type("Hit", (), {"remote_addr": "10.0.0.5", "method": "GET", "path": f"/{token}"})()] \
            if token == self._hit_token else []


async def _run_one(rule_id: str, handler):
    async with _session(handler) as session:
        findings = await run_payload_checks(session, TARGET, rules=RULES)
    return next(f for f in findings if f.rule_id == rule_id)


class TestDoubleDecodeBypass:
    @pytest.mark.asyncio
    async def test_double_encoded_bypass_with_real_disclosure_fails(self):
        # Genuine evidence: the "bypassed" response body actually contains
        # /etc/passwd content (root's entry always has uid/gid 0:0) —
        # confident FAIL.
        def handler(request: httpx.Request) -> httpx.Response:
            if "%252e" in str(request.url):
                return httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin")
            return httpx.Response(403, text="blocked")

        finding = await _run_one("DOUBLE_DECODE_BYPASS", handler)
        assert finding.verdict == Verdict.FAIL
        assert finding.control_id == "V1.1.1"

    @pytest.mark.asyncio
    async def test_double_encoded_bypass_without_disclosure_is_inconclusive(self):
        # Regression — a status-code gap alone (single blocked, double not)
        # used to be enough for a confident FAIL even when the "bypassed"
        # response is just a generic page with no file content, e.g. an
        # SPA's catch-all route (nginx `try_files $uri /index.html`)
        # returning the same 200+index.html for any unmatched path.
        # Confirmed false positive against a real target (2026-08-15
        # marketplace scan). No /etc/passwd content in the body -> the
        # discrepancy is a real anomaly worth noting, but not proof of
        # actual traversal, so INCONCLUSIVE rather than FAIL.
        def handler(request: httpx.Request) -> httpx.Response:
            if "%252e" in str(request.url):
                return httpx.Response(200, text="<!doctype html><html>generic SPA shell</html>")
            return httpx.Response(403, text="blocked")

        finding = await _run_one("DOUBLE_DECODE_BYPASS", handler)
        assert finding.verdict == Verdict.INCONCLUSIVE
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
            "SQL_INJECTION_LIVE", "COMMAND_INJECTION_LIVE", "SSTI_LIVE", "XXE_LIVE",
            "NOSQL_INJECTION_LIVE", "CORS_MISCONFIG_LIVE",
            "WEBSOCKET_TOKEN_UNAUTH_ISSUANCE", "WEBSOCKET_TOKEN_DERIVED_FROM_SESSION",
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

    @pytest.mark.asyncio
    @pytest.mark.parametrize("path", [
        "/auth/login", "/login", "/auth/register", "/register", "/signup",
        "/forgot-password", "/reset-password",
    ])
    async def test_public_by_definition_paths_skipped(self, path):
        # Regression — login/register/password-recovery entry points MUST
        # be reachable without an existing session by definition (you can't
        # log in if the login page itself requires you to already be
        # logged in). Confirmed false positive against a real target
        # (2026-08-15 marketplace scan: GET /auth/login, /auth/register on
        # the frontend's SPA both flagged FAIL).
        rule = RULES["UNAUTHENTICATED_ACCESS_ALLOWED"]

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200)  # 200 regardless of auth

        session = DastSession(
            ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="tok"),
            resolve=False, transport=httpx.MockTransport(handler),
        )
        async with session:
            finding = await _check_unauthenticated_access(session, f"{TARGET}{path}", rule)
        assert finding.verdict == Verdict.NOT_TESTED
        assert "login/registration/password-recovery" in finding.note

    @pytest.mark.asyncio
    @pytest.mark.parametrize("path", ["/auth/logout", "/auth/me", "/profile", "/orders/123"])
    async def test_other_auth_paths_not_skipped(self, path):
        # Deliberately narrow — /logout, /me, and ordinary resource paths
        # can legitimately require authentication (this app's own logout
        # route does), so the skip list must not swallow those too.
        rule = RULES["UNAUTHENTICATED_ACCESS_ALLOWED"]

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200)  # 200 regardless of auth

        session = DastSession(
            ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="tok"),
            resolve=False, transport=httpx.MockTransport(handler),
        )
        async with session:
            finding = await _check_unauthenticated_access(session, f"{TARGET}{path}", rule)
        assert finding.verdict == Verdict.FAIL


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


class TestCommandInjection:
    @pytest.mark.asyncio
    async def test_no_query_params_is_not_tested(self):
        rule = RULES["COMMAND_INJECTION_LIVE"]
        async with _session(lambda r: httpx.Response(200)) as session:
            finding = await _check_command_injection(session, TARGET, rule)
        assert finding.verdict == Verdict.NOT_TESTED

    @pytest.mark.asyncio
    async def test_both_404_is_not_tested(self):
        rule = RULES["COMMAND_INJECTION_LIVE"]
        async with _session(lambda r: httpx.Response(404)) as session:
            finding = await _check_command_injection(session, f"{TARGET}/ping?host=1", rule)
        assert finding.verdict == Verdict.NOT_TESTED

    @pytest.mark.asyncio
    async def test_no_timing_signal_passes(self):
        rule = RULES["COMMAND_INJECTION_LIVE"]
        async with _session(lambda r: httpx.Response(200, text="pong")) as session:
            finding = await _check_command_injection(session, f"{TARGET}/ping?host=1", rule)
        assert finding.verdict == Verdict.PASS

    @pytest.mark.asyncio
    async def test_timing_confirmed_without_collaborator_fails(self):
        rule = RULES["COMMAND_INJECTION_LIVE"]
        with patch(
            "app.domain.analysis.dast.checks.timing_oracle",
            new=AsyncMock(return_value=(True, {"delta_ms": 5000.0})),
        ):
            async with _session(lambda r: httpx.Response(200)) as session:
                finding = await _check_command_injection(session, f"{TARGET}/ping?host=1", rule)
        assert finding.verdict == Verdict.FAIL
        assert finding.evidence_type == "time_delay"

    @pytest.mark.asyncio
    async def test_timing_confirmed_with_collaborator_hit_is_confirmed(self):
        rule = RULES["COMMAND_INJECTION_LIVE"]
        collab = _FakeCollaborator(hit_token="token-1")
        with patch(
            "app.domain.analysis.dast.checks.timing_oracle",
            new=AsyncMock(return_value=(True, {"delta_ms": 5000.0})),
        ), patch("app.domain.analysis.dast.checks.asyncio.sleep", new=AsyncMock()):
            async with _session(lambda r: httpx.Response(200)) as session:
                finding = await _check_command_injection(session, f"{TARGET}/ping?host=1", rule, collaborator=collab)
        assert finding.verdict == Verdict.CONFIRMED
        assert finding.evidence_type == "oob_callback"
        assert finding.reproduction is not None

    @pytest.mark.asyncio
    async def test_timing_confirmed_with_collaborator_no_hit_stays_fail(self):
        rule = RULES["COMMAND_INJECTION_LIVE"]
        collab = _FakeCollaborator(hit_token=None)
        with patch(
            "app.domain.analysis.dast.checks.timing_oracle",
            new=AsyncMock(return_value=(True, {"delta_ms": 5000.0})),
        ), patch("app.domain.analysis.dast.checks.asyncio.sleep", new=AsyncMock()):
            async with _session(lambda r: httpx.Response(200)) as session:
                finding = await _check_command_injection(session, f"{TARGET}/ping?host=1", rule, collaborator=collab)
        assert finding.verdict == Verdict.FAIL
        assert finding.evidence_type == "time_delay"

    @pytest.mark.asyncio
    async def test_skipped_by_default_without_active_mode(self):
        async with _session(lambda r: httpx.Response(200)) as session:
            findings = await run_payload_checks(session, f"{TARGET}/ping?host=1", rules=RULES)
        finding = next(f for f in findings if f.rule_id == "COMMAND_INJECTION_LIVE")
        assert finding.verdict == Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION

    @pytest.mark.asyncio
    async def test_runs_when_active_mode_enabled(self):
        async with _session(lambda r: httpx.Response(200)) as session:
            findings = await run_payload_checks(session, f"{TARGET}/ping?host=1", rules=RULES, active_mode=True)
        finding = next(f for f in findings if f.rule_id == "COMMAND_INJECTION_LIVE")
        assert finding.verdict != Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION


class TestSsti:
    @pytest.mark.asyncio
    async def test_no_query_params_is_not_tested(self):
        rule = RULES["SSTI_LIVE"]
        async with _session(lambda r: httpx.Response(200)) as session:
            finding = await _check_ssti(session, TARGET, rule)
        assert finding.verdict == Verdict.NOT_TESTED

    @pytest.mark.asyncio
    async def test_arithmetic_not_evaluated_passes(self):
        rule = RULES["SSTI_LIVE"]

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="<html>no injection here</html>")

        async with _session(handler) as session:
            finding = await _check_ssti(session, f"{TARGET}/greet?name=world", rule)
        assert finding.verdict == Verdict.PASS

    @pytest.mark.asyncio
    async def test_arithmetic_evaluated_without_collaborator_fails(self):
        rule = RULES["SSTI_LIVE"]

        def handler(request: httpx.Request) -> httpx.Response:
            name = request.url.params.get("name", "")
            match = re.search(r"\{\{(\d+)\*(\d+)\}\}", name)
            if match:
                product = int(match.group(1)) * int(match.group(2))
                return httpx.Response(200, text=f"<html>Hello {product}</html>")
            return httpx.Response(200, text=f"<html>Hello {name}</html>")

        async with _session(handler) as session:
            finding = await _check_ssti(session, f"{TARGET}/greet?name=world", rule)
        assert finding.verdict == Verdict.FAIL
        assert finding.evidence_type == "response_diff"

    @pytest.mark.asyncio
    async def test_arithmetic_evaluated_with_collaborator_gadget_hit_is_confirmed(self):
        rule = RULES["SSTI_LIVE"]
        # The arithmetic-evaluation request is a plain GET too — the fake
        # collaborator's counter advances once per gadget attempt
        # regardless, so the first gadget (jinja2) gets "token-1".
        collab = _FakeCollaborator(hit_token="token-1")

        def handler(request: httpx.Request) -> httpx.Response:
            name = request.url.params.get("name", "")
            match = re.search(r"\{\{(\d+)\*(\d+)\}\}", name)
            if match:
                product = int(match.group(1)) * int(match.group(2))
                return httpx.Response(200, text=f"<html>Hello {product}</html>")
            return httpx.Response(200, text="<html>ok</html>")

        with patch("app.domain.analysis.dast.checks.asyncio.sleep", new=AsyncMock()):
            async with _session(handler) as session:
                finding = await _check_ssti(session, f"{TARGET}/greet?name=world", rule, collaborator=collab)
        assert finding.verdict == Verdict.CONFIRMED
        assert finding.evidence_type == "oob_callback"
        assert finding.reproduction is not None

    @pytest.mark.asyncio
    async def test_skipped_by_default_without_active_mode(self):
        async with _session(lambda r: httpx.Response(200)) as session:
            findings = await run_payload_checks(session, f"{TARGET}/greet?name=world", rules=RULES)
        finding = next(f for f in findings if f.rule_id == "SSTI_LIVE")
        assert finding.verdict == Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION

    @pytest.mark.asyncio
    async def test_runs_when_active_mode_enabled(self):
        async with _session(lambda r: httpx.Response(200)) as session:
            findings = await run_payload_checks(
                session, f"{TARGET}/greet?name=world", rules=RULES, active_mode=True,
            )
        finding = next(f for f in findings if f.rule_id == "SSTI_LIVE")
        assert finding.verdict != Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION


class TestXxe:
    @pytest.mark.asyncio
    async def test_without_collaborator_not_tested(self):
        rule = RULES["XXE_LIVE"]
        async with _session(lambda r: httpx.Response(200)) as session:
            finding = await _check_xxe(session, f"{TARGET}/upload", rule)
        assert finding.verdict == Verdict.NOT_TESTED

    @pytest.mark.asyncio
    async def test_404_is_not_tested(self):
        rule = RULES["XXE_LIVE"]
        collab = _FakeCollaborator()
        async with _session(lambda r: httpx.Response(404)) as session:
            finding = await _check_xxe(session, f"{TARGET}/upload", rule, collaborator=collab)
        assert finding.verdict == Verdict.NOT_TESTED

    @pytest.mark.asyncio
    async def test_collaborator_hit_confirms(self):
        rule = RULES["XXE_LIVE"]
        collab = _FakeCollaborator(hit_token="token-1")
        with patch("app.domain.analysis.dast.checks.asyncio.sleep", new=AsyncMock()):
            async with _session(lambda r: httpx.Response(200)) as session:
                finding = await _check_xxe(session, f"{TARGET}/upload", rule, collaborator=collab)
        assert finding.verdict == Verdict.CONFIRMED
        assert finding.evidence_type == "oob_callback"
        assert finding.reproduction is not None

    @pytest.mark.asyncio
    async def test_no_hit_passes(self):
        rule = RULES["XXE_LIVE"]
        collab = _FakeCollaborator(hit_token=None)
        with patch("app.domain.analysis.dast.checks.asyncio.sleep", new=AsyncMock()):
            async with _session(lambda r: httpx.Response(200)) as session:
                finding = await _check_xxe(session, f"{TARGET}/upload", rule, collaborator=collab)
        assert finding.verdict == Verdict.PASS

    @pytest.mark.asyncio
    async def test_skipped_by_default_without_active_mode(self):
        collab = _FakeCollaborator()
        async with _session(lambda r: httpx.Response(200)) as session:
            findings = await run_payload_checks(session, f"{TARGET}/upload", rules=RULES, collaborator=collab)
        finding = next(f for f in findings if f.rule_id == "XXE_LIVE")
        assert finding.verdict == Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION

    @pytest.mark.asyncio
    async def test_runs_when_active_mode_enabled(self):
        collab = _FakeCollaborator()
        with patch("app.domain.analysis.dast.checks.asyncio.sleep", new=AsyncMock()):
            async with _session(lambda r: httpx.Response(200)) as session:
                findings = await run_payload_checks(
                    session, f"{TARGET}/upload", rules=RULES, active_mode=True, collaborator=collab,
                )
        finding = next(f for f in findings if f.rule_id == "XXE_LIVE")
        assert finding.verdict != Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION


class TestNosqlInjection:
    @pytest.mark.asyncio
    async def test_no_query_params_is_not_tested(self):
        rule = RULES["NOSQL_INJECTION_LIVE"]
        async with _session(lambda r: httpx.Response(200)) as session:
            finding = await _check_nosql_injection(session, TARGET, rule)
        assert finding.verdict == Verdict.NOT_TESTED

    @pytest.mark.asyncio
    async def test_both_404_is_not_tested(self):
        rule = RULES["NOSQL_INJECTION_LIVE"]
        async with _session(lambda r: httpx.Response(404)) as session:
            finding = await _check_nosql_injection(session, f"{TARGET}/login?username=alice", rule)
        assert finding.verdict == Verdict.NOT_TESTED

    @pytest.mark.asyncio
    async def test_operator_bypass_produces_different_response_fails(self):
        rule = RULES["NOSQL_INJECTION_LIVE"]

        def handler(request: httpx.Request) -> httpx.Response:
            if "username%5B%24ne%5D" in str(request.url) or "username[$ne]" in str(request.url):
                return httpx.Response(200, text="user " * 200)  # operator bypass: matches everyone
            return httpx.Response(200, text="no such user")  # literal control value: no match

        async with _session(handler) as session:
            finding = await _check_nosql_injection(session, f"{TARGET}/login?username=alice", rule)
        assert finding.verdict == Verdict.FAIL
        assert finding.evidence_type == "response_diff"

    @pytest.mark.asyncio
    async def test_identical_responses_pass(self):
        rule = RULES["NOSQL_INJECTION_LIVE"]

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="no such user")

        async with _session(handler) as session:
            finding = await _check_nosql_injection(session, f"{TARGET}/login?username=alice", rule)
        assert finding.verdict == Verdict.PASS

    @pytest.mark.asyncio
    async def test_skipped_by_default_without_active_mode(self):
        async with _session(lambda r: httpx.Response(200)) as session:
            findings = await run_payload_checks(session, f"{TARGET}/login?username=alice", rules=RULES)
        finding = next(f for f in findings if f.rule_id == "NOSQL_INJECTION_LIVE")
        assert finding.verdict == Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION

    @pytest.mark.asyncio
    async def test_runs_when_active_mode_enabled(self):
        async with _session(lambda r: httpx.Response(200, text="same")) as session:
            findings = await run_payload_checks(
                session, f"{TARGET}/login?username=alice", rules=RULES, active_mode=True,
            )
        finding = next(f for f in findings if f.rule_id == "NOSQL_INJECTION_LIVE")
        assert finding.verdict != Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION


class TestCorsMisconfiguration:
    @pytest.mark.asyncio
    async def test_reflects_origin_with_credentials_fails(self):
        rule = RULES["CORS_MISCONFIG_LIVE"]

        def handler(request: httpx.Request) -> httpx.Response:
            origin = request.headers.get("origin", "")
            return httpx.Response(200, headers={
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            })

        async with _session(handler) as session:
            finding = await _check_cors_misconfiguration(session, f"{TARGET}/api/data", rule)
        assert finding.verdict == Verdict.FAIL
        assert finding.confidence >= 0.8

    @pytest.mark.asyncio
    async def test_reflects_origin_without_credentials_fails_lower_confidence(self):
        rule = RULES["CORS_MISCONFIG_LIVE"]

        def handler(request: httpx.Request) -> httpx.Response:
            origin = request.headers.get("origin", "")
            return httpx.Response(200, headers={"Access-Control-Allow-Origin": origin})

        async with _session(handler) as session:
            finding = await _check_cors_misconfiguration(session, f"{TARGET}/api/data", rule)
        assert finding.verdict == Verdict.FAIL
        assert finding.confidence < 0.8

    @pytest.mark.asyncio
    async def test_wildcard_with_credentials_fails(self):
        rule = RULES["CORS_MISCONFIG_LIVE"]

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            })

        async with _session(handler) as session:
            finding = await _check_cors_misconfiguration(session, f"{TARGET}/api/data", rule)
        assert finding.verdict == Verdict.FAIL

    @pytest.mark.asyncio
    async def test_no_reflection_passes(self):
        rule = RULES["CORS_MISCONFIG_LIVE"]

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={"Access-Control-Allow-Origin": "https://trusted.example"})

        async with _session(handler) as session:
            finding = await _check_cors_misconfiguration(session, f"{TARGET}/api/data", rule)
        assert finding.verdict == Verdict.PASS

    @pytest.mark.asyncio
    async def test_no_cors_headers_at_all_passes(self):
        rule = RULES["CORS_MISCONFIG_LIVE"]
        async with _session(lambda r: httpx.Response(200)) as session:
            finding = await _check_cors_misconfiguration(session, f"{TARGET}/api/data", rule)
        assert finding.verdict == Verdict.PASS

    @pytest.mark.asyncio
    async def test_404_is_not_tested(self):
        rule = RULES["CORS_MISCONFIG_LIVE"]
        async with _session(lambda r: httpx.Response(404)) as session:
            finding = await _check_cors_misconfiguration(session, f"{TARGET}/api/data", rule)
        assert finding.verdict == Verdict.NOT_TESTED

    @pytest.mark.asyncio
    async def test_not_gated_behind_active_mode(self):
        def handler(request: httpx.Request) -> httpx.Response:
            origin = request.headers.get("origin", "")
            return httpx.Response(200, headers={"Access-Control-Allow-Origin": origin})

        async with _session(handler) as session:
            findings = await run_payload_checks(session, f"{TARGET}/api/data", rules=RULES)
        finding = next(f for f in findings if f.rule_id == "CORS_MISCONFIG_LIVE")
        assert finding.verdict != Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION


class TestRequestPacing:
    @pytest.mark.asyncio
    async def test_default_no_delay_between_checks(self):
        two_rules = {"OPEN_REDIRECT_LIVE": RULES["OPEN_REDIRECT_LIVE"], "REFLECTED_XSS_LIVE": RULES["REFLECTED_XSS_LIVE"]}
        with patch("app.domain.analysis.dast.checks.asyncio.sleep", new=AsyncMock()) as sleep_mock:
            async with _session(lambda r: httpx.Response(200)) as session:
                await run_payload_checks(session, f"{TARGET}/x?q=1", rules=two_rules)
        sleep_mock.assert_not_called()

    @pytest.mark.asyncio
    async def test_request_delay_paces_every_check_after_the_first(self):
        two_rules = {"OPEN_REDIRECT_LIVE": RULES["OPEN_REDIRECT_LIVE"], "REFLECTED_XSS_LIVE": RULES["REFLECTED_XSS_LIVE"]}
        with patch("app.domain.analysis.dast.checks.asyncio.sleep", new=AsyncMock()) as sleep_mock:
            async with _session(lambda r: httpx.Response(200)) as session:
                await run_payload_checks(session, f"{TARGET}/x?q=1", rules=two_rules, request_delay=0.15)
        sleep_mock.assert_called_once_with(0.15)

    @pytest.mark.asyncio
    async def test_skipped_checks_are_not_paced_or_counted_as_the_first(self):
        # REQUEST_SMUGGLING requires active_mode -> skipped, no request made.
        # OPEN_REDIRECT_LIVE runs -> the actual first (and only) real request,
        # so it should NOT be preceded by a delay.
        two_rules = {"REQUEST_SMUGGLING": RULES["REQUEST_SMUGGLING"], "OPEN_REDIRECT_LIVE": RULES["OPEN_REDIRECT_LIVE"]}
        with patch("app.domain.analysis.dast.checks.asyncio.sleep", new=AsyncMock()) as sleep_mock:
            async with _session(lambda r: httpx.Response(200)) as session:
                await run_payload_checks(session, f"{TARGET}/x?q=1", rules=two_rules, request_delay=0.15)
        sleep_mock.assert_not_called()


WS_TOKEN_URL = f"{TARGET}/ws/token"


class TestWebsocketTokenRequiresAuth:
    @pytest.mark.asyncio
    async def test_url_shape_not_matched_is_not_tested(self):
        rule = RULES["WEBSOCKET_TOKEN_UNAUTH_ISSUANCE"]
        session = DastSession(
            ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="tok"),
            resolve=False, transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"token": "x"})),
        )
        async with session:
            finding = await _check_websocket_token_requires_auth(session, f"{TARGET}/orders/123", rule)
        assert finding.verdict == Verdict.NOT_TESTED

    @pytest.mark.asyncio
    async def test_no_authenticated_session_is_not_configured(self):
        rule = RULES["WEBSOCKET_TOKEN_UNAUTH_ISSUANCE"]
        async with _session(lambda r: httpx.Response(200, json={"token": "x"})) as session:  # AuthMode.NONE
            finding = await _check_websocket_token_requires_auth(session, WS_TOKEN_URL, rule)
        assert finding.verdict == Verdict.NOT_CONFIGURED

    @pytest.mark.asyncio
    async def test_authenticated_response_not_token_shaped_is_not_tested(self):
        rule = RULES["WEBSOCKET_TOKEN_UNAUTH_ISSUANCE"]
        session = DastSession(
            ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="tok"),
            resolve=False, transport=httpx.MockTransport(lambda r: httpx.Response(200, text="not json")),
        )
        async with session:
            finding = await _check_websocket_token_requires_auth(session, WS_TOKEN_URL, rule)
        assert finding.verdict == Verdict.NOT_TESTED

    @pytest.mark.asyncio
    async def test_token_issued_without_auth_fails(self):
        rule = RULES["WEBSOCKET_TOKEN_UNAUTH_ISSUANCE"]

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"ticket": "same-for-everyone"})  # 200 regardless of auth

        session = DastSession(
            ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="tok"),
            resolve=False, transport=httpx.MockTransport(handler),
        )
        async with session:
            finding = await _check_websocket_token_requires_auth(session, WS_TOKEN_URL, rule)
        assert finding.verdict == Verdict.FAIL
        assert finding.control_id == "V4.4.4"

    @pytest.mark.asyncio
    async def test_token_only_issued_with_auth_passes(self):
        rule = RULES["WEBSOCKET_TOKEN_UNAUTH_ISSUANCE"]

        def handler(request: httpx.Request) -> httpx.Response:
            if request.headers.get("authorization"):
                return httpx.Response(200, json={"ticket": "abc123"})
            return httpx.Response(401)

        session = DastSession(
            ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="tok"),
            resolve=False, transport=httpx.MockTransport(handler),
        )
        async with session:
            finding = await _check_websocket_token_requires_auth(session, WS_TOKEN_URL, rule)
        assert finding.verdict == Verdict.PASS

    @pytest.mark.asyncio
    async def test_not_gated_behind_active_mode(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"ticket": "abc123"})

        session = DastSession(
            ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="tok"),
            resolve=False, transport=httpx.MockTransport(handler),
        )
        async with session:
            findings = await run_payload_checks(session, WS_TOKEN_URL, rules=RULES)
        finding = next(f for f in findings if f.rule_id == "WEBSOCKET_TOKEN_UNAUTH_ISSUANCE")
        assert finding.verdict != Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION


class TestWebsocketTokenNotDerivedFromSession:
    @pytest.mark.asyncio
    async def test_url_shape_not_matched_is_not_tested(self):
        rule = RULES["WEBSOCKET_TOKEN_DERIVED_FROM_SESSION"]
        session = DastSession(
            ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="tok"),
            resolve=False, transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"token": "tok"})),
        )
        async with session:
            finding = await _check_websocket_token_not_derived_from_session(session, f"{TARGET}/orders/123", rule)
        assert finding.verdict == Verdict.NOT_TESTED

    @pytest.mark.asyncio
    async def test_no_authenticated_session_is_not_configured(self):
        rule = RULES["WEBSOCKET_TOKEN_DERIVED_FROM_SESSION"]
        async with _session(lambda r: httpx.Response(200, json={"token": "x"})) as session:  # AuthMode.NONE
            finding = await _check_websocket_token_not_derived_from_session(session, WS_TOKEN_URL, rule)
        assert finding.verdict == Verdict.NOT_CONFIGURED

    @pytest.mark.asyncio
    async def test_ws_token_identical_to_bearer_token_fails(self):
        rule = RULES["WEBSOCKET_TOKEN_DERIVED_FROM_SESSION"]
        session = DastSession(
            ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="tok"),
            resolve=False,
            transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"wsToken": "tok"})),
        )
        async with session:
            finding = await _check_websocket_token_not_derived_from_session(session, WS_TOKEN_URL, rule)
        assert finding.verdict == Verdict.FAIL
        assert finding.control_id == "V4.4.3"

    @pytest.mark.asyncio
    async def test_ws_token_distinct_from_bearer_token_passes(self):
        rule = RULES["WEBSOCKET_TOKEN_DERIVED_FROM_SESSION"]
        session = DastSession(
            ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="tok"),
            resolve=False,
            transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"wsToken": "a-totally-different-value"})),
        )
        async with session:
            finding = await _check_websocket_token_not_derived_from_session(session, WS_TOKEN_URL, rule)
        assert finding.verdict == Verdict.PASS

    @pytest.mark.asyncio
    async def test_no_token_field_in_response_is_not_tested(self):
        rule = RULES["WEBSOCKET_TOKEN_DERIVED_FROM_SESSION"]
        session = DastSession(
            ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="tok"),
            resolve=False, transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"status": "ok"})),
        )
        async with session:
            finding = await _check_websocket_token_not_derived_from_session(session, WS_TOKEN_URL, rule)
        assert finding.verdict == Verdict.NOT_TESTED

    @pytest.mark.asyncio
    async def test_not_gated_behind_active_mode(self):
        session = DastSession(
            ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="tok"),
            resolve=False,
            transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"wsToken": "different"})),
        )
        async with session:
            findings = await run_payload_checks(session, WS_TOKEN_URL, rules=RULES)
        finding = next(f for f in findings if f.rule_id == "WEBSOCKET_TOKEN_DERIVED_FROM_SESSION")
        assert finding.verdict != Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION
