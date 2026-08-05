"""DAST auth harness (Phase 1) — DastSession/DastSessionPair.

Uses httpx.MockTransport so no real sockets are involved; validate_public_http_url's
DNS resolution is disabled via resolve=False for the same reason
tests/unit/test_ingestion_hardening.py does — these are fake hostnames.
"""
import httpx
import pytest

from app.domain.analysis.dast.config import (
    ActorConfig,
    AuthMode,
    DynamicScanConfig,
    FormLoginConfig,
)
from app.domain.analysis.dast.session import DastSession, DastSessionPair


def _echo_transport(username_seen: list, password_seen: list) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            body = request.content.decode()
            username_seen.append(body)
            resp = httpx.Response(200, headers={"set-cookie": "session=abc123; Path=/"})
            return resp
        auth = request.headers.get("authorization", "")
        return httpx.Response(200, json={"authorization_seen": auth, "cookie_seen": request.headers.get("cookie", "")})

    return httpx.MockTransport(handler)


class TestBearerAuth:
    @pytest.mark.asyncio
    async def test_bearer_token_attached_to_every_request(self):
        actor = ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="secret-token-xyz")
        transport = _echo_transport([], [])
        async with DastSession(actor, resolve=False, transport=transport) as session:
            resp = await session.request("GET", "https://target.example/api/whoami")
        assert resp.json()["authorization_seen"] == "Bearer secret-token-xyz"

    @pytest.mark.asyncio
    async def test_bearer_mode_without_token_raises(self):
        actor = ActorConfig(auth_mode=AuthMode.BEARER, bearer_token=None)
        with pytest.raises(ValueError):
            async with DastSession(actor, resolve=False, transport=_echo_transport([], [])):
                pass


class TestFormLogin:
    @pytest.mark.asyncio
    async def test_login_posts_credentials_and_reuses_cookie(self):
        seen: list = []
        form = FormLoginConfig(
            login_url="https://target.example/login",
            username_field="user",
            password_field="pass",
            username="alice",
            password="hunter2",
        )
        actor = ActorConfig(auth_mode=AuthMode.FORM_LOGIN, form_login=form)
        transport = _echo_transport(seen, [])
        async with DastSession(actor, resolve=False, transport=transport) as session:
            assert "user=alice" in seen[0] and "pass=hunter2" in seen[0]
            resp = await session.request("GET", "https://target.example/api/whoami")
        assert resp.json()["cookie_seen"] == "session=abc123"

    @pytest.mark.asyncio
    async def test_form_login_mode_without_config_raises(self):
        actor = ActorConfig(auth_mode=AuthMode.FORM_LOGIN, form_login=None)
        with pytest.raises(ValueError):
            async with DastSession(actor, resolve=False, transport=_echo_transport([], [])):
                pass


class TestNoneAuth:
    @pytest.mark.asyncio
    async def test_no_auth_mode_sends_plain_request(self):
        actor = ActorConfig(auth_mode=AuthMode.NONE)
        transport = _echo_transport([], [])
        async with DastSession(actor, resolve=False, transport=transport) as session:
            resp = await session.request("GET", "https://target.example/api/whoami")
        assert resp.json()["authorization_seen"] == ""


class TestSsrfGuard:
    @pytest.mark.asyncio
    async def test_request_to_private_host_is_rejected(self):
        actor = ActorConfig(auth_mode=AuthMode.NONE)
        async with DastSession(actor, resolve=False, transport=_echo_transport([], [])) as session:
            with pytest.raises(ValueError):
                await session.request("GET", "http://127.0.0.1:8000/admin")

    @pytest.mark.asyncio
    async def test_request_to_localhost_is_rejected(self):
        actor = ActorConfig(auth_mode=AuthMode.NONE)
        async with DastSession(actor, resolve=False, transport=_echo_transport([], [])) as session:
            with pytest.raises(ValueError):
                await session.request("GET", "https://localhost/internal")


class TestRedaction:
    @pytest.mark.asyncio
    async def test_bearer_token_redacted_from_log_line(self):
        actor = ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="secret-token-xyz")
        async with DastSession(actor, resolve=False, transport=_echo_transport([], [])) as session:
            log_line = f"Authorization: Bearer secret-token-xyz"
            assert "secret-token-xyz" not in session.redact(log_line)

    @pytest.mark.asyncio
    async def test_password_redacted_from_log_line(self):
        form = FormLoginConfig(
            login_url="https://target.example/login",
            username_field="user",
            password_field="pass",
            username="alice",
            password="hunter2",
        )
        actor = ActorConfig(auth_mode=AuthMode.FORM_LOGIN, form_login=form)
        async with DastSession(actor, resolve=False, transport=_echo_transport([], [])) as session:
            assert "hunter2" not in session.redact("POST body: user=alice&pass=hunter2")

    @pytest.mark.asyncio
    async def test_session_cookie_redacted_after_login(self):
        form = FormLoginConfig(
            login_url="https://target.example/login",
            username_field="user",
            password_field="pass",
            username="alice",
            password="hunter2",
        )
        actor = ActorConfig(auth_mode=AuthMode.FORM_LOGIN, form_login=form)
        async with DastSession(actor, resolve=False, transport=_echo_transport([], [])) as session:
            assert "abc123" not in session.redact("Cookie: session=abc123")


class TestSessionRefresh:
    """Track C4 — a form_login session that gets a 401 mid-scan re-logs-in
    and retries the original request exactly once."""

    @staticmethod
    def _expiring_session_transport(*, expire_after: int, login_calls: list) -> httpx.MockTransport:
        state = {"login_count": 0, "current_session": None, "successes_this_session": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/login":
                state["login_count"] += 1
                login_calls.append(state["login_count"])
                state["current_session"] = f"session-{state['login_count']}"
                state["successes_this_session"] = 0
                return httpx.Response(200, headers={"set-cookie": f"session={state['current_session']}; Path=/"})

            cookie = request.headers.get("cookie", "")
            if state["current_session"] and state["current_session"] in cookie:
                if state["successes_this_session"] >= expire_after:
                    return httpx.Response(401, json={"error": "expired"})
                state["successes_this_session"] += 1
                return httpx.Response(200, json={"ok": True})
            return httpx.Response(401, json={"error": "unauthorized"})

        return httpx.MockTransport(handler)

    def _form(self) -> FormLoginConfig:
        return FormLoginConfig(
            login_url="https://target.example/login",
            username_field="user", password_field="pass",
            username="alice", password="hunter2",
        )

    @pytest.mark.asyncio
    async def test_expired_session_triggers_reauth_and_retry_succeeds(self):
        login_calls: list = []
        transport = self._expiring_session_transport(expire_after=1, login_calls=login_calls)
        actor = ActorConfig(auth_mode=AuthMode.FORM_LOGIN, form_login=self._form())
        async with DastSession(actor, resolve=False, transport=transport) as session:
            first = await session.request("GET", "https://target.example/api/data")
            second = await session.request("GET", "https://target.example/api/data")

        assert first.status_code == 200
        assert second.status_code == 200  # would be 401 without the C4 re-auth/retry
        assert login_calls == [1, 2]  # initial login at __aenter__, one re-login on the 401

    @pytest.mark.asyncio
    async def test_bearer_mode_never_reauths_on_401(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"error": "unauthorized"})

        actor = ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="tok")
        async with DastSession(actor, resolve=False, transport=httpx.MockTransport(handler)) as session:
            resp = await session.request("GET", "https://target.example/api/data")
        assert resp.status_code == 401  # returned as-is, no login_url to even retry against

    @pytest.mark.asyncio
    async def test_reauth_failure_propagates(self):
        actor = ActorConfig(auth_mode=AuthMode.FORM_LOGIN, form_login=self._form())
        # __aenter__'s own initial login must succeed for the session to exist at all;
        # the re-auth attempt triggered by the 401 below is the one that fails.
        login_attempts = {"count": 0}

        def two_stage_handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/login":
                login_attempts["count"] += 1
                if login_attempts["count"] == 1:
                    return httpx.Response(200, headers={"set-cookie": "session=abc; Path=/"})
                return httpx.Response(500)
            return httpx.Response(401)

        async with DastSession(actor, resolve=False, transport=httpx.MockTransport(two_stage_handler)) as session:
            with pytest.raises(httpx.HTTPStatusError):
                await session.request("GET", "https://target.example/api/data")
        assert login_attempts["count"] == 2  # initial + one failed re-auth attempt, no more

    @pytest.mark.asyncio
    async def test_retry_only_attempted_once_even_if_it_also_401s(self):
        login_calls: list = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/login":
                login_calls.append(1)
                return httpx.Response(200, headers={"set-cookie": "session=abc; Path=/"})
            return httpx.Response(401)  # every protected request 401s, even after re-login

        actor = ActorConfig(auth_mode=AuthMode.FORM_LOGIN, form_login=self._form())
        async with DastSession(actor, resolve=False, transport=httpx.MockTransport(handler)) as session:
            resp = await session.request("GET", "https://target.example/api/data")

        assert resp.status_code == 401  # final response returned, not swallowed
        assert len(login_calls) == 2  # initial __aenter__ login + exactly one re-auth, no loop


class TestSessionPair:
    @pytest.mark.asyncio
    async def test_second_actor_holds_independent_session(self):
        transport = _echo_transport([], [])
        config = DynamicScanConfig(
            target_url="https://target.example",
            actor=ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="token-a"),
            second_actor=ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="token-b"),
        )
        async with DastSessionPair(config, resolve=False, transport=transport) as pair:
            resp_a = await pair.primary.request("GET", "https://target.example/whoami")
            resp_b = await pair.secondary.request("GET", "https://target.example/whoami")
        assert resp_a.json()["authorization_seen"] == "Bearer token-a"
        assert resp_b.json()["authorization_seen"] == "Bearer token-b"

    @pytest.mark.asyncio
    async def test_no_second_actor_leaves_secondary_none(self):
        config = DynamicScanConfig(target_url="https://target.example")
        async with DastSessionPair(config, resolve=False, transport=_echo_transport([], [])) as pair:
            assert pair.secondary is None
