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
