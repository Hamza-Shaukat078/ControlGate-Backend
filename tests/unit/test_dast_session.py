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
    OAuth2Config,
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

    @pytest.mark.asyncio
    async def test_json_only_login_endpoint_retried_as_json_after_415(self):
        """Bug fix — a JSON-only API login route (Flask's request.get_json()
        without force=True, e.g. vuln-bank-app's /api/auth/login) 415s the
        default x-www-form-urlencoded POST. Login must retry as a JSON body
        and succeed, instead of raise_for_status() blowing up the whole
        dynamic phase."""
        requests_seen: list = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/login":
                content_type = request.headers.get("content-type", "")
                requests_seen.append(content_type)
                if "application/json" not in content_type:
                    return httpx.Response(415)
                import json as _json

                body = _json.loads(request.content)
                assert body == {"user": "alice", "pass": "hunter2"}
                return httpx.Response(200, headers={"set-cookie": "session=abc123; Path=/"})
            return httpx.Response(200, json={"cookie_seen": request.headers.get("cookie", "")})

        form = FormLoginConfig(
            login_url="https://target.example/login",
            username_field="user",
            password_field="pass",
            username="alice",
            password="hunter2",
        )
        actor = ActorConfig(auth_mode=AuthMode.FORM_LOGIN, form_login=form)
        transport = httpx.MockTransport(handler)
        async with DastSession(actor, resolve=False, transport=transport) as session:
            resp = await session.request("GET", "https://target.example/api/whoami")
        assert len(requests_seen) == 2, "expected a form-encoded attempt, then a JSON retry"
        assert resp.json()["cookie_seen"] == "session=abc123"

    @pytest.mark.asyncio
    async def test_non_415_login_failure_not_retried_as_json(self):
        """A real credential failure (e.g. 401) must surface as-is, not get
        masked by a pointless JSON retry — only 415 means "wrong media
        type, try again"."""
        attempts: list = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/login":
                attempts.append(1)
                return httpx.Response(401)
            return httpx.Response(200)

        form = FormLoginConfig(
            login_url="https://target.example/login",
            username_field="user",
            password_field="pass",
            username="alice",
            password="wrong",
        )
        actor = ActorConfig(auth_mode=AuthMode.FORM_LOGIN, form_login=form)
        transport = httpx.MockTransport(handler)
        with pytest.raises(httpx.HTTPStatusError):
            async with DastSession(actor, resolve=False, transport=transport):
                pass
        assert len(attempts) == 1

    @pytest.mark.asyncio
    async def test_json_bearer_token_extracted_from_nested_login_response(self):
        """A JWT microservice API (no Set-Cookie at all — the marketplace
        auth-service shape this was built against) hands the access token
        back nested in the JSON body instead: {"data": {"user": {...},
        "accessToken": "..."}}. form_login must pick that up and apply it as
        a Bearer header, not just rely on the (empty) cookie jar."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/auth/login":
                return httpx.Response(
                    200,
                    json={"success": True, "data": {"user": {"email": "a@b.com"}, "accessToken": "tok-abc123"}},
                )
            return httpx.Response(200, json={"authorization_seen": request.headers.get("authorization", "")})

        form = FormLoginConfig(
            login_url="https://target.example/auth/login",
            username_field="email",
            password_field="password",
            username="a@b.com",
            password="hunter2",
        )
        actor = ActorConfig(auth_mode=AuthMode.FORM_LOGIN, form_login=form)
        transport = httpx.MockTransport(handler)
        async with DastSession(actor, resolve=False, transport=transport) as session:
            resp = await session.request("GET", "https://target.example/orders/1")
        assert resp.json()["authorization_seen"] == "Bearer tok-abc123"

    @pytest.mark.asyncio
    async def test_cookie_only_login_unaffected_by_json_token_check(self):
        """No matching key in the login response body → no Authorization
        header gets added — cookie-only targets keep working exactly as
        before this existed."""
        form = FormLoginConfig(
            login_url="https://target.example/login",
            username_field="user",
            password_field="pass",
            username="alice",
            password="hunter2",
        )
        actor = ActorConfig(auth_mode=AuthMode.FORM_LOGIN, form_login=form)
        transport = _echo_transport([], [])
        async with DastSession(actor, resolve=False, transport=transport) as session:
            resp = await session.request("GET", "https://target.example/api/whoami")
        assert resp.json()["authorization_seen"] == ""
        assert resp.json()["cookie_seen"] == "session=abc123"


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


class TestRedirectSsrfGuard:
    """A redirect hop is a second, attacker-influenced destination — the
    guard must re-validate it too, not just the URL the caller passed in."""

    @staticmethod
    def _redirect_transport(location: str) -> httpx.MockTransport:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/start":
                return httpx.Response(302, headers={"location": location})
            return httpx.Response(200, json={"ok": True, "path": request.url.path})

        return httpx.MockTransport(handler)

    @pytest.mark.asyncio
    async def test_redirect_to_private_ip_is_rejected(self):
        actor = ActorConfig(auth_mode=AuthMode.NONE)
        transport = self._redirect_transport("http://127.0.0.1/admin")
        async with DastSession(actor, resolve=False, transport=transport) as session:
            with pytest.raises(ValueError):
                await session.request("GET", "https://target.example/start")

    @pytest.mark.asyncio
    async def test_redirect_to_cloud_metadata_ip_is_rejected(self):
        actor = ActorConfig(auth_mode=AuthMode.NONE)
        transport = self._redirect_transport("http://169.254.169.254/latest/meta-data/")
        async with DastSession(actor, resolve=False, transport=transport) as session:
            with pytest.raises(ValueError):
                await session.request("GET", "https://target.example/start")

    @pytest.mark.asyncio
    async def test_redirect_to_public_host_still_succeeds(self):
        actor = ActorConfig(auth_mode=AuthMode.NONE)
        transport = self._redirect_transport("https://target.example/landed")
        async with DastSession(actor, resolve=False, transport=transport) as session:
            resp = await session.request("GET", "https://target.example/start")
        assert resp.json() == {"ok": True, "path": "/landed"}

    @pytest.mark.asyncio
    async def test_redirect_guard_also_applies_to_unauthenticated_request(self):
        actor = ActorConfig(auth_mode=AuthMode.NONE)
        transport = self._redirect_transport("http://127.0.0.1/admin")
        async with DastSession(actor, resolve=False, transport=transport) as session:
            with pytest.raises(ValueError):
                await session.request_unauthenticated("GET", "https://target.example/start")


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


class TestBrowserAuthState:
    """Track C2 — DastSession.browser_auth_state() exports whatever this
    session already authenticated with, in the shapes Playwright's
    BrowserContext wants — never a second login."""

    @pytest.mark.asyncio
    async def test_bearer_token_exported_as_authorization_header(self):
        actor = ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="secret-token-xyz")
        async with DastSession(actor, resolve=False, transport=_echo_transport([], [])) as session:
            cookies, headers = session.browser_auth_state()

        assert cookies == []
        assert headers == {"Authorization": "Bearer secret-token-xyz"}

    @pytest.mark.asyncio
    async def test_form_login_cookie_exported_with_domain_and_path(self):
        form = FormLoginConfig(
            login_url="https://target.example/login",
            username_field="user", password_field="pass",
            username="alice", password="hunter2",
        )
        actor = ActorConfig(auth_mode=AuthMode.FORM_LOGIN, form_login=form)
        async with DastSession(actor, resolve=False, transport=_echo_transport([], [])) as session:
            cookies, headers = session.browser_auth_state()

        assert headers == {}
        assert len(cookies) == 1
        assert cookies[0]["name"] == "session"
        assert cookies[0]["value"] == "abc123"
        assert cookies[0]["domain"]
        assert cookies[0]["path"] == "/"

    @pytest.mark.asyncio
    async def test_no_auth_mode_exports_nothing(self):
        actor = ActorConfig(auth_mode=AuthMode.NONE)
        async with DastSession(actor, resolve=False, transport=_echo_transport([], [])) as session:
            cookies, headers = session.browser_auth_state()

        assert cookies == []
        assert headers == {}


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


class TestApiKeyAuth:
    """Track C6 — a static header, no token exchange, no refresh."""

    @pytest.mark.asyncio
    async def test_api_key_header_attached_to_every_request(self):
        actor = ActorConfig(auth_mode=AuthMode.API_KEY, api_key_header="X-API-Key", api_key_value="secret-key-1")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"key_seen": request.headers.get("x-api-key", "")})

        async with DastSession(actor, resolve=False, transport=httpx.MockTransport(handler)) as session:
            resp = await session.request("GET", "https://target.example/api/data")
        assert resp.json()["key_seen"] == "secret-key-1"

    @pytest.mark.asyncio
    async def test_api_key_mode_without_header_or_value_raises(self):
        actor = ActorConfig(auth_mode=AuthMode.API_KEY, api_key_header=None, api_key_value="secret")
        with pytest.raises(ValueError):
            async with DastSession(actor, resolve=False, transport=_echo_transport([], [])):
                pass

    @pytest.mark.asyncio
    async def test_api_key_value_redacted_from_log_line(self):
        actor = ActorConfig(auth_mode=AuthMode.API_KEY, api_key_header="X-API-Key", api_key_value="secret-key-1")
        async with DastSession(actor, resolve=False, transport=_echo_transport([], [])) as session:
            assert "secret-key-1" not in session.redact("X-API-Key: secret-key-1")

    @pytest.mark.asyncio
    async def test_api_key_exported_via_browser_auth_state(self):
        actor = ActorConfig(auth_mode=AuthMode.API_KEY, api_key_header="X-API-Key", api_key_value="secret-key-1")
        async with DastSession(actor, resolve=False, transport=_echo_transport([], [])) as session:
            cookies, headers = session.browser_auth_state()
        assert cookies == []
        assert headers == {"X-API-Key": "secret-key-1"}


class TestCsrfFormLogin:
    """Track C6 — COOKIE + CSRF: fetch csrf_source_url first, fold the
    extracted token into the login POST body."""

    @staticmethod
    def _transport(login_bodies: list, *, csrf_html: str = '<input type="hidden" name="csrf_token" value="tokABC">'):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/csrf":
                return httpx.Response(200, text=csrf_html, headers={"content-type": "text/html"})
            if request.url.path == "/login":
                login_bodies.append(request.content.decode())
                return httpx.Response(200, headers={"set-cookie": "session=abc123; Path=/"})
            return httpx.Response(200, json={"ok": True})

        return httpx.MockTransport(handler)

    def _form(self, **overrides) -> FormLoginConfig:
        base = dict(
            login_url="https://target.example/login",
            username_field="user", password_field="pass",
            username="alice", password="hunter2",
            csrf_field="csrf_token", csrf_source_url="https://target.example/csrf",
        )
        base.update(overrides)
        return FormLoginConfig(**base)

    @pytest.mark.asyncio
    async def test_csrf_token_fetched_and_included_in_login_body(self):
        bodies: list = []
        actor = ActorConfig(auth_mode=AuthMode.FORM_LOGIN, form_login=self._form())
        async with DastSession(actor, resolve=False, transport=self._transport(bodies)):
            pass
        assert "csrf_token=tokABC" in bodies[0]
        assert "user=alice" in bodies[0] and "pass=hunter2" in bodies[0]

    @pytest.mark.asyncio
    async def test_missing_csrf_token_still_attempts_login(self):
        bodies: list = []
        actor = ActorConfig(auth_mode=AuthMode.FORM_LOGIN, form_login=self._form())
        async with DastSession(
            actor, resolve=False, transport=self._transport(bodies, csrf_html="<p>no token here</p>"),
        ):
            pass
        assert "csrf_token" not in bodies[0]
        assert "user=alice" in bodies[0]

    @pytest.mark.asyncio
    async def test_csrf_token_extracted_from_meta_tag(self):
        bodies: list = []
        actor = ActorConfig(auth_mode=AuthMode.FORM_LOGIN, form_login=self._form())
        html = '<meta name="csrf_token" content="metaTokXYZ">'
        async with DastSession(actor, resolve=False, transport=self._transport(bodies, csrf_html=html)):
            pass
        assert "csrf_token=metaTokXYZ" in bodies[0]

    @pytest.mark.asyncio
    async def test_form_login_without_csrf_fields_unaffected(self):
        """No csrf_field/csrf_source_url set — behaves exactly like plain form_login."""
        bodies: list = []
        actor = ActorConfig(
            auth_mode=AuthMode.FORM_LOGIN,
            form_login=self._form(csrf_field=None, csrf_source_url=None),
        )
        async with DastSession(actor, resolve=False, transport=self._transport(bodies)):
            pass
        assert "user=alice" in bodies[0] and "csrf_token" not in bodies[0]


class TestOAuth2Auth:
    """Track C6 — client-credentials and password grants, refreshed on 401
    or proactively once the token nears the expiry the token response
    reported."""

    @staticmethod
    def _token_transport(token_calls: list, *, expires_in=3600, include_refresh_token=True, protected_status=None):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/token":
                body = dict(x.split("=") for x in request.content.decode().split("&") if x)
                token_calls.append(body)
                token_id = f"tok{len(token_calls)}"
                payload = {"access_token": token_id, "token_type": "bearer", "expires_in": expires_in}
                if include_refresh_token:
                    payload["refresh_token"] = f"refresh{len(token_calls)}"
                return httpx.Response(200, json=payload)
            auth = request.headers.get("authorization", "")
            # Only the very first minted token (tok1) is treated as
            # "expired" — any subsequent token (from a refresh or re-auth)
            # succeeds, so a test can assert the retry actually used a new
            # token rather than looping forever.
            if protected_status is not None and auth == "Bearer tok1":
                return httpx.Response(protected_status)
            return httpx.Response(200, json={"authorization_seen": auth})

        return httpx.MockTransport(handler)

    @pytest.mark.asyncio
    async def test_client_credentials_grant_sets_bearer_header(self):
        calls: list = []
        cfg = OAuth2Config(
            token_url="https://target.example/token", grant_type="client_credentials",
            client_id="cid", client_secret="csecret",
        )
        actor = ActorConfig(auth_mode=AuthMode.OAUTH2, oauth2=cfg)
        async with DastSession(actor, resolve=False, transport=self._token_transport(calls)) as session:
            resp = await session.request("GET", "https://target.example/api/data")
        assert resp.json()["authorization_seen"] == "Bearer tok1"
        assert calls[0]["grant_type"] == "client_credentials"
        assert calls[0]["client_id"] == "cid"

    @pytest.mark.asyncio
    async def test_password_grant_includes_username_and_password(self):
        calls: list = []
        cfg = OAuth2Config(
            token_url="https://target.example/token", grant_type="password",
            username="alice", password="hunter2", client_id="cid",
        )
        actor = ActorConfig(auth_mode=AuthMode.OAUTH2, oauth2=cfg)
        async with DastSession(actor, resolve=False, transport=self._token_transport(calls)) as session:
            resp = await session.request("GET", "https://target.example/api/data")
        assert resp.json()["authorization_seen"] == "Bearer tok1"
        assert calls[0]["username"] == "alice"
        assert calls[0]["password"] == "hunter2"

    @pytest.mark.asyncio
    async def test_missing_access_token_in_response_raises(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"token_type": "bearer"})  # no access_token

        cfg = OAuth2Config(token_url="https://target.example/token")
        actor = ActorConfig(auth_mode=AuthMode.OAUTH2, oauth2=cfg)
        with pytest.raises(ValueError):
            async with DastSession(actor, resolve=False, transport=httpx.MockTransport(handler)):
                pass

    @pytest.mark.asyncio
    async def test_401_triggers_refresh_token_grant_and_retry_succeeds(self):
        calls: list = []
        cfg = OAuth2Config(token_url="https://target.example/token", client_id="cid", client_secret="csecret")
        actor = ActorConfig(auth_mode=AuthMode.OAUTH2, oauth2=cfg)
        transport = self._token_transport(calls, protected_status=401)
        async with DastSession(actor, resolve=False, transport=transport) as session:
            resp = await session.request("GET", "https://target.example/api/data")
        # 1st call: initial client_credentials grant; 2nd call: refresh_token grant
        # triggered by the 401 (tok1 always 401s in this transport, so the retry
        # with tok2 is what finally returns 200).
        assert len(calls) == 2
        assert calls[1]["grant_type"] == "refresh_token"
        assert calls[1]["refresh_token"] == "refresh1"
        assert resp.status_code == 200
        assert resp.json()["authorization_seen"] == "Bearer tok2"

    @pytest.mark.asyncio
    async def test_proactive_refresh_before_token_expiry(self):
        """expires_in=0 means the token is considered expired the moment it's
        acquired (30s early-refresh buffer floors at 0) — the very next
        request() call must refresh before sending, not wait for a 401."""
        calls: list = []
        cfg = OAuth2Config(token_url="https://target.example/token", client_id="cid", client_secret="csecret")
        actor = ActorConfig(auth_mode=AuthMode.OAUTH2, oauth2=cfg)
        transport = self._token_transport(calls, expires_in=0)
        async with DastSession(actor, resolve=False, transport=transport) as session:
            resp = await session.request("GET", "https://target.example/api/data")
        assert len(calls) == 2  # initial grant + proactive refresh before the request went out
        assert resp.json()["authorization_seen"] == "Bearer tok2"

    @pytest.mark.asyncio
    async def test_long_lived_token_not_refreshed_unnecessarily(self):
        calls: list = []
        cfg = OAuth2Config(token_url="https://target.example/token", client_id="cid", client_secret="csecret")
        actor = ActorConfig(auth_mode=AuthMode.OAUTH2, oauth2=cfg)
        transport = self._token_transport(calls, expires_in=3600)
        async with DastSession(actor, resolve=False, transport=transport) as session:
            await session.request("GET", "https://target.example/api/data")
            await session.request("GET", "https://target.example/api/data")
        assert len(calls) == 1  # one grant covers both requests, no refresh needed

    @pytest.mark.asyncio
    async def test_oauth2_mode_without_config_raises(self):
        actor = ActorConfig(auth_mode=AuthMode.OAUTH2, oauth2=None)
        with pytest.raises(ValueError):
            async with DastSession(actor, resolve=False, transport=_echo_transport([], [])):
                pass

    @pytest.mark.asyncio
    async def test_access_token_and_client_secret_redacted_from_log_line(self):
        calls: list = []
        cfg = OAuth2Config(token_url="https://target.example/token", client_id="cid", client_secret="csecret")
        actor = ActorConfig(auth_mode=AuthMode.OAUTH2, oauth2=cfg)
        async with DastSession(actor, resolve=False, transport=self._token_transport(calls)) as session:
            assert "csecret" not in session.redact("client_secret=csecret")
            assert "tok1" not in session.redact("Authorization: Bearer tok1")
