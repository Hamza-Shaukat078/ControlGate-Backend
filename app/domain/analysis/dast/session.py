"""Authenticated HTTP session harness for the DAST engine.

dynamic_probe.py validates its target once, up front, because it only ever
calls the one fixed target_url. A real DAST engine (crawler + payload/scenario
checks in later phases) fires many requests at many discovered URLs, so this
validates the SSRF/public-host guard on every single request instead.
"""
import logging
import re
import time
from typing import Dict, Optional

import httpx

from app.core.network import validate_public_http_url
from app.domain.analysis.dast.config import ActorConfig, AuthMode, DynamicScanConfig, OAuth2Config

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 10.0
REDACTED = "***REDACTED***"

# Track C6 — lightweight regex CSRF-token extraction, same weight/approach as
# crawler.py's link/form extraction rather than pulling in a real HTML
# parser for one field lookup. Tried in order: a hidden <input name=X
# value=...> (attribute order either way), a <meta name=X content=...> (the
# Rails/Django-JS convention), and a bare "X": "..." JSON field (an API-ish
# login page that hands the SPA a token in a JSON payload instead of HTML).
_CSRF_PATTERNS = (
    r'<input\b[^>]*\bname=["\']{field}["\'][^>]*\bvalue=["\']([^"\']*)["\']',
    r'<input\b[^>]*\bvalue=["\']([^"\']*)["\'][^>]*\bname=["\']{field}["\']',
    r'<meta\b[^>]*\bname=["\']{field}["\'][^>]*\bcontent=["\']([^"\']*)["\']',
    r'["\']{field}["\']\s*:\s*["\']([^"\']+)["\']',
)


def _extract_csrf_token(text: str, field_name: str) -> Optional[str]:
    escaped = re.escape(field_name)
    for pattern in _CSRF_PATTERNS:
        match = re.search(pattern.format(field=escaped), text, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


# form_login's cookie-jar auth (below) covers a session-cookie login. A JWT
# microservice API commonly does the opposite: no Set-Cookie at all, the
# access token comes back in the JSON body instead (often nested, e.g.
# {"data": {"user": {...}, "accessToken": "..."}}). Rather than a separate
# auth mode the user has to know to pick, every successful form_login
# response is checked for one of these field names (order doesn't matter —
# _extract_bearer_token_from_json does a full recursive search) and, if
# found, applied as a Bearer header alongside whatever cookies landed. A
# cookie-only target simply has no matching key here and behaves exactly as
# before this existed.
_BEARER_TOKEN_KEY_NAMES = {"accesstoken", "token", "jwt", "authtoken", "idtoken", "bearertoken"}


def _extract_bearer_token_from_json(data) -> Optional[str]:
    if isinstance(data, dict):
        for key, value in data.items():
            normalized = key.lower().replace("_", "").replace("-", "")
            if isinstance(value, str) and value and normalized in _BEARER_TOKEN_KEY_NAMES:
                return value
        for value in data.values():
            found = _extract_bearer_token_from_json(value)
            if found:
                return found
    elif isinstance(data, list):
        for item in data:
            found = _extract_bearer_token_from_json(item)
            if found:
                return found
    return None


class DastSession:
    """One authenticated HTTP session for a single DAST scan actor."""

    def __init__(
        self,
        actor: ActorConfig,
        *,
        allow_http: bool = True,
        resolve: bool = True,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        transport: Optional[httpx.BaseTransport] = None,
    ):
        self._actor = actor
        self._allow_http = allow_http
        self._resolve = resolve
        self._timeout = timeout
        self._transport = transport
        self._client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            transport=transport,
            event_hooks={"request": [self._validate_redirect_target]},
        )
        self._reauth_in_progress = False
        # Track C6 — OAuth2 token state. None until the first successful
        # _acquire_oauth2_token(): _oauth2_expiry stays None for a token
        # whose response didn't include expires_in, which just means this
        # session never proactively refreshes it and instead relies purely
        # on the reactive 401-triggered refresh in request() below.
        self._oauth2_expiry: Optional[float] = None
        self._oauth2_refresh_token: Optional[str] = None
        self._secrets: set[str] = set()
        if actor.bearer_token:
            self._secrets.add(actor.bearer_token)
        if actor.form_login:
            self._secrets.add(actor.form_login.password)
        if actor.api_key_value:
            self._secrets.add(actor.api_key_value)
        if actor.oauth2:
            if actor.oauth2.client_secret:
                self._secrets.add(actor.oauth2.client_secret)
            if actor.oauth2.password:
                self._secrets.add(actor.oauth2.password)

    async def __aenter__(self) -> "DastSession":
        await self._authenticate()
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self._client.aclose()

    async def _validate_redirect_target(self, request: httpx.Request) -> None:
        """httpx 'request' event hook — fires for the initial request AND
        again for every redirect hop it follows internally (each rebuilt
        redirect Request re-enters the same event-hook loop before it's
        sent, see AsyncClient._send_handling_redirects). request()/
        _authenticate() only validate the URL the caller/login-flow passed
        in up front; without this hook a 3xx response (e.g. to a
        169.254.169.254/internal host) would be followed unchecked since
        follow_redirects=True on this client. Runs SSRF/public-host
        validation on every hop, not just the first one.
        """
        validate_public_http_url(str(request.url), allow_http=self._allow_http, resolve=self._resolve)

    async def _authenticate(self) -> None:
        actor = self._actor
        if actor.auth_mode == AuthMode.NONE:
            return
        if actor.auth_mode == AuthMode.BEARER:
            if not actor.bearer_token:
                raise ValueError("auth_mode=bearer requires bearer_token")
            self._client.headers["Authorization"] = f"Bearer {actor.bearer_token}"
            return
        if actor.auth_mode == AuthMode.FORM_LOGIN:
            form = actor.form_login
            if not form:
                raise ValueError("auth_mode=form_login requires form_login config")
            validate_public_http_url(form.login_url, allow_http=self._allow_http, resolve=self._resolve)
            data = {form.username_field: form.username, form.password_field: form.password}
            # Track C6 — COOKIE + CSRF: fetch the token first if this login
            # needs one. Never fatal on its own — a target that rotated its
            # form shape or dropped CSRF protection shouldn't hard-fail the
            # login, it should just attempt it without the field and let the
            # login POST itself succeed or fail on its own merits.
            if form.csrf_field and form.csrf_source_url:
                validate_public_http_url(form.csrf_source_url, allow_http=self._allow_http, resolve=self._resolve)
                try:
                    csrf_resp = await self._client.get(form.csrf_source_url)
                    csrf_resp.raise_for_status()
                    token = _extract_csrf_token(csrf_resp.text, form.csrf_field)
                    if token is not None:
                        data[form.csrf_field] = token
                    else:
                        logger.warning(
                            f"CSRF field '{form.csrf_field}' not found at {form.csrf_source_url}; "
                            "attempting login without it"
                        )
                except Exception as exc:
                    logger.warning(f"CSRF token fetch from {form.csrf_source_url} failed: {exc}")
            resp = await self._client.post(form.login_url, data=data)
            if resp.status_code == 415:
                # Bug fix — "form_login" means "username+password submitted
                # to a login endpoint", not necessarily an HTML <form>: a
                # JSON-only API login route (Flask's request.get_json()
                # without force=True, common on API-first targets like a
                # bank/SPA backend) rejects the x-www-form-urlencoded body
                # above with 415 before ever looking at the credentials, so
                # every dynamic check downstream saw 0 results even though
                # the username/password were correct. Retry once as a JSON
                # body — cheap (only fires on an explicit "wrong media
                # type" from the target) and turns a hard-fail into a
                # working login for that shape without needing a new config
                # field the user has to already know to set.
                resp = await self._client.post(form.login_url, json=data)
            resp.raise_for_status()
            # Session cookies land in self._client.cookies automatically via
            # httpx's cookie jar — every subsequent request() reuses them.
            # A JWT API that hands back the token in the JSON body instead
            # (no Set-Cookie at all) gets the same treatment bearer auth
            # would have needed manually — see _extract_bearer_token_from_json.
            try:
                body = resp.json()
            except ValueError:
                body = None
            if body is not None:
                token = _extract_bearer_token_from_json(body)
                if token:
                    self._client.headers["Authorization"] = f"Bearer {token}"
            return
        if actor.auth_mode == AuthMode.OAUTH2:
            cfg = actor.oauth2
            if not cfg:
                raise ValueError("auth_mode=oauth2 requires oauth2 config")
            validate_public_http_url(cfg.token_url, allow_http=self._allow_http, resolve=self._resolve)
            await self._acquire_oauth2_token(cfg)
            return
        if actor.auth_mode == AuthMode.API_KEY:
            if not actor.api_key_header or not actor.api_key_value:
                raise ValueError("auth_mode=api_key requires api_key_header and api_key_value")
            self._client.headers[actor.api_key_header] = actor.api_key_value
            return
        raise ValueError(f"Unknown auth_mode: {actor.auth_mode}")

    async def _acquire_oauth2_token(self, cfg: OAuth2Config) -> None:
        """RFC 6749 client_credentials (§4.4) / password (§4.3) grant —
        POSTed as application/x-www-form-urlencoded, the shape every
        mainstream OAuth2/OIDC provider (Keycloak, Auth0, a plain
        FastAPI/Authlib backend) accepts."""
        data: Dict[str, str] = {"grant_type": cfg.grant_type}
        if cfg.grant_type == "password":
            data["username"] = cfg.username or ""
            data["password"] = cfg.password or ""
        if cfg.client_id:
            data["client_id"] = cfg.client_id
        if cfg.client_secret:
            data["client_secret"] = cfg.client_secret
        if cfg.scope:
            data["scope"] = cfg.scope
        resp = await self._client.post(cfg.token_url, data=data)
        resp.raise_for_status()
        self._apply_oauth2_token_response(resp.json())

    async def _refresh_oauth2_token(self) -> None:
        """Prefers the refresh_token grant (RFC 6749 §6) when the last token
        response included one — cheaper than a full re-auth and doesn't
        need the password/client-credentials to still be valid if the IdP
        rotates them independently of tokens. Falls back to re-running the
        original grant (same as a fresh _authenticate()) when there's no
        refresh token, or the refresh attempt itself fails (revoked, IdP
        doesn't support it, ...)."""
        cfg = self._actor.oauth2
        if cfg is None:
            return
        if self._oauth2_refresh_token:
            data: Dict[str, str] = {"grant_type": "refresh_token", "refresh_token": self._oauth2_refresh_token}
            if cfg.client_id:
                data["client_id"] = cfg.client_id
            if cfg.client_secret:
                data["client_secret"] = cfg.client_secret
            try:
                resp = await self._client.post(cfg.token_url, data=data)
                resp.raise_for_status()
                self._apply_oauth2_token_response(resp.json())
                return
            except Exception as exc:
                logger.debug(f"OAuth2 refresh_token grant failed, falling back to original grant: {exc}")
        await self._acquire_oauth2_token(cfg)

    def _apply_oauth2_token_response(self, payload: dict) -> None:
        access_token = payload.get("access_token")
        if not access_token:
            raise ValueError("OAuth2 token endpoint response is missing 'access_token'")
        self._client.headers["Authorization"] = f"Bearer {access_token}"
        self._secrets.add(access_token)
        refresh_token = payload.get("refresh_token")
        if refresh_token:
            self._oauth2_refresh_token = refresh_token
            self._secrets.add(refresh_token)
        expires_in = payload.get("expires_in")
        if isinstance(expires_in, (int, float)):
            # Refresh 30s early so a request that starts just before expiry
            # doesn't race the token dying mid-flight; time.monotonic() (not
            # wall-clock) so this is immune to system clock adjustments
            # during a long-running scan.
            self._oauth2_expiry = time.monotonic() + max(float(expires_in) - 30, 0)
        else:
            self._oauth2_expiry = None

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Track C4 — a form_login session can outlive a long crawl. A 401
        here (only 401 — "Unauthorized"/session-not-valid, not 403
        "Forbidden"/genuinely-denied, which several checks legitimately
        expect and shouldn't have silently retried out from under them,
        e.g. IDOR/UNAUTHENTICATED_ACCESS_ALLOWED) triggers exactly one
        re-login + retry for form_login, or one refresh + retry for oauth2
        (Track C6 — via _refresh_oauth2_token, refresh_token grant if
        available else re-running the original grant). Bearer/api_key
        sessions can't meaningfully "refresh" (no refresh-token concept for
        either) so a 401 there just propagates. _reauth_in_progress guards
        against looping if the re-auth itself keeps failing (credentials
        actually revoked, not just an expired session/token) — a second
        failure propagates normally, same as before this existed.
        """
        validate_public_http_url(url, allow_http=self._allow_http, resolve=self._resolve)
        # Proactive refresh: an oauth2 token nearing/past its known expiry is
        # refreshed before it ever produces a 401, so a long crawl doesn't
        # pay for a wasted round-trip + reactive retry on every request
        # after expiry.
        if (
            self._actor.auth_mode == AuthMode.OAUTH2
            and self._oauth2_expiry is not None
            and time.monotonic() >= self._oauth2_expiry
            and not self._reauth_in_progress
        ):
            self._reauth_in_progress = True
            try:
                await self._refresh_oauth2_token()
            except Exception as exc:
                logger.debug(f"Proactive OAuth2 refresh failed, continuing with existing token: {exc}")
            finally:
                self._reauth_in_progress = False

        resp = await self._client.request(method, url, **kwargs)
        if (
            resp.status_code == 401
            and self._actor.auth_mode in (AuthMode.FORM_LOGIN, AuthMode.OAUTH2)
            and not self._reauth_in_progress
        ):
            self._reauth_in_progress = True
            try:
                if self._actor.auth_mode == AuthMode.OAUTH2:
                    await self._refresh_oauth2_token()
                else:
                    await self._authenticate()
            finally:
                self._reauth_in_progress = False
            resp = await self._client.request(method, url, **kwargs)
        return resp

    @property
    def is_authenticated(self) -> bool:
        return self._actor.auth_mode != AuthMode.NONE

    async def request_unauthenticated(self, method: str, url: str, **kwargs) -> httpx.Response:
        """One-off request through this session's transport/timeout but with
        no Authorization header and none of this session's cookies — used by
        the unauthenticated-access check to see what an anonymous caller gets,
        without needing a second real DastSession/actor just for that."""
        validate_public_http_url(url, allow_http=self._allow_http, resolve=self._resolve)
        async with httpx.AsyncClient(
            timeout=self._timeout,
            follow_redirects=True,
            transport=self._transport,
            event_hooks={"request": [self._validate_redirect_target]},
        ) as anon_client:
            return await anon_client.request(method, url, **kwargs)

    def browser_auth_state(self) -> tuple[list[dict], dict[str, str]]:
        """Track C2 — exports this session's *already-established* auth
        state (cookies from a completed form_login, or the bearer header)
        in the shapes Playwright's BrowserContext wants
        (context.add_cookies()/context.set_extra_http_headers()). The
        browser crawler never performs its own login — this is the one
        place that translation happens, keeping actual login logic
        confined to _authenticate() above.

        httpx.Cookies wraps a stdlib http.cookiejar.CookieJar; iterating
        its .jar gives real Cookie objects with the domain/path Playwright
        needs (unlike Cookies.__iter__, which only yields name/value)."""
        cookies = [
            {
                "name": c.name,
                "value": c.value,
                "domain": c.domain,
                "path": c.path or "/",
            }
            for c in self._client.cookies.jar
            if c.domain  # Playwright's add_cookies() requires a non-empty domain (or a url instead)
        ]
        headers = {}
        auth_header = self._client.headers.get("Authorization")
        if auth_header:
            headers["Authorization"] = auth_header
        if self._actor.auth_mode == AuthMode.API_KEY and self._actor.api_key_header and self._actor.api_key_value:
            headers[self._actor.api_key_header] = self._actor.api_key_value
        return cookies, headers

    def redact(self, text: str) -> str:
        """Strip every known secret value (tokens, passwords, live session
        cookies) out of a string before it's logged or stored as evidence."""
        if not text:
            return text
        redacted = text
        for secret in self._secrets:
            redacted = redacted.replace(secret, REDACTED)
        for cookie_value in self._client.cookies.values():
            if cookie_value:
                redacted = redacted.replace(cookie_value, REDACTED)
        return redacted


class DastSessionPair:
    """Holds the primary (and optional second) actor session for a scan.

    A second session is what makes cross-session scenario checks possible
    (Phase 2B+) — e.g. confirming a credential change in one session
    invalidates the *other* session for the same account.
    """

    def __init__(
        self,
        config: DynamicScanConfig,
        *,
        resolve: bool = True,
        transport: Optional[httpx.BaseTransport] = None,
    ):
        self.primary = DastSession(config.actor, allow_http=True, resolve=resolve, transport=transport)
        self.secondary: Optional[DastSession] = (
            DastSession(config.second_actor, allow_http=True, resolve=resolve, transport=transport)
            if config.second_actor is not None
            else None
        )

    async def __aenter__(self) -> "DastSessionPair":
        await self.primary.__aenter__()
        if self.secondary is not None:
            await self.secondary.__aenter__()
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.primary.__aexit__(*exc_info)
        if self.secondary is not None:
            await self.secondary.__aexit__(*exc_info)
