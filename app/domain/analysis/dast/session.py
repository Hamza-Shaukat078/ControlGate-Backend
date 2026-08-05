"""Authenticated HTTP session harness for the DAST engine.

dynamic_probe.py validates its target once, up front, because it only ever
calls the one fixed target_url. A real DAST engine (crawler + payload/scenario
checks in later phases) fires many requests at many discovered URLs, so this
validates the SSRF/public-host guard on every single request instead.
"""
import logging
from typing import Optional

import httpx

from app.core.network import validate_public_http_url
from app.domain.analysis.dast.config import ActorConfig, AuthMode, DynamicScanConfig

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 10.0
REDACTED = "***REDACTED***"


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
        self._client = httpx.AsyncClient(timeout=timeout, follow_redirects=True, transport=transport)
        self._reauth_in_progress = False
        self._secrets: set[str] = set()
        if actor.bearer_token:
            self._secrets.add(actor.bearer_token)
        if actor.form_login:
            self._secrets.add(actor.form_login.password)

    async def __aenter__(self) -> "DastSession":
        await self._authenticate()
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self._client.aclose()

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
            resp = await self._client.post(
                form.login_url,
                data={form.username_field: form.username, form.password_field: form.password},
            )
            resp.raise_for_status()
            # Session cookies land in self._client.cookies automatically via
            # httpx's cookie jar — every subsequent request() reuses them.
            return
        raise ValueError(f"Unknown auth_mode: {actor.auth_mode}")

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Track C4 — a form_login session can outlive a long crawl. A 401
        here (only 401 — "Unauthorized"/session-not-valid, not 403
        "Forbidden"/genuinely-denied, which several checks legitimately
        expect and shouldn't have silently retried out from under them,
        e.g. IDOR/UNAUTHENTICATED_ACCESS_ALLOWED) triggers exactly one
        re-login + retry. Bearer sessions can't meaningfully "refresh" (no
        refresh-token concept in ActorConfig) so this only applies to
        form_login. _reauth_in_progress guards against looping if the
        re-login itself keeps failing (credentials actually revoked, not
        just an expired session) — a second failure propagates normally,
        same as before this existed.
        """
        validate_public_http_url(url, allow_http=self._allow_http, resolve=self._resolve)
        resp = await self._client.request(method, url, **kwargs)
        if (
            resp.status_code == 401
            and self._actor.auth_mode == AuthMode.FORM_LOGIN
            and not self._reauth_in_progress
        ):
            self._reauth_in_progress = True
            try:
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
            timeout=self._timeout, follow_redirects=True, transport=self._transport,
        ) as anon_client:
            return await anon_client.request(method, url, **kwargs)

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
