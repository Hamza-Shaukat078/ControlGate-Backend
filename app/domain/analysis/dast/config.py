"""Scan-time configuration for the DAST engine.

Credentials here (bearer_token, form_login.password) are deliberately never
persisted — unlike a Repository's access_token (which is reused across many
scans and stored encrypted via app.core.crypto), a scan's login credentials
are supplied fresh on each ScanStart request and live only in memory for the
duration of that scan's async worker. Nothing in this module writes them to
Mongo or to a log line; see DastSession.redact() for how they're kept out of
captured evidence too.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class AuthMode(str, Enum):
    NONE = "none"
    BEARER = "bearer"
    FORM_LOGIN = "form_login"
    # Track C6 — client-credentials and password grants both live under this
    # one mode (OAuth2Config.grant_type picks between them) rather than two
    # separate AuthMode values: both resolve to the same shape once
    # authenticated (an Authorization: Bearer <access_token> header, plus an
    # optional refresh_token this session can use later), so nothing
    # downstream of _authenticate() needs to distinguish them.
    OAUTH2 = "oauth2"
    API_KEY = "api_key"


@dataclass
class FormLoginConfig:
    login_url: str
    username_field: str
    password_field: str
    username: str
    password: str
    # Track C6 — COOKIE + CSRF: when both are set, DastSession._authenticate
    # GETs csrf_source_url first, extracts a token named csrf_field out of
    # that page (hidden <input>, <meta>, or a JSON body field — see
    # session._extract_csrf_token), and includes it under csrf_field in the
    # login POST body alongside username/password. A login endpoint that
    # doesn't use CSRF protection simply leaves these unset and behaves
    # exactly as before this existed.
    csrf_field: Optional[str] = None
    csrf_source_url: Optional[str] = None


@dataclass
class OAuth2Config:
    """Token acquisition for AuthMode.OAUTH2. token_url is POSTed with a
    standard application/x-www-form-urlencoded grant request (RFC 6749 §4.3
    for client_credentials, §4.3 for password) — every OAuth2 provider this
    engine has been pointed at (Keycloak, Auth0, a plain FastAPI/OAuthlib
    backend) accepts that shape, so no provider-specific branching lives
    here.
    """

    token_url: str
    grant_type: str = "client_credentials"  # or "password"
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    scope: Optional[str] = None


@dataclass
class ActorConfig:
    """One authenticated identity a DAST scan can act as.

    A second ActorConfig (DynamicScanConfig.second_actor) is what lets
    cross-session scenario checks exist at all — e.g. V7.4.3 (does changing
    actor A's password invalidate actor A's *other* session) needs two
    concurrently held sessions for the same account, not one.
    """

    auth_mode: AuthMode = AuthMode.NONE
    bearer_token: Optional[str] = None
    form_login: Optional[FormLoginConfig] = None
    oauth2: Optional[OAuth2Config] = None
    # Track C6 — API_KEY: trivially set once as a static request header
    # (e.g. header="X-API-Key", value="..."). No token exchange, no
    # refresh — the key is either valid for the whole scan or it isn't.
    api_key_header: Optional[str] = None
    api_key_value: Optional[str] = None


@dataclass
class DynamicScanConfig:
    target_url: str
    actor: ActorConfig = field(default_factory=ActorConfig)
    second_actor: Optional[ActorConfig] = None
    # Gates any check with side effects: race/business-logic scenarios,
    # request smuggling, anything the user hasn't explicitly authorized.
    active_mode: bool = False
