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


@dataclass
class FormLoginConfig:
    login_url: str
    username_field: str
    password_field: str
    username: str
    password: str


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


@dataclass
class DynamicScanConfig:
    target_url: str
    actor: ActorConfig = field(default_factory=ActorConfig)
    second_actor: Optional[ActorConfig] = None
    # Gates any check with side effects: race/business-logic scenarios,
    # request smuggling, anything the user hasn't explicitly authorized.
    active_mode: bool = False
