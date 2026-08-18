from datetime import datetime
from typing import Optional
from pydantic import Field, field_validator, model_validator
from enum import Enum
from app.schemas.common import APIModel
from app.enums.scan_mode import ScanMode
from app.enums.scan_type import ScanType
from app.domain.analysis.dast.config import AuthMode


class Language(str, Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"



class DynamicFormLoginRequest(APIModel):
    login_url: str
    username_field: str
    password_field: str
    username: str
    password: str
    # Track C6 — COOKIE + CSRF: both must be supplied together (see
    # validate_csrf_fields_paired below) to fetch a CSRF token before
    # logging in. Neither set (the default) behaves exactly as before this
    # existed — a plain username/password POST.
    csrf_field: Optional[str] = Field(
        None, description="Name of the CSRF token field/input to include in the login POST body. "
                           "Requires csrf_source_url."
    )
    csrf_source_url: Optional[str] = Field(
        None, description="URL to GET before logging in, to extract the CSRF token named csrf_field "
                           "from (a hidden <input>, <meta> tag, or JSON field). Requires csrf_field."
    )

    @field_validator('login_url')
    @classmethod
    def validate_login_url_scheme(cls, v):
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("'login_url' must start with http:// or https://")
        return v

    @field_validator('csrf_source_url')
    @classmethod
    def validate_csrf_source_url_scheme(cls, v):
        if v is not None and not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("'csrf_source_url' must start with http:// or https://")
        return v

    @model_validator(mode='after')
    def validate_csrf_fields_paired(self):
        if bool(self.csrf_field) != bool(self.csrf_source_url):
            raise ValueError("'csrf_field' and 'csrf_source_url' must be supplied together")
        return self


class DynamicOAuth2Request(APIModel):
    """Track C6 — client-credentials and password grants (RFC 6749 §4.3/§4.4).
    Whichever it is, DastSession ends up with an Authorization: Bearer
    <access_token> header, refreshed automatically (refresh_token grant if
    the response included one, else re-running this same grant) on a 401
    mid-scan — see DastSession._refresh_oauth2_token."""

    token_url: str
    grant_type: str = "client_credentials"
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    scope: Optional[str] = None

    @field_validator('token_url')
    @classmethod
    def validate_token_url_scheme(cls, v):
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("'token_url' must start with http:// or https://")
        return v

    @field_validator('grant_type')
    @classmethod
    def validate_grant_type(cls, v):
        allowed = {"client_credentials", "password"}
        if v not in allowed:
            raise ValueError(f"'grant_type' must be one of {sorted(allowed)}")
        return v

    @model_validator(mode='after')
    def validate_grant_requirements(self):
        if self.grant_type == "password" and not (self.username and self.password):
            raise ValueError("grant_type='password' requires 'username' and 'password'")
        return self


class DynamicScenarioStepRequest(APIModel):
    method: str
    url: str
    session: str = "primary"  # "primary" | "secondary"
    params: Optional[dict] = None
    data: Optional[dict] = None
    json_body: Optional[dict] = None
    headers: Optional[dict] = None
    follow_redirects: bool = False
    assert_status_in: Optional[list[int]] = None
    # Track C — the OAuth/OIDC live-protocol checks (V10.4.x) this field set
    # was added for need more than a status code to tell "silently accepted"
    # apart from "correctly rejected": two different response_modes/redirect
    # targets both come back 302, a consent screen and a silent re-grant
    # both come back 302 (V10.7.1) — only the body/redirect target tells
    # them apart. All non-null assert_* fields on one step are ANDed
    # together (api_scenario.py appends each as its own Assertion;
    # scenario_runner.run_scenario already requires every assertion in a
    # step's list to pass).
    assert_body_contains: Optional[str] = None
    assert_body_not_contains: Optional[str] = None
    assert_redirect_location_contains: Optional[str] = None
    # V10.4.3 — authorization codes must be rejected past their max lifetime
    # (10 min L1/L2, 1 min L3), which needs a real wall-clock wait between
    # obtaining the code and attempting the exchange. Capped at 650s (a bit
    # over the 10-minute ceiling ASVS itself specifies, so it's usable for
    # every level this control applies to) — scan_service.py extends this
    # scenario's own timeout by the same amount so the wait doesn't just
    # get cut off by PER_ITEM_TIMEOUT.
    delay_seconds: Optional[float] = Field(None, ge=0, le=650)

    @field_validator('method')
    @classmethod
    def validate_method(cls, v):
        allowed = {"GET", "POST", "PUT", "PATCH", "DELETE"}
        if v.upper() not in allowed:
            raise ValueError(f"'method' must be one of {sorted(allowed)}")
        return v.upper()

    @field_validator('session')
    @classmethod
    def validate_session_actor(cls, v):
        if v not in ("primary", "secondary"):
            raise ValueError("'session' must be 'primary' or 'secondary'")
        return v

    @field_validator('url')
    @classmethod
    def validate_step_url_scheme(cls, v):
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("'url' must start with http:// or https://")
        return v


class DynamicScenarioRequest(APIModel):
    scenario_id: str
    asvs_controls: list[str] = Field(default_factory=list)
    # Defaults true, unlike dynamic_active_mode itself: a user-supplied
    # scenario is app-specific and usually has real side effects (changing a
    # password, revoking access, submitting an order) — require the scan to
    # explicitly opt in via dynamic_active_mode rather than assume it's safe.
    requires_active_mode: bool = True
    severity: str = "medium"
    description: str = ""
    steps: list[DynamicScenarioStepRequest]

    @field_validator('steps')
    @classmethod
    def validate_steps_not_empty(cls, v):
        if not v:
            raise ValueError("'steps' must contain at least one step")
        return v


class DynamicRaceProbeRequest(APIModel):
    """V2.3.4 — fires 'concurrency' concurrent requests at the same endpoint
    and checks whether more than 'max_expected_successes' came back 2xx.
    A different shape than DynamicScenarioRequest (concurrent, not
    sequential), so it's its own request type rather than a Scenario step."""

    scenario_id: str
    asvs_controls: list[str] = Field(default_factory=lambda: ["V2.3.4"])
    url: str
    method: str = "POST"
    session: str = "primary"
    params: Optional[dict] = None
    data: Optional[dict] = None
    headers: Optional[dict] = None
    concurrency: int = Field(5, ge=2, le=20)
    max_expected_successes: int = Field(1, ge=0)
    requires_active_mode: bool = True
    severity: str = "high"

    @field_validator('method')
    @classmethod
    def validate_method(cls, v):
        allowed = {"GET", "POST", "PUT", "PATCH", "DELETE"}
        if v.upper() not in allowed:
            raise ValueError(f"'method' must be one of {sorted(allowed)}")
        return v.upper()

    @field_validator('session')
    @classmethod
    def validate_session_actor(cls, v):
        if v not in ("primary", "secondary"):
            raise ValueError("'session' must be 'primary' or 'secondary'")
        return v

    @field_validator('url')
    @classmethod
    def validate_url_scheme(cls, v):
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("'url' must start with http:// or https://")
        return v


class DynamicIdorProbeRequest(APIModel):
    """V8.2.1 — has the primary actor request a resource it owns, then has
    the second actor request the exact same URL. A 2xx for the second actor
    means no ownership check gates the endpoint. Needs dynamic_second_actor_*
    configured (same 'primary'/'secondary' vocabulary as race probes), not a
    Scenario step because the two calls are actor-scoped, not sequential."""

    scenario_id: str
    asvs_controls: list[str] = Field(default_factory=lambda: ["V8.2.1"])
    owner_resource_url: str
    method: str = "GET"
    params: Optional[dict] = None
    data: Optional[dict] = None
    headers: Optional[dict] = None
    severity: str = "high"
    # None => derive from method (GET/HEAD don't need it, mutating methods do) —
    # matches IdorProbeConfig.resolved_requires_active_mode(). An explicit
    # true/false here overrides that inference, same escape hatch the dataclass gives.
    requires_active_mode: Optional[bool] = None

    @field_validator('method')
    @classmethod
    def validate_method(cls, v):
        allowed = {"GET", "POST", "PUT", "PATCH", "DELETE"}
        if v.upper() not in allowed:
            raise ValueError(f"'method' must be one of {sorted(allowed)}")
        return v.upper()

    @field_validator('owner_resource_url')
    @classmethod
    def validate_url_scheme(cls, v):
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("'owner_resource_url' must start with http:// or https://")
        return v


class DynamicMassAssignmentProbeRequest(APIModel):
    """V15.3.3 — submits an unrequested privileged field (e.g. {"role":
    "admin"}) alongside a normal-looking object-update request from the
    primary actor, then has the second actor independently re-read the
    resource to confirm whether it actually took. Requires
    dynamic_second_actor_auth_mode to be configured — the same
    'don't trust the submitter's own view' reasoning as IDOR probes,
    applied to state persistence instead of access control."""

    scenario_id: str
    asvs_controls: list[str] = Field(default_factory=lambda: ["V15.3.3"])
    update_url: str
    update_method: str = "PATCH"
    baseline_fields: Optional[dict] = None
    injected_field: str = "role"
    injected_value: object = "admin"
    verify_url: Optional[str] = None
    verify_field_path: Optional[str] = None
    severity: str = "high"

    @field_validator('update_method')
    @classmethod
    def validate_method(cls, v):
        allowed = {"POST", "PUT", "PATCH"}
        if v.upper() not in allowed:
            raise ValueError(f"'update_method' must be one of {sorted(allowed)}")
        return v.upper()

    @field_validator('update_url')
    @classmethod
    def validate_url_scheme(cls, v):
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("'update_url' must start with http:// or https://")
        return v


class DynamicTimingProbeVariantRequest(APIModel):
    params: Optional[dict] = None
    data: Optional[dict] = None
    json_body: Optional[dict] = None


class DynamicTimingComparisonProbeRequest(APIModel):
    """V11.2.5 — sends two fixed payload variants at the same endpoint
    repeatedly and checks whether response timing distinguishes them (a
    padding-oracle / timing-side-channel indicator). This scanner has no
    way to generate valid-vs-invalid-padding ciphertext for a target's own
    encryption scheme on its own — variant_a/variant_b are supplied by the
    tester, who already knows the scheme and has crafted (for example) a
    valid-padding-but-wrong-content ciphertext and an invalid-padding one.
    Neither variant is assumed to be the "expected" one; the probe only
    reports whether the two are timing-distinguishable at all."""

    scenario_id: str
    asvs_controls: list[str] = Field(default_factory=lambda: ["V11.2.5"])
    url: str
    method: str = "POST"
    session: str = "primary"
    variant_a: DynamicTimingProbeVariantRequest
    variant_b: DynamicTimingProbeVariantRequest
    headers: Optional[dict] = None
    samples: int = Field(7, ge=3, le=30)
    requires_active_mode: bool = True
    severity: str = "medium"

    @field_validator('method')
    @classmethod
    def validate_method(cls, v):
        allowed = {"GET", "POST", "PUT", "PATCH", "DELETE"}
        if v.upper() not in allowed:
            raise ValueError(f"'method' must be one of {sorted(allowed)}")
        return v.upper()

    @field_validator('session')
    @classmethod
    def validate_session_actor(cls, v):
        if v not in ("primary", "secondary"):
            raise ValueError("'session' must be 'primary' or 'secondary'")
        return v

    @field_validator('url')
    @classmethod
    def validate_url_scheme(cls, v):
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("'url' must start with http:// or https://")
        return v


class DynamicSignalingFuzzProbeRequest(APIModel):
    """V17.3.2 — sends a corpus of malformed offer/answer/ICE-candidate-
    shaped messages at a WebSocket signaling endpoint and checks whether a
    fresh handshake still succeeds immediately after each one. payloads
    defaults to a built-in corpus (websocket_fuzz_probe.
    DEFAULT_SIGNALING_FUZZ_PAYLOADS) covering the obvious failure classes
    (truncated JSON, type confusion, an oversized field, embedded control
    characters, a missing required field, ...) if not supplied — pass an
    empty list explicitly to opt out rather than omitting the field."""

    scenario_id: str
    asvs_controls: list[str] = Field(default_factory=lambda: ["V17.3.2"])
    url: str
    payloads: Optional[list[str]] = None
    headers: Optional[dict] = None
    requires_active_mode: bool = True
    severity: str = "high"

    @field_validator('url')
    @classmethod
    def validate_url_scheme(cls, v):
        if not (v.startswith("ws://") or v.startswith("wss://")):
            raise ValueError("'url' must start with ws:// or wss://")
        return v


class DynamicWebRtcConnectionRequest(APIModel):
    """One negotiated WebRTC peer connection, for the V17.2.x media-layer
    probes below. Exactly one of signaling_url (a WHIP-style exchange:
    this scanner POSTs its own offer SDP as `Content-Type: application/sdp`
    and expects the answer SDP back in the response body — a real,
    standardized shape a growing number of ingest/SFU endpoints speak
    natively) or remote_answer_sdp (the tester already completed the
    offer/answer exchange out-of-band and hands the resulting answer
    straight to this probe, for every other signaling shape) must be set."""

    signaling_url: Optional[str] = None
    signaling_headers: Optional[dict] = None
    remote_answer_sdp: Optional[str] = None
    ice_servers: list[str] = Field(default_factory=list)

    @field_validator('signaling_url')
    @classmethod
    def validate_signaling_url_scheme(cls, v):
        if v is not None and not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("'signaling_url' must start with http:// or https://")
        return v

    @model_validator(mode='after')
    def validate_exactly_one_signaling_method(self):
        if bool(self.signaling_url) == bool(self.remote_answer_sdp):
            raise ValueError("exactly one of 'signaling_url' or 'remote_answer_sdp' must be set")
        return self


class DynamicMediaFloodProbeRequest(APIModel):
    """V17.2.5/V17.2.7 — holds N other real, legitimate WebRTC sessions
    (flood_connections) open concurrently with one control_connection and
    flags it if the control session's own media stops flowing. The two
    controls are the same test from this scanner's vantage point; tag
    asvs_controls with V17.2.7 instead of the V17.2.5 default if
    control_connection points at a recording-enabled session specifically
    — this scanner can't tell "this session is being recorded" from the
    outside."""

    scenario_id: str
    asvs_controls: list[str] = Field(default_factory=lambda: ["V17.2.5"])
    control_connection: DynamicWebRtcConnectionRequest
    flood_connections: list[DynamicWebRtcConnectionRequest] = Field(..., min_length=1)
    hold_seconds: float = Field(5.0, ge=1.0, le=60.0)
    requires_active_mode: bool = True
    severity: str = "high"


class DynamicMalformedPacketProbeRequest(APIModel):
    """V17.2.4 — sends a corpus of malformed raw datagrams at the media
    transport (the same UDP association SRTP/DTLS/ICE already share) and
    checks whether the connection stays healthy. payloads are hex-encoded
    strings (raw bytes aren't JSON-safe); defaults to a built-in corpus
    (webrtc_probe.DEFAULT_MALFORMED_RTP_PAYLOADS) if not supplied — pass
    an empty list explicitly to opt out rather than omitting the field."""

    scenario_id: str
    asvs_controls: list[str] = Field(default_factory=lambda: ["V17.2.4"])
    connection: DynamicWebRtcConnectionRequest
    payloads: Optional[list[str]] = None
    requires_active_mode: bool = True
    severity: str = "critical"

    @field_validator('payloads')
    @classmethod
    def validate_payloads_are_hex(cls, v):
        if v is None:
            return v
        for entry in v:
            try:
                bytes.fromhex(entry)
            except ValueError:
                raise ValueError(f"payload {entry!r} is not valid hex")
        return v


class DynamicSrtpAuthProbeRequest(APIModel):
    """V17.2.3 — needs TWO connections (attacker + observer) because this
    scanner can't see the target server's own internal accept/reject
    state; the only generically observable signal is whether a forged
    packet gets RELAYED to the second connection, which only means
    anything against an SFU/mixer-style target. A baseline check (does a
    validly-authenticated forged packet get relayed at all) gates the real
    test automatically — see webrtc_probe.py's own docstring."""

    scenario_id: str
    asvs_controls: list[str] = Field(default_factory=lambda: ["V17.2.3"])
    attacker_connection: DynamicWebRtcConnectionRequest
    observer_connection: DynamicWebRtcConnectionRequest
    requires_active_mode: bool = True
    severity: str = "high"


class ScanStart(APIModel):
    # Direct code scan fields
    code: Optional[str] = Field(None, description="Direct code input (max 400 lines)")
    language: Optional[Language] = Field(None, description="Programming language for direct code")
    filename: Optional[str] = Field(None, description="Filename for direct code (e.g., app.py)")
    
    # Repository scan fields
    repo_id: Optional[int] = Field(None, description="Repository ID from database")
    branch: Optional[str] = Field("main", description="Git branch to scan")
    file_paths: Optional[list[str]] = Field(
        None,
        description="Optional list of repository file paths to scan (relative to repo root)",
    )
    
    # Common fields
    scan_type: ScanType = Field(
        ScanType.STATIC,
        description="Which engine(s) to run: static (default, needs code/repo_id), "
                    "dynamic (needs target_url, no code/repo_id required), or hybrid (both).",
    )
    scan_mode: ScanMode = Field(ScanMode.DEEP, description="Scan depth/mode")
    target_url: Optional[str] = Field(
        None,
        description="Optional live deployment URL — enables the ASVS dynamic-probe checks "
                    "(TLS version, HTTPS enforcement, certificate trust, live HSTS header, "
                    ".git/.svn exposure). Required when scan_type is 'dynamic' or 'hybrid'.",
    )
    dynamic_additional_target_urls: Optional[list[str]] = Field(
        None, max_length=10,
        description="Extra origins for a microservice app (crawler.py's same-origin rule means "
                    "target_url alone can never reach a sibling service on its own port) — swept "
                    "within this SAME scan and reported together, instead of needing a separate scan "
                    "per service. Each gets the same auth/active-mode/probe config as target_url; for "
                    "a hybrid scan, the static->dynamic bridge correlation (build_dynamic_targets) "
                    "runs against every one of them, not just target_url.",
    )

    # Dynamic-scan auth (Phase 1/2B) — only meaningful when scan_type is
    # 'dynamic'/'hybrid'. dynamic_bearer_token/dynamic_form_login.password are
    # never persisted: they're used in-memory for this scan's async worker only
    # (see app/domain/analysis/dast/config.py) and are not written to the scan
    # document, unlike a Repository's long-lived encrypted access_token.
    dynamic_auth_mode: AuthMode = Field(
        AuthMode.NONE,
        description="Auth mode for dynamic-scan checks that need an authenticated session "
                    "(e.g. the logout-invalidation scenario). 'bearer' requires dynamic_bearer_token; "
                    "'form_login' requires dynamic_form_login (optionally with csrf_field/"
                    "csrf_source_url for a CSRF-protected login); 'oauth2' requires dynamic_oauth2 "
                    "(client-credentials or password grant, auto-refreshed on 401); 'api_key' requires "
                    "dynamic_api_key_header and dynamic_api_key_value.",
    )
    dynamic_bearer_token: Optional[str] = Field(
        None, description="Bearer token, required when dynamic_auth_mode='bearer'. Never persisted."
    )
    dynamic_form_login: Optional[DynamicFormLoginRequest] = Field(
        None, description="Form-login credentials, required when dynamic_auth_mode='form_login'. Never persisted."
    )
    dynamic_oauth2: Optional[DynamicOAuth2Request] = Field(
        None, description="OAuth2 client-credentials/password grant config, required when "
                           "dynamic_auth_mode='oauth2'. Never persisted."
    )
    dynamic_api_key_header: Optional[str] = Field(
        None, description="Header name the static API key is sent under, required when "
                           "dynamic_auth_mode='api_key' (e.g. 'X-API-Key'). Never persisted."
    )
    dynamic_api_key_value: Optional[str] = Field(
        None, description="Static API key value, required when dynamic_auth_mode='api_key'. Never persisted."
    )
    dynamic_active_mode: bool = Field(
        False,
        description="Authorizes dynamic checks with side effects: request-smuggling probes and "
                    "cross-session/race scenarios. Checks/scenarios that need this report "
                    "'skipped_requires_active_authorization' when it's not set, rather than silently "
                    "not running.",
    )

    # Second actor (Phase: cross-session scenarios) — only meaningful together with
    # dynamic_active_mode for scenarios like credential-change-invalidates-sessions
    # (V7.4.3), which needs two concurrently held sessions for the same account to
    # confirm one session's action actually terminates the other.
    dynamic_second_actor_auth_mode: AuthMode = Field(
        AuthMode.NONE,
        description="Auth mode for a second, independent session (cross-session scenarios only). "
                    "Same requirements as dynamic_auth_mode.",
    )
    dynamic_second_actor_bearer_token: Optional[str] = Field(
        None, description="Bearer token for the second actor. Never persisted."
    )
    dynamic_second_actor_form_login: Optional[DynamicFormLoginRequest] = Field(
        None, description="Form-login credentials for the second actor. Never persisted."
    )
    dynamic_second_actor_oauth2: Optional[DynamicOAuth2Request] = Field(
        None, description="OAuth2 config for the second actor. Never persisted."
    )
    dynamic_second_actor_api_key_header: Optional[str] = Field(
        None, description="API key header name for the second actor. Never persisted."
    )
    dynamic_second_actor_api_key_value: Optional[str] = Field(
        None, description="API key value for the second actor. Never persisted."
    )
    dynamic_scenarios: Optional[list[DynamicScenarioRequest]] = Field(
        None, max_length=20,
        description="User-supplied multi-step scenarios for app-specific checks the engine can't "
                    "generically discover — e.g. V7.4.3 (credential change invalidates other "
                    "sessions: step 1 on 'primary', step 2 re-checking on 'secondary'), V8.3.2 "
                    "(permission revoke takes effect immediately), V2.3.1 (step-skipping). Each "
                    "runs through the session(s) configured via dynamic_auth_mode/"
                    "dynamic_second_actor_auth_mode. Capped at 20 per scan — each one is a real "
                    "side-effecting request sequence against the target.",
    )
    dynamic_race_probes: Optional[list[DynamicRaceProbeRequest]] = Field(
        None, max_length=20,
        description="User-supplied race/double-submit probes (V2.3.4) — fires N concurrent "
                    "requests at one endpoint and flags it if more succeed than expected. Capped "
                    "at 20 per scan, same reasoning as dynamic_scenarios.",
    )
    dynamic_idor_probes: Optional[list[DynamicIdorProbeRequest]] = Field(
        None, max_length=20,
        description="User-supplied cross-session IDOR/BOLA probes (V8.2.1) — the primary actor "
                    "requests a resource it owns, the second actor requests the same URL, and a "
                    "2xx for the second actor flags a missing ownership check. Requires "
                    "dynamic_second_actor_auth_mode to be configured. Capped at 20 per scan, same "
                    "reasoning as dynamic_scenarios.",
    )
    dynamic_mass_assignment_probes: Optional[list[DynamicMassAssignmentProbeRequest]] = Field(
        None, max_length=20,
        description="User-supplied mass-assignment probes (V15.3.3) — the primary actor submits an "
                    "unrequested privileged field (e.g. role=admin) on a normal-looking object-update "
                    "request, and the second actor independently re-reads the resource to confirm "
                    "whether it actually took. Requires dynamic_second_actor_auth_mode to be "
                    "configured. Capped at 20 per scan, same reasoning as dynamic_scenarios.",
    )
    dynamic_timing_probes: Optional[list[DynamicTimingComparisonProbeRequest]] = Field(
        None, max_length=20,
        description="User-supplied timing-side-channel probes (V11.2.5) — sends two tester-crafted "
                    "payload variants (e.g. valid-padding-but-wrong-content ciphertext vs. "
                    "invalid-padding ciphertext) at the same endpoint repeatedly and flags it if "
                    "response timing distinguishes them. This scanner can't generate valid ciphertext "
                    "for a target's own encryption scheme on its own, so both variants must be "
                    "supplied. Capped at 20 per scan, same reasoning as dynamic_scenarios.",
    )
    dynamic_signaling_fuzz_probes: Optional[list[DynamicSignalingFuzzProbeRequest]] = Field(
        None, max_length=20,
        description="User-supplied WebSocket signaling-server fuzz probes (V17.3.2) — sends a "
                    "corpus of malformed offer/answer/ICE-candidate-shaped messages at a WebSocket "
                    "signaling endpoint and flags it if a fresh handshake stops succeeding "
                    "immediately after one of them (evidence the server crashed or hung). Capped "
                    "at 20 per scan, same reasoning as dynamic_scenarios.",
    )
    dynamic_media_flood_probes: Optional[list[DynamicMediaFloodProbeRequest]] = Field(
        None, max_length=10,
        description="User-supplied WebRTC media-flood probes (V17.2.5/V17.2.7) — negotiates real "
                    "DTLS/SRTP peer connections (needs the aiortc dependency) and holds N other "
                    "legitimate sessions open concurrently with one control session, flagging it if "
                    "the control session's own media stops flowing. Capped at 10 per scan — each "
                    "one is N+1 real, held-open media sessions against the target.",
    )
    dynamic_malformed_packet_probes: Optional[list[DynamicMalformedPacketProbeRequest]] = Field(
        None, max_length=20,
        description="User-supplied WebRTC malformed-packet probes (V17.2.4) — sends a corpus of "
                    "malformed raw datagrams at the media transport and flags it if the connection "
                    "stops being healthy immediately after one of them. Capped at 20 per scan, same "
                    "reasoning as dynamic_scenarios.",
    )
    dynamic_srtp_auth_probes: Optional[list[DynamicSrtpAuthProbeRequest]] = Field(
        None, max_length=20,
        description="User-supplied SRTP authentication-enforcement probes (V17.2.3) — forges an "
                    "SRTP packet with a corrupted authentication tag and checks whether a second, "
                    "observing connection ever sees it relayed. Only meaningful against an "
                    "SFU/mixer-style target that relays media between sessions; degrades to "
                    "not_tested otherwise. Capped at 20 per scan, same reasoning as "
                    "dynamic_scenarios.",
    )
    dynamic_crawl_max_pages: Optional[int] = Field(
        None, ge=1, le=100,
        description="Override the crawler's default page-visit cap (10) for dynamic/hybrid scans. "
                    "Raise for larger target apps where the default under-discovers routes/forms.",
    )
    dynamic_crawl_max_depth: Optional[int] = Field(
        None, ge=0, le=5,
        description="Override the crawler's default link-following depth (2) for dynamic/hybrid scans.",
    )
    dynamic_state_crawl_max_forms: Optional[int] = Field(
        None, ge=1, le=30,
        description="Track C6 — override how many distinct discovered forms the state/form-transition "
                    "crawl submits (default 5) to reach post-submission pages (search results, checkout "
                    "steps, password-reset confirmation, ...) that a pure link-following crawl can't see. "
                    "Only runs when dynamic_active_mode is true — submitting a form is a real state change.",
    )
    dynamic_state_crawl_max_depth: Optional[int] = Field(
        None, ge=0, le=5,
        description="Override how many chained form submissions the state/form-transition crawl follows "
                    "(default 2) — e.g. login -> dashboard -> update-profile is depth 2.",
    )
    dynamic_rule_ids: Optional[list[str]] = Field(
        None, max_length=50,
        description="Restrict which payload-check rule_ids (e.g. 'OPEN_REDIRECT_LIVE', "
                    "'CSRF_TOKEN_NOT_VALIDATED') run against crawled/target URLs. Omit to run all of "
                    "them. Unknown rule_ids are silently ignored, same tolerance as a typo'd "
                    "dynamic_race_probes/dynamic_scenarios scenario_id.",
    )
    dynamic_ssrf_collaborator_host: Optional[str] = Field(
        None,
        description="Host the SSRF out-of-band collaborator listener binds to (V5.3.2). Defaults to "
                    "127.0.0.1 — only reachable from targets on the same host/network as the scanner. "
                    "To confirm SSRF against a real external target, this must be a publicly-reachable "
                    "host; standing up that listener is a deployment concern outside this API's scope. "
                    "Only used when dynamic_active_mode is true (the check is skipped otherwise).",
    )
    dynamic_ssrf_collaborator_port: Optional[int] = Field(
        None, ge=1, le=65535,
        description="Port for the SSRF collaborator listener. Defaults to an OS-assigned ephemeral port.",
    )
    dynamic_openapi_spec_url: Optional[str] = Field(
        None,
        description="URL of an OpenAPI/Swagger spec (JSON or YAML) to fetch and expand into testable "
                    "URLs (Track C3). Every discovered operation is folded into the same check_urls list "
                    "the crawler populates — API-first targets with little/no server-rendered HTML for "
                    "the crawler to follow become discoverable. Fetched through the same SSRF-guarded "
                    "session as every other request. Mutually exclusive with 'dynamic_openapi_spec'.",
    )
    dynamic_openapi_spec: Optional[str] = Field(
        None,
        description="Raw OpenAPI/Swagger spec text (JSON or YAML), supplied inline instead of a URL — "
                    "useful when the spec isn't served live by the target. Mutually exclusive with "
                    "'dynamic_openapi_spec_url'.",
    )
    enable_llm: bool = Field(
        True,
        description="Whether the static pipeline's LLM classification pass runs on flagged findings "
                    "(confidence scoring / natural-language explanation). Regex and taint/DFG detection "
                    "run identically either way — this only toggles the LLM enrichment step, which can "
                    "add substantial wall-clock time (one call per flagged finding, with provider "
                    "fallback/retry) on a large repository, especially if configured LLM providers are "
                    "unavailable/rate-limited. Ignored for scan_type='dynamic' (no static pipeline runs).",
    )
    dynamic_use_headless_browser: bool = Field(
        False,
        description="Track C2 — additionally crawl with a real headless Chromium (via Playwright) and "
                    "run a DOM-XSS probe (location.hash reflected unescaped into the DOM) against "
                    "discovered URLs. Needed for JS-rendered (SPA) targets the regex crawler can't see "
                    "into — its results are merged alongside the regex crawler's, never replacing them. "
                    "Requires the Chromium binary to be installed (`playwright install chromium`); "
                    "missing/broken browser support degrades this scan silently rather than failing it.",
    )

    @field_validator('target_url')
    @classmethod
    def validate_target_url_scheme(cls, v):
        if v is not None and not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("'target_url' must start with http:// or https://")
        return v

    @field_validator('dynamic_additional_target_urls')
    @classmethod
    def validate_additional_target_urls_scheme(cls, v):
        if v:
            for url in v:
                if not (url.startswith("http://") or url.startswith("https://")):
                    raise ValueError(f"'{url}' in dynamic_additional_target_urls must start with http:// or https://")
        return v

    @field_validator('code')
    @classmethod
    def validate_code_length(cls, v):
        if v is not None:
            line_count = len(v.split('\n'))
            if line_count > 400:
                raise ValueError(f"Code exceeds 400-line limit (got {line_count} lines)")
        return v

    @field_validator('repo_id')
    @classmethod
    def validate_input_mode(cls, v, info):
        code = info.data.get('code')
        # Either code OR repo_id must be provided, not both
        if code and v:
            raise ValueError("Provide either 'code' or 'repo_id', not both")
        return v

    # model_validator(mode="after") — not field_validator — because these are
    # cross-field requirement checks that must fire even when the field being
    # required is omitted entirely (field_validators don't run on unset defaults).
    @model_validator(mode='after')
    def validate_scan_type_requirements(self):
        if self.scan_type == ScanType.DYNAMIC:
            if not self.target_url:
                raise ValueError("'target_url' is required when scan_type is 'dynamic'")
        else:
            if self.scan_type == ScanType.HYBRID and not self.target_url:
                raise ValueError("'target_url' is required when scan_type is 'hybrid'")
            if not self.code and not self.repo_id:
                raise ValueError("Either 'code' or 'repo_id' must be provided")
        return self

    @model_validator(mode='after')
    def validate_dynamic_auth_requirements(self):
        if self.dynamic_auth_mode == AuthMode.BEARER and not self.dynamic_bearer_token:
            raise ValueError("'dynamic_bearer_token' is required when dynamic_auth_mode is 'bearer'")
        if self.dynamic_auth_mode == AuthMode.FORM_LOGIN and not self.dynamic_form_login:
            raise ValueError("'dynamic_form_login' is required when dynamic_auth_mode is 'form_login'")
        if self.dynamic_auth_mode == AuthMode.OAUTH2 and not self.dynamic_oauth2:
            raise ValueError("'dynamic_oauth2' is required when dynamic_auth_mode is 'oauth2'")
        if self.dynamic_auth_mode == AuthMode.API_KEY and not (
            self.dynamic_api_key_header and self.dynamic_api_key_value
        ):
            raise ValueError(
                "'dynamic_api_key_header' and 'dynamic_api_key_value' are both required when "
                "dynamic_auth_mode is 'api_key'"
            )
        if self.dynamic_second_actor_auth_mode == AuthMode.BEARER and not self.dynamic_second_actor_bearer_token:
            raise ValueError(
                "'dynamic_second_actor_bearer_token' is required when "
                "dynamic_second_actor_auth_mode is 'bearer'"
            )
        if self.dynamic_second_actor_auth_mode == AuthMode.FORM_LOGIN and not self.dynamic_second_actor_form_login:
            raise ValueError(
                "'dynamic_second_actor_form_login' is required when "
                "dynamic_second_actor_auth_mode is 'form_login'"
            )
        if self.dynamic_second_actor_auth_mode == AuthMode.OAUTH2 and not self.dynamic_second_actor_oauth2:
            raise ValueError(
                "'dynamic_second_actor_oauth2' is required when dynamic_second_actor_auth_mode is 'oauth2'"
            )
        if self.dynamic_second_actor_auth_mode == AuthMode.API_KEY and not (
            self.dynamic_second_actor_api_key_header and self.dynamic_second_actor_api_key_value
        ):
            raise ValueError(
                "'dynamic_second_actor_api_key_header' and 'dynamic_second_actor_api_key_value' are both "
                "required when dynamic_second_actor_auth_mode is 'api_key'"
            )
        return self

    @model_validator(mode='after')
    def validate_openapi_spec_source(self):
        if self.dynamic_openapi_spec_url and self.dynamic_openapi_spec:
            raise ValueError(
                "Provide either 'dynamic_openapi_spec_url' or 'dynamic_openapi_spec', not both — "
                "ambiguous which one should win"
            )
        return self

    @field_validator('file_paths')
    @classmethod
    def validate_file_paths_for_repo(cls, v, info):
        if v:
            if info.data.get('code'):
                raise ValueError("'file_paths' cannot be used with direct code scans")
            if not info.data.get('repo_id'):
                raise ValueError("'file_paths' requires 'repo_id'")
        return v
    
    @field_validator('language')
    @classmethod
    def validate_language_for_code(cls, v, info):
        code = info.data.get('code')
        if code and not v:
            raise ValueError("'language' is required when providing direct code")
        return v


class ProbeDiscoveryRequest(APIModel):
    """Track: probe auto-discovery — drives probe_discovery.py's GET sweep
    ahead of an actual scan, so the GUI can pre-fill IDOR/mass-assignment
    candidates for the user to review instead of hand-typing resource URLs.
    Same auth shape as ScanStart's dynamic_* fields (primary + optional
    second actor), just without everything else a real scan needs."""

    target_urls: list[str] = Field(..., min_length=1, max_length=10)

    repo_id: Optional[int] = Field(
        None,
        description="Optional repository ID — when provided, the repo is briefly cloned to run the same "
                    "source-route discovery a hybrid scan uses (bridge.py's discover_routes_from_source), "
                    "so a pure-JSON API with no crawlable HTML/OpenAPI spec (its real endpoints live at "
                    "target_url + a sub-path, e.g. /orders, never visible from a bare-origin GET) still "
                    "surfaces its resource-list endpoints instead of finding nothing.",
    )
    repo_branch: str = "main"

    dynamic_auth_mode: AuthMode = AuthMode.NONE
    dynamic_bearer_token: Optional[str] = None
    dynamic_form_login: Optional[DynamicFormLoginRequest] = None
    dynamic_oauth2: Optional[DynamicOAuth2Request] = None
    dynamic_api_key_header: Optional[str] = None
    dynamic_api_key_value: Optional[str] = None

    dynamic_second_actor_auth_mode: AuthMode = AuthMode.NONE
    dynamic_second_actor_bearer_token: Optional[str] = None
    dynamic_second_actor_form_login: Optional[DynamicFormLoginRequest] = None
    dynamic_second_actor_oauth2: Optional[DynamicOAuth2Request] = None
    dynamic_second_actor_api_key_header: Optional[str] = None
    dynamic_second_actor_api_key_value: Optional[str] = None

    @field_validator('target_urls')
    @classmethod
    def validate_target_urls_scheme(cls, v):
        for url in v:
            if not (url.startswith("http://") or url.startswith("https://")):
                raise ValueError(f"'{url}' must start with http:// or https://")
        return v


class IdorCandidateRead(APIModel):
    scenario_id: str
    owner_resource_url: str
    method: str = "GET"
    source_url: str = ""


class MassAssignmentCandidateRead(APIModel):
    scenario_id: str
    update_url: str
    update_method: str = "PUT"
    injected_field: str
    injected_value: object
    source_url: str = ""


class ProbeDiscoveryResponse(APIModel):
    idor_candidates: list[IdorCandidateRead] = Field(default_factory=list)
    mass_assignment_candidates: list[MassAssignmentCandidateRead] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class ScanResponse(APIModel):
    scan_id: str = Field(..., description="Unique scan identifier for polling")
    status: str = Field("PENDING", description="Initial scan status")
    message: str = Field("Scan initiated successfully")
    input_type: str = Field(..., description="DIRECT_CODE or REPOSITORY")
    user_id: str = Field(..., description="ID of the user who initiated the scan")
    created_at: str = Field(..., description="ISO timestamp of scan creation")


class ScanStatusRead(APIModel):
    scan_id: str
    user_id: str
    state: str
    progress: int
    eta: int | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    current_file: str | None = None
    files_scanned: int = 0
    total_files: int = 0
    # Dynamic/DAST phase telemetry (Track: live dynamic scan viewer) — mirrors
    # current_file/files_scanned's role for the static phase, but for the
    # DAST checks (crawl, payload checks, JWT/SSRF/mass-assignment probes,
    # etc.) that run after/alongside it. current_dynamic_action is the
    # human-readable checkpoint _run_dynamic_checks last announced (e.g.
    # "Running payload checks across 6 URL(s)..."); dynamic_findings_count
    # is a running tally so the count visibly grows mid-scan instead of only
    # appearing once at COMPLETED.
    current_dynamic_action: str | None = None
    dynamic_findings_count: int = 0
    target_url: str | None = None
    scan_type: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class ScanSummary(APIModel):
    scan_id: str
    user_id: str
    status: str
    input_type: str
    total_files: int
    files_scanned: int
    vulnerabilities_found: int
    by_severity: dict
    duration_seconds: float
    created_at: str
    completed_at: Optional[str] = None
    vulnerabilities: Optional[list] = None  # Add vulnerabilities list
    scanned_files: Optional[list[str]] = None
    config_findings: Optional[list] = None
    dependency_findings: Optional[list] = None
    dependency_control_result: Optional[dict] = None
    capability_findings: Optional[list] = None
    dynamic_probe_findings: Optional[list] = None
    dynamic_findings: Optional[list] = None
    discovered_forms: Optional[list] = None
