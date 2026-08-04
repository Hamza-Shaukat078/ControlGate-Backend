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

    @field_validator('login_url')
    @classmethod
    def validate_login_url_scheme(cls, v):
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("'login_url' must start with http:// or https://")
        return v


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

    # Dynamic-scan auth (Phase 1/2B) — only meaningful when scan_type is
    # 'dynamic'/'hybrid'. dynamic_bearer_token/dynamic_form_login.password are
    # never persisted: they're used in-memory for this scan's async worker only
    # (see app/domain/analysis/dast/config.py) and are not written to the scan
    # document, unlike a Repository's long-lived encrypted access_token.
    dynamic_auth_mode: AuthMode = Field(
        AuthMode.NONE,
        description="Auth mode for dynamic-scan checks that need an authenticated session "
                    "(e.g. the logout-invalidation scenario). 'bearer' requires dynamic_bearer_token; "
                    "'form_login' requires dynamic_form_login.",
    )
    dynamic_bearer_token: Optional[str] = Field(
        None, description="Bearer token, required when dynamic_auth_mode='bearer'. Never persisted."
    )
    dynamic_form_login: Optional[DynamicFormLoginRequest] = Field(
        None, description="Form-login credentials, required when dynamic_auth_mode='form_login'. Never persisted."
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
    dynamic_scenarios: Optional[list[DynamicScenarioRequest]] = Field(
        None,
        description="User-supplied multi-step scenarios for app-specific checks the engine can't "
                    "generically discover — e.g. V7.4.3 (credential change invalidates other "
                    "sessions: step 1 on 'primary', step 2 re-checking on 'secondary'), V8.3.2 "
                    "(permission revoke takes effect immediately), V2.3.1 (step-skipping). Each "
                    "runs through the session(s) configured via dynamic_auth_mode/"
                    "dynamic_second_actor_auth_mode.",
    )
    dynamic_race_probes: Optional[list[DynamicRaceProbeRequest]] = Field(
        None,
        description="User-supplied race/double-submit probes (V2.3.4) — fires N concurrent "
                    "requests at one endpoint and flags it if more succeed than expected.",
    )

    @field_validator('target_url')
    @classmethod
    def validate_target_url_scheme(cls, v):
        if v is not None and not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("'target_url' must start with http:// or https://")
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
    dynamic_findings: Optional[list] = None
    discovered_forms: Optional[list] = None
