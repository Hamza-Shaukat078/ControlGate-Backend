from datetime import datetime
from typing import Optional
from pydantic import Field, field_validator
from enum import Enum
from app.schemas.common import APIModel


class ScanMode(str, Enum):
    QUICK = "QUICK"
    DEEP = "DEEP"
    FULL = "FULL"


class Language(str, Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
   


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
    scan_mode: ScanMode = Field(ScanMode.DEEP, description="Scan depth/mode")
    target_url: Optional[str] = Field(
        None,
        description="Optional live deployment URL — enables the ASVS dynamic-probe checks "
                    "(TLS version, HTTPS enforcement, certificate trust, live HSTS header, "
                    ".git/.svn exposure). Skipped entirely when not provided.",
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
        if not code and not v:
            raise ValueError("Either 'code' or 'repo_id' must be provided")
        return v

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
