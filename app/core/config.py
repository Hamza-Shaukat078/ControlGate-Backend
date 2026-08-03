from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False, extra="ignore")

    ENV: str = Field(default="dev")
    API_V1_STR: str = Field(default="/api/v1")
    PROJECT_NAME: str = Field(default="VULCAN API")

    # Number of reverse-proxy hops in front of this app that are trusted to
    # append an honest entry to X-Forwarded-For (e.g. 1 nginx). 0 (default) —
    # never trust XFF; rate limiting keys on the direct socket peer address
    # only. Blindly trusting XFF without knowing the real proxy topology lets
    # a client set an arbitrary claimed IP and dodge the limit (the same
    # SPOOFABLE_PROXY_HEADER risk this scanner itself flags elsewhere) — only
    # raise this above 0 if the deployment actually sits behind that many
    # trusted proxies.
    TRUSTED_PROXY_HOP_COUNT: int = Field(default=0)
    BACKEND_CORS_ORIGINS: str = Field(default="http://localhost:3000")

    DATABASE_URL: str = Field(default="sqlite+aiosqlite:///./vulcan.db")

    MONGO_URI: str = Field(default="")
    MONGO_HOST: str = Field(default="localhost")
    MONGO_PORT: int = Field(default=27017)
    MONGO_DB_NAME: str = Field(default="vulcan")
    MONGO_USER: str = Field(default="")
    MONGO_PASSWORD: str = Field(default="")

    JWT_SECRET: str = Field(default="")
    JWT_ALGORITHM: str = Field(default="HS256")

    @field_validator("JWT_SECRET")
    @classmethod
    def _require_jwt_secret(cls, v: str) -> str:
        # JWT_SECRET signs every access/refresh token AND (via crypto.py, which
        # derives its Fernet key from this same value) is the encryption key
        # for repository access tokens at rest. An empty default here used to
        # be silently accepted; if the env var is ever missing in some
        # deployment, both of those would fall back to a key derived from the
        # empty string — a fixed, publicly known value. Fail startup instead
        # of booting insecurely.
        if not v or not v.strip():
            raise ValueError(
                "JWT_SECRET must be set — it signs auth tokens and derives the "
                "repository-token encryption key. Set it in .env or the "
                "environment before starting the app."
            )
        return v

    JWT_ISSUER: str = Field(default="controlgate-api")
    JWT_AUDIENCE: str = Field(default="controlgate-users")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=60)
    REFRESH_TOKEN_EXPIRE_MINUTES: int = Field(default=43200)

    DEFAULT_ADMIN_EMAIL: str = Field(default="admin@vulcan.ai")
    DEFAULT_ADMIN_PASSWORD: str = Field(default="")

    FRONTEND_BASE_URL: str = Field(default="http://localhost:3000")
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = Field(default=30)

    SMTP_HOST: str = Field(default="")
    SMTP_PORT: int = Field(default=587)
    SMTP_USER: str = Field(default="")
    SMTP_PASSWORD: str = Field(default="")
    SMTP_USE_TLS: bool = Field(default=True)
    SMTP_FROM_EMAIL: str = Field(default="")
    SMTP_FROM_NAME: str = Field(default="Vulcan Security")

    SENDGRID_API_KEY: str = Field(default="")

    GOOGLE_OAUTH_CLIENT_ID: str = Field(default="")
    GOOGLE_OAUTH_CLIENT_SECRET: str = Field(default="")
    GOOGLE_OAUTH_REDIRECT_URI: str = Field(default="http://localhost:8000/api/v1/auth/oauth/google/callback")
    FRONTEND_OAUTH_REDIRECT_URL: str = Field(default="http://localhost:3000/oauth/callback")

    GITHUB_OAUTH_CLIENT_ID: str = Field(default="")
    GITHUB_OAUTH_CLIENT_SECRET: str = Field(default="")
    GITHUB_OAUTH_REDIRECT_URI: str = Field(default="http://localhost:8000/api/v1/auth/oauth/github/callback")

    REPO_STORAGE_DIR: str = Field(default="repo_uploads")
    ATTESTATION_EVIDENCE_DIR: str = Field(default="attestation_evidence")

    ENABLE_LLM: bool = Field(default=True)
    LLM_PROVIDER: str = Field(default="github")
    LLM_API_KEY: str = Field(default="")
    LLM_BASE_URL: str = Field(default="")
    LLM_MODEL_CLASSIFIER: str = Field(default="gpt-4o-mini")


settings = Settings()

# Ensure LLM-related settings are available via os.environ for non-settings consumers.
import os as _os
_os.environ.setdefault("ENABLE_LLM", "true" if settings.ENABLE_LLM else "false")
if settings.LLM_PROVIDER:
    _os.environ.setdefault("LLM_PROVIDER", settings.LLM_PROVIDER)
if settings.LLM_API_KEY:
    _os.environ.setdefault("LLM_API_KEY", settings.LLM_API_KEY)
if settings.LLM_BASE_URL:
    _os.environ.setdefault("LLM_BASE_URL", settings.LLM_BASE_URL)
if settings.LLM_MODEL_CLASSIFIER:
    _os.environ.setdefault("LLM_MODEL_CLASSIFIER", settings.LLM_MODEL_CLASSIFIER)
