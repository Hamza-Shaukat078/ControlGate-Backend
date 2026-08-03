"""
Settings validation tests.

JWT_SECRET used to default to a hardcoded "change-me-super-secret" value, then
later to an empty string with nothing enforcing it actually gets set. It signs
every auth token and (via app/core/crypto.py, which derives its Fernet key
from this same value) is also the repository-token encryption key — an empty
secret means both fall back to a key derived from "", a fixed, publicly known
value. Settings now fails fast at startup instead of booting insecurely.
"""
import pytest
from pydantic import ValidationError

from app.core.config import Settings


def _settings(**overrides) -> Settings:
    # _env_file=None skips loading the repo's real .env, so these tests are
    # independent of whatever secret happens to be configured locally.
    return Settings(_env_file=None, JWT_SECRET="a-real-secret-value", **overrides)


class TestJwtSecretRequired:
    def test_empty_jwt_secret_rejected(self):
        with pytest.raises(ValidationError, match="JWT_SECRET must be set"):
            Settings(_env_file=None, JWT_SECRET="")

    def test_whitespace_only_jwt_secret_rejected(self):
        with pytest.raises(ValidationError, match="JWT_SECRET must be set"):
            Settings(_env_file=None, JWT_SECRET="   ")

    def test_missing_jwt_secret_rejected(self, monkeypatch):
        # No JWT_SECRET kwarg at all — falls back to the field default (""),
        # which must also fail rather than silently booting. Importing
        # app.core.config anywhere in the process (as pytest collection
        # already has, transitively) leaves JWT_SECRET sitting in os.environ
        # as a side effect of python-dotenv's .env loading, so _env_file=None
        # alone isn't enough here — the env var itself has to be cleared too.
        monkeypatch.delenv("JWT_SECRET", raising=False)
        with pytest.raises(ValidationError, match="JWT_SECRET must be set"):
            Settings(_env_file=None)

    def test_real_jwt_secret_accepted(self):
        settings = _settings()
        assert settings.JWT_SECRET == "a-real-secret-value"
