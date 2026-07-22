"""
Unit tests — app/core/security.py

Covers: password hashing, password verification, JWT creation/decoding,
token expiry, extra claims, tampered-token rejection.
"""
import time
import pytest
from jose import JWTError

from app.core.security import (
    get_password_hash,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    create_token,
)
from app.core.config import settings


# ── Password hashing ──────────────────────────────────────────────────────────

class TestPasswordHashing:
    def test_hash_is_not_plaintext(self):
        h = get_password_hash("secret123")
        assert h != "secret123"

    def test_hash_starts_with_bcrypt_prefix(self):
        h = get_password_hash("secret123")
        assert h.startswith("$2b$") or h.startswith("$2a$")

    def test_same_password_different_hashes(self):
        # bcrypt salts each hash
        h1 = get_password_hash("password")
        h2 = get_password_hash("password")
        assert h1 != h2

    def test_verify_correct_password(self):
        h = get_password_hash("correct_horse")
        assert verify_password("correct_horse", h) is True

    def test_verify_wrong_password(self):
        h = get_password_hash("correct_horse")
        assert verify_password("wrong_horse", h) is False

    def test_verify_empty_password_fails(self):
        h = get_password_hash("notempty")
        assert verify_password("", h) is False

    def test_hash_empty_string(self):
        h = get_password_hash("")
        assert verify_password("", h) is True

    def test_unicode_password(self):
        pw = "pässwörد🔑"
        h = get_password_hash(pw)
        assert verify_password(pw, h) is True
        assert verify_password("passw", h) is False


# ── JWT creation ──────────────────────────────────────────────────────────────

class TestJWTCreation:
    def test_access_token_is_string(self):
        token = create_access_token("user-123")
        assert isinstance(token, str)
        assert len(token) > 20

    def test_token_contains_subject(self):
        token = create_access_token("user-abc")
        payload = decode_token(token)
        assert payload["sub"] == "user-abc"

    def test_integer_subject_coerced_to_string(self):
        token = create_access_token(42)
        payload = decode_token(token)
        assert payload["sub"] == "42"

    def test_extra_claims_present_in_payload(self):
        token = create_access_token("u1", extra_claims={"role": "admin"})
        payload = decode_token(token)
        assert payload["role"] == "admin"

    def test_multiple_extra_claims(self):
        token = create_access_token("u1", extra_claims={"role": "premium", "org": "acme"})
        payload = decode_token(token)
        assert payload["role"] == "premium"
        assert payload["org"] == "acme"

    def test_access_token_has_iat_and_exp(self):
        token = create_access_token("u1")
        payload = decode_token(token)
        assert "iat" in payload
        assert "exp" in payload
        assert payload["exp"] > payload["iat"]

    def test_exp_is_in_future(self):
        token = create_access_token("u1")
        payload = decode_token(token)
        assert payload["exp"] > int(time.time())

    def test_refresh_token_has_longer_expiry_than_access(self):
        access = create_access_token("u1")
        refresh = create_refresh_token("u1")
        a_exp = decode_token(access)["exp"]
        r_exp = decode_token(refresh)["exp"]
        assert r_exp > a_exp

    def test_custom_expiry_minutes(self):
        token = create_token("u1", expires_minutes=1)
        payload = decode_token(token)
        remaining = payload["exp"] - int(time.time())
        assert 0 < remaining <= 60 + 5  # allow 5s clock skew


# ── JWT decoding & validation ─────────────────────────────────────────────────

class TestJWTDecoding:
    def test_valid_token_decodes(self):
        token = create_access_token("user-xyz")
        payload = decode_token(token)
        assert payload["sub"] == "user-xyz"

    def test_tampered_token_raises(self):
        token = create_access_token("user-xyz")
        tampered = token[:-5] + "XXXXX"
        with pytest.raises(JWTError):
            decode_token(tampered)

    def test_wrong_secret_raises(self):
        from jose import jwt as _jwt
        fake_token = _jwt.encode(
            {"sub": "hacker", "exp": int(time.time()) + 3600},
            "wrong-secret",
            algorithm=settings.JWT_ALGORITHM,
        )
        with pytest.raises(JWTError):
            decode_token(fake_token)

    def test_expired_token_raises(self):
        token = create_token("u1", expires_minutes=-1)  # already expired
        with pytest.raises(JWTError):
            decode_token(token)

    def test_malformed_token_raises(self):
        with pytest.raises(JWTError):
            decode_token("this.is.not.a.jwt")

    def test_empty_token_raises(self):
        with pytest.raises(JWTError):
            decode_token("")
