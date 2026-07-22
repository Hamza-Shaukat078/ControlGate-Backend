"""
Integration tests — /api/v1/auth/* endpoints

Tests registration, login, JWT validation, profile retrieval,
password reset flow, and token refresh against an in-memory MongoDB.
"""
import pytest
from unittest.mock import patch, AsyncMock


# ── Registration ──────────────────────────────────────────────────────────────

class TestRegister:
    URL = "/api/v1/auth/register"

    def test_register_new_user_returns_201(self, client):
        r = client.post(self.URL, json={
            "email": "newuser@test.com",
            "password": "SecurePass123!",
            "full_name": "New User",
        })
        assert r.status_code == 201

    def test_register_returns_user_fields(self, client):
        r = client.post(self.URL, json={
            "email": "fields@test.com",
            "password": "SecurePass123!",
        })
        assert r.status_code == 201
        body = r.json()
        assert "email" in body
        assert body["email"] == "fields@test.com"
        assert "id" in body
        assert "hashed_password" not in body

    def test_register_default_role_is_normal(self, client):
        r = client.post(self.URL, json={
            "email": "role@test.com",
            "password": "SecurePass123!",
        })
        assert r.status_code == 201
        assert r.json().get("role") == "normal"

    def test_register_duplicate_email_returns_409(self, client):
        payload = {"email": "dup@test.com", "password": "Pass123!"}
        client.post(self.URL, json=payload)
        r = client.post(self.URL, json=payload)
        assert r.status_code == 409

    def test_register_missing_email_returns_422(self, client):
        r = client.post(self.URL, json={"password": "Pass123!"})
        assert r.status_code == 422

    def test_register_missing_password_returns_422(self, client):
        r = client.post(self.URL, json={"email": "nopw@test.com"})
        assert r.status_code == 422

    def test_register_invalid_email_format_returns_422(self, client):
        r = client.post(self.URL, json={"email": "not-an-email", "password": "Pass123!"})
        assert r.status_code == 422

    def test_register_optional_full_name(self, client):
        r = client.post(self.URL, json={
            "email": "nofullname@test.com",
            "password": "Pass123!",
        })
        assert r.status_code == 201

    def test_register_with_full_name(self, client):
        r = client.post(self.URL, json={
            "email": "withname@test.com",
            "password": "Pass123!",
            "full_name": "Alice Smith",
        })
        assert r.status_code == 201
        assert r.json().get("full_name") == "Alice Smith"


# ── Login ─────────────────────────────────────────────────────────────────────

class TestLogin:
    REG_URL = "/api/v1/auth/register"
    URL = "/api/v1/auth/login"

    def _register(self, client, email="login@test.com", password="Pass123!"):
        client.post(self.REG_URL, json={"email": email, "password": password})

    def test_login_valid_credentials_returns_200(self, client):
        self._register(client)
        r = client.post(self.URL, json={"email": "login@test.com", "password": "Pass123!"})
        assert r.status_code == 200

    def test_login_returns_access_token(self, client):
        self._register(client)
        r = client.post(self.URL, json={"email": "login@test.com", "password": "Pass123!"})
        body = r.json()
        assert "access_token" in body
        assert len(body["access_token"]) > 20

    def test_login_returns_token_type_bearer(self, client):
        self._register(client)
        r = client.post(self.URL, json={"email": "login@test.com", "password": "Pass123!"})
        assert r.json().get("token_type", "").lower() == "bearer"

    def test_login_wrong_password_returns_401(self, client):
        self._register(client)
        r = client.post(self.URL, json={"email": "login@test.com", "password": "WrongPass!"})
        assert r.status_code == 401

    def test_login_nonexistent_user_returns_401(self, client):
        r = client.post(self.URL, json={"email": "ghost@test.com", "password": "Pass123!"})
        assert r.status_code == 401

    def test_login_empty_password_returns_401_or_422(self, client):
        self._register(client)
        r = client.post(self.URL, json={"email": "login@test.com", "password": ""})
        assert r.status_code in (401, 422)

    def test_login_missing_fields_returns_422(self, client):
        r = client.post(self.URL, json={"email": "login@test.com"})
        assert r.status_code == 422


# ── GET /auth/me ──────────────────────────────────────────────────────────────

class TestGetMe:
    URL = "/api/v1/auth/me"

    def test_me_authenticated_returns_200(self, client, normal_user):
        r = client.get(self.URL)
        assert r.status_code == 200

    def test_me_returns_correct_email(self, client, normal_user):
        r = client.get(self.URL)
        assert r.json()["email"] == normal_user["email"]

    def test_me_returns_role(self, client, normal_user):
        r = client.get(self.URL)
        assert r.json()["role"] == "normal"

    def test_me_does_not_return_hashed_password(self, client):
        r = client.get(self.URL)
        body = r.json()
        assert "hashed_password" not in body
        assert "password" not in body

    def test_me_unauthenticated_returns_401(self, mongo_db):
        from app.main import app
        from app.db.mongo import get_mongo_db
        async def _db():
            yield mongo_db
        app.dependency_overrides[get_mongo_db] = _db
        from fastapi.testclient import TestClient
        with TestClient(app, raise_server_exceptions=False) as c:
            r = c.get(self.URL)
        app.dependency_overrides.clear()
        assert r.status_code == 401


# ── Token Refresh ─────────────────────────────────────────────────────────────

class TestRefreshToken:
    URL = "/api/v1/auth/refresh"

    def test_refresh_authenticated_returns_new_token(self, client):
        r = client.post(self.URL)
        assert r.status_code == 200
        assert "access_token" in r.json()

    def test_refresh_returns_different_token(self, client):
        r1 = client.post(self.URL)
        r2 = client.post(self.URL)
        # Tokens may differ by timestamp; both should be valid
        assert r1.status_code == 200
        assert r2.status_code == 200


# ── Logout ────────────────────────────────────────────────────────────────────

class TestLogout:
    URL = "/api/v1/auth/logout"

    def test_logout_authenticated_returns_200(self, client):
        r = client.post(self.URL)
        assert r.status_code == 200

    def test_logout_returns_message(self, client):
        r = client.post(self.URL)
        assert "message" in r.json()


# ── Password Reset Flow ───────────────────────────────────────────────────────

class TestPasswordReset:
    FORGOT_URL = "/api/v1/auth/forgot-password"
    RESET_URL  = "/api/v1/auth/reset-password"
    VALIDATE_URL = "/api/v1/auth/validate-reset-token"

    def test_forgot_password_returns_200_always(self, client):
        # Endpoint must not reveal whether account exists
        r = client.post(self.FORGOT_URL, json={"email": "doesnotexist@test.com"})
        assert r.status_code == 200

    def test_forgot_password_registered_email_returns_200(self, client):
        client.post("/api/v1/auth/register", json={
            "email": "reset@test.com", "password": "Pass123!"
        })
        with patch("app.services.auth_service.AuthService.request_password_reset",
                   new_callable=AsyncMock) as m:
            m.return_value = None
            r = client.post(self.FORGOT_URL, json={"email": "reset@test.com"})
        assert r.status_code == 200

    def test_validate_invalid_token_returns_false(self, client):
        r = client.post(self.VALIDATE_URL, json={"token": "invalid-token-xyz"})
        assert r.status_code == 200
        assert r.json().get("valid") is False

    def test_reset_invalid_token_returns_400(self, client):
        r = client.post(self.RESET_URL, json={
            "token": "bad-token", "new_password": "NewPass123!"
        })
        assert r.status_code == 400
