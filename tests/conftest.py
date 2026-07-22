"""
Shared fixtures for all Vulcan backend tests.

MongoDB is mocked with mongomock so no real database connection is needed.
FastAPI dependency overrides swap out get_mongo_db and get_current_user.
"""
from __future__ import annotations

import pytest
import mongomock
from datetime import datetime, timezone
from bson import ObjectId
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, MagicMock, patch

from app.core.security import get_password_hash, create_access_token


# ── In-memory MongoDB via mongomock ───────────────────────────────────────────

@pytest.fixture(scope="session")
def mongo_client():
    return mongomock.MongoClient()


@pytest.fixture
def mongo_db(mongo_client):
    db = mongo_client["vulcan_test"]
    yield db
    # Wipe all collections between tests
    for name in db.list_collection_names():
        db[name].drop()


# ── Pre-built user documents ──────────────────────────────────────────────────

def _make_user(role: str, email: str | None = None) -> dict:
    uid = ObjectId()
    return {
        "_id": uid,
        "id": str(uid),
        "email": email or f"{role}@vulcan.test",
        "full_name": f"{role.title()} User",
        "hashed_password": get_password_hash("TestPass123!"),
        "role": role,
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
    }


@pytest.fixture
def normal_user(mongo_db):
    doc = _make_user("normal")
    mongo_db.users.insert_one(doc)
    return doc


@pytest.fixture
def premium_user(mongo_db):
    doc = _make_user("premium")
    mongo_db.users.insert_one(doc)
    return doc


@pytest.fixture
def admin_user(mongo_db):
    doc = _make_user("admin")
    mongo_db.users.insert_one(doc)
    return doc


# ── JWT helpers ───────────────────────────────────────────────────────────────

def auth_headers(user: dict) -> dict:
    token = create_access_token(subject=user["id"], extra_claims={"role": user["role"]})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def normal_headers(normal_user):
    return auth_headers(normal_user)


@pytest.fixture
def premium_headers(premium_user):
    return auth_headers(premium_user)


@pytest.fixture
def admin_headers(admin_user):
    return auth_headers(admin_user)


# ── FastAPI test client with dependency overrides ─────────────────────────────

@pytest.fixture
def client(mongo_db, normal_user):
    from app.main import app
    from app.db.mongo import get_mongo_db
    from app.api.deps import get_current_user

    async def _db():
        yield mongo_db

    async def _user():
        return normal_user

    app.dependency_overrides[get_mongo_db] = _db
    app.dependency_overrides[get_current_user] = _user

    with TestClient(app, raise_server_exceptions=False) as c:
        yield c

    app.dependency_overrides.clear()


@pytest.fixture
def admin_client(mongo_db, admin_user):
    from app.main import app
    from app.db.mongo import get_mongo_db
    from app.api.deps import get_current_user

    async def _db():
        yield mongo_db

    async def _user():
        return admin_user

    app.dependency_overrides[get_mongo_db] = _db
    app.dependency_overrides[get_current_user] = _user

    with TestClient(app, raise_server_exceptions=False) as c:
        yield c

    app.dependency_overrides.clear()


@pytest.fixture
def premium_client(mongo_db, premium_user):
    from app.main import app
    from app.db.mongo import get_mongo_db
    from app.api.deps import get_current_user

    async def _db():
        yield mongo_db

    async def _user():
        return premium_user

    app.dependency_overrides[get_mongo_db] = _db
    app.dependency_overrides[get_current_user] = _user

    with TestClient(app, raise_server_exceptions=False) as c:
        yield c

    app.dependency_overrides.clear()


# ── Sample scan document ──────────────────────────────────────────────────────

@pytest.fixture
def sample_scan(mongo_db, normal_user):
    scan_id = "scan-test-abc123"
    doc = {
        "_id": ObjectId(),
        "scan_id": scan_id,
        "user_id": str(normal_user["_id"]),
        "status": "COMPLETED",
        "input_type": "CODE",
        "total_files": 1,
        "files_scanned": 1,
        "vulnerabilities_found": 3,
        "duration_seconds": 5.2,
        "created_at": datetime.now(timezone.utc),
        "completed_at": datetime.now(timezone.utc),
        "summary": {
            "vulnerabilities": [
                {
                    "id": "vuln-001",
                    "type": "SQL Injection",
                    "severity": "critical",
                    "cvss_score": 9.8,
                    "cwe": "CWE-89",
                    "owasp": "A03",
                    "location": {"file": "app.py", "start_line": 10},
                    "analysis": {
                        "llm_classification": {"explanation": "SQL injection via f-string"}
                    },
                },
                {
                    "id": "vuln-002",
                    "type": "Hardcoded Secret",
                    "severity": "critical",
                    "cvss_score": 9.1,
                    "cwe": "CWE-798",
                    "owasp": "A07",
                    "location": {"file": "config.py", "start_line": 5},
                    "analysis": {"llm_classification": {"explanation": "Hardcoded API key"}},
                },
                {
                    "id": "vuln-003",
                    "type": "Path Traversal",
                    "severity": "high",
                    "cvss_score": 8.6,
                    "cwe": "CWE-22",
                    "owasp": "A01",
                    "location": {"file": "files.py", "start_line": 22},
                    "analysis": {"llm_classification": {"explanation": "User controls file path"}},
                },
            ]
        },
    }
    mongo_db.scans.insert_one(doc)
    return doc
