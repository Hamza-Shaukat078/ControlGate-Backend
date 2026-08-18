"""
Shared fixtures for all Vulcan backend tests.

MongoDB is mocked with mongomock-motor (an async-compatible wrapper around
mongomock, matching Motor's AsyncIOMotorClient interface) so no real database
connection is needed. FastAPI dependency overrides swap out get_mongo_db and
get_current_user.
"""
from __future__ import annotations

import pytest
from mongomock_motor import AsyncMongoMockClient
from datetime import datetime, timezone
from bson import ObjectId
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, MagicMock, patch

from app.core.security import get_password_hash, create_access_token


# ── Disable app.main's real-Mongo startup event for the whole test session ────
#
# app.main.on_startup() calls ensure_indexes()/seed_admin()/seed_asvs_controls()
# as plain function calls, not FastAPI Depends() — so the get_mongo_db overrides
# below can't intercept them. Every `with TestClient(app) as c:` block re-runs
# that startup event (ASGI lifespan), which otherwise opens a real connection to
# the docker-compose MongoDB instance (localhost:27018) and blocks for the full
# 30s server-selection timeout when that container isn't running, either erroring
# fixture setup outright or surfacing as a downstream assertion failure. This
# fixture keeps this module's stated promise ("no real database connection is
# needed") by no-opping just those three Mongo-touching startup calls; SQLite
# model init (init_models) is untouched since it's a local file, not a network
# service, and isn't part of this failure mode.
@pytest.fixture(autouse=True, scope="session")
def _disable_real_mongo_startup():
    import app.main as main_module

    with patch.object(main_module, "ensure_indexes", new=AsyncMock()), \
         patch.object(main_module, "seed_admin", new=AsyncMock()), \
         patch.object(main_module, "seed_asvs_controls", new=AsyncMock()):
        yield


# ── Never let a developer's local .env leak into the SSRF/private-target guard ─
#
# app.main imports trigger `load_dotenv()`, which — unlike pydantic-settings'
# own env_file loading — writes straight into the real os.environ. A developer
# scanning their own local app (this repo's own workflow: marketplace
# containers on localhost) sets ALLOW_PRIVATE_SCAN_TARGETS=1 in .env so
# validate_public_http_url() will accept those targets. That's a legitimate,
# deliberate per-developer escape hatch (see app/core/network.py's own
# docstring) — but every test process that imports app.main inherits it too,
# silently neutering every test that verifies the guard actually rejects
# loopback/private/link-local targets (confirmed false-negative regression
# in an unrelated real scan session: ~19 SSRF/TLS-guard tests failed, not
# because the guard is broken, but because .env's dev convenience flag was
# leaking into the test suite's own process). Tests must exercise the real,
# secure-by-default behavior regardless of what's in the machine's local
# .env; scope=session with a manual pop/restore (rather than the
# function-scoped `monkeypatch` fixture) keeps this active for every test.
@pytest.fixture(autouse=True, scope="session")
def _no_private_scan_targets_leak_from_local_env():
    import os

    had_value = "ALLOW_PRIVATE_SCAN_TARGETS" in os.environ
    old_value = os.environ.pop("ALLOW_PRIVATE_SCAN_TARGETS", None)
    try:
        yield
    finally:
        if had_value:
            os.environ["ALLOW_PRIVATE_SCAN_TARGETS"] = old_value


# ── In-memory MongoDB via mongomock-motor ──────────────────────────────────────

@pytest.fixture(scope="session")
def mongo_client():
    return AsyncMongoMockClient()


@pytest.fixture
async def mongo_db(mongo_client):
    db = mongo_client["vulcan_test"]
    yield db
    # Wipe all collections between tests
    for name in await db.list_collection_names():
        await db[name].drop()


# ── Pre-built user documents ──────────────────────────────────────────────────

def _make_user(role: str, email: str | None = None) -> dict:
    uid = ObjectId()
    return {
        "_id": uid,
        "id": str(uid),
        "email": email or f"{role}@vulcan.example.com",
        "full_name": f"{role.title()} User",
        "hashed_password": get_password_hash("TestPass123!"),
        "role": role,
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
    }


@pytest.fixture
async def normal_user(mongo_db):
    doc = _make_user("normal")
    await mongo_db.users.insert_one(doc)
    return doc


@pytest.fixture
async def premium_user(mongo_db):
    doc = _make_user("premium")
    await mongo_db.users.insert_one(doc)
    return doc


@pytest.fixture
async def admin_user(mongo_db):
    doc = _make_user("admin")
    await mongo_db.users.insert_one(doc)
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
async def sample_scan(mongo_db, normal_user):
    scan_id = "scan-test-abc123"
    doc = {
        "_id": ObjectId(),
        "scan_id": scan_id,
        "user_id": str(normal_user["_id"]),
        "state": "COMPLETED",
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
    await mongo_db.scans.insert_one(doc)
    return doc
