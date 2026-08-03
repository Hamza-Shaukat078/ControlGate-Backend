"""
Integration tests — WebSocket scan-progress stream auth (/api/v1/scans/ws/{scan_id}).

scan_ws reimplements auth manually (it needs the token from a query param, not
an Authorization header, so it can't just use Depends(get_current_user)) — it
decodes the JWT, looks up the user, and checks scan ownership/admin, all
before accept(). That reimplementation initially missed one thing
get_current_user has: checking the token's jti against token_revocations.
A user who logs out (revoking their token) could still open/hold a scan
WebSocket with that same token until it naturally expired. These tests pin
that check, alongside the ownership/admin/inactive-user checks next to it.
"""
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from bson import ObjectId
from starlette.testclient import WebSocketDisconnect

from app.core.security import create_access_token, decode_token


def _connect(app, scan_id: str, token: str):
    from starlette.testclient import TestClient
    client = TestClient(app)
    return client.websocket_connect(f"/api/v1/scans/ws/{scan_id}?token={token}")


@pytest.fixture
async def owner_and_scan(mongo_db, normal_user):
    scan_id = "ws-test-scan-1"
    await mongo_db.scans.insert_one({
        "scan_id": scan_id,
        "user_id": str(normal_user["_id"]),
        "state": "RUNNING",
        "progress": 10,
        "logs": [],
    })
    return normal_user, scan_id


@pytest.fixture(autouse=True)
def _patch_mongo_database(mongo_db):
    with patch("app.db.mongo.get_mongo_database", return_value=mongo_db):
        yield


class TestScanWsRevocation:
    async def test_revoked_token_is_rejected(self, owner_and_scan, mongo_db):
        from app.main import app
        user, scan_id = owner_and_scan
        token = create_access_token(subject=user["id"], extra_claims={"role": user["role"]})
        jti = decode_token(token)["jti"]

        await mongo_db.token_revocations.insert_one({
            "jti": jti,
            "user_id": user["id"],
            "expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
            "revoked_at": datetime.now(timezone.utc),
        })

        with pytest.raises(WebSocketDisconnect) as exc_info:
            with _connect(app, scan_id, token):
                pass
        assert exc_info.value.code == 4001

    async def test_non_revoked_token_is_accepted(self, owner_and_scan):
        from app.main import app
        user, scan_id = owner_and_scan
        token = create_access_token(subject=user["id"], extra_claims={"role": user["role"]})

        with _connect(app, scan_id, token) as ws:
            message = ws.receive_json()
            assert message["type"] == "status"


class TestScanWsOwnershipAndAuth:
    async def test_missing_token_rejected(self, owner_and_scan):
        from app.main import app
        _, scan_id = owner_and_scan
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with _connect(app, scan_id, ""):
                pass
        assert exc_info.value.code == 4001

    async def test_garbage_token_rejected(self, owner_and_scan):
        from app.main import app
        _, scan_id = owner_and_scan
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with _connect(app, scan_id, "not-a-real-jwt"):
                pass
        assert exc_info.value.code == 4001

    async def test_inactive_user_rejected(self, mongo_db, owner_and_scan):
        from app.main import app
        user, scan_id = owner_and_scan
        await mongo_db.users.update_one({"_id": user["_id"]}, {"$set": {"is_active": False}})
        token = create_access_token(subject=user["id"], extra_claims={"role": user["role"]})

        with pytest.raises(WebSocketDisconnect) as exc_info:
            with _connect(app, scan_id, token):
                pass
        assert exc_info.value.code == 4001

    async def test_other_users_scan_rejected(self, mongo_db, owner_and_scan):
        from app.main import app
        from tests.conftest import _make_user
        _, scan_id = owner_and_scan
        other = _make_user("normal", email="other@vulcan.example.com")
        await mongo_db.users.insert_one(other)
        token = create_access_token(subject=other["id"], extra_claims={"role": other["role"]})

        with pytest.raises(WebSocketDisconnect) as exc_info:
            with _connect(app, scan_id, token):
                pass
        assert exc_info.value.code == 4003

    async def test_admin_can_access_other_users_scan(self, mongo_db, owner_and_scan):
        from app.main import app
        from tests.conftest import _make_user
        _, scan_id = owner_and_scan
        admin = _make_user("admin")
        await mongo_db.users.insert_one(admin)
        token = create_access_token(subject=admin["id"], extra_claims={"role": admin["role"]})

        with _connect(app, scan_id, token) as ws:
            message = ws.receive_json()
            assert message["type"] == "status"

    async def test_nonexistent_scan_rejected(self, normal_user):
        from app.main import app
        token = create_access_token(subject=normal_user["id"], extra_claims={"role": normal_user["role"]})
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with _connect(app, "no-such-scan", token):
                pass
        assert exc_info.value.code == 4004
