"""Integration tests — /api/v1/graphs/* endpoints.

graphs.py had zero integration coverage despite being the only route file
with none (compare test_asvs_api.py, test_auth_api.py, test_repositories_api.py,
test_scan_api.py). Covers the auth/ownership guard shared by all three routes
and the GraphService delegation on the main file_graph endpoint.
"""
from datetime import datetime, timezone

from bson import ObjectId


async def _insert_scan(mongo_db, *, scan_id, user_id, state="COMPLETED", graph_data=None):
    await mongo_db.scans.insert_one({
        "scan_id": scan_id,
        "user_id": ObjectId(user_id) if isinstance(user_id, str) else user_id,
        "state": state,
        "graph_data": graph_data,
        "created_at": datetime.now(timezone.utc),
    })


GRAPH_DATA = {
    "nodes": [{"id": "n1", "node_type": "AST", "type": "Call", "label": "Call", "properties": {}}],
    "edges": [],
    "source_content": "print(1)",
    "file_path": "app.py",
}


class TestFileGraphEndpoint:
    URL = "/api/v1/graphs/{scan_id}/file/{file_id}"

    def test_unknown_scan_returns_404(self, client):
        r = client.get(self.URL.format(scan_id="nope", file_id="f1"))
        assert r.status_code == 404

    async def test_owner_can_fetch_their_own_scan_graph(self, client, normal_user, mongo_db):
        await _insert_scan(mongo_db, scan_id="s1", user_id=normal_user["id"], graph_data=GRAPH_DATA)
        r = client.get(self.URL.format(scan_id="s1", file_id="f1"))
        assert r.status_code == 200
        assert r.json()["type"] == "AST"

    async def test_non_owner_gets_403(self, client, admin_user, mongo_db):
        await _insert_scan(mongo_db, scan_id="s2", user_id=admin_user["id"], graph_data=GRAPH_DATA)
        r = client.get(self.URL.format(scan_id="s2", file_id="f1"))
        assert r.status_code == 403

    async def test_admin_can_fetch_any_users_scan_graph(self, admin_client, normal_user, mongo_db):
        await _insert_scan(mongo_db, scan_id="s3", user_id=normal_user["id"], graph_data=GRAPH_DATA)
        r = admin_client.get(self.URL.format(scan_id="s3", file_id="f1"))
        assert r.status_code == 200

    def test_unauthenticated_returns_401(self, mongo_db):
        from fastapi.testclient import TestClient
        from app.main import app
        from app.db.mongo import get_mongo_db

        async def _db():
            yield mongo_db

        app.dependency_overrides[get_mongo_db] = _db
        with TestClient(app, raise_server_exceptions=False) as c:
            r = c.get(self.URL.format(scan_id="s1", file_id="f1"))
        app.dependency_overrides.clear()
        assert r.status_code == 401

    async def test_graph_type_query_param_is_forwarded(self, client, normal_user, mongo_db):
        await _insert_scan(mongo_db, scan_id="s4", user_id=normal_user["id"], graph_data=GRAPH_DATA)
        r = client.get(self.URL.format(scan_id="s4", file_id="f1"), params={"type": "CPG"})
        assert r.status_code == 200
        assert r.json()["type"] == "CPG"


class TestNodeDetailsEndpoint:
    URL = "/api/v1/graphs/{scan_id}/nodes/{node_id}"

    def test_unknown_scan_returns_404(self, client):
        r = client.get(self.URL.format(scan_id="nope", node_id="n1"))
        assert r.status_code == 404

    async def test_owner_gets_node_details(self, client, normal_user, mongo_db):
        await _insert_scan(mongo_db, scan_id="s5", user_id=normal_user["id"])
        r = client.get(self.URL.format(scan_id="s5", node_id="n1"))
        assert r.status_code == 200
        assert r.json()["node_id"] == "n1"

    async def test_non_owner_gets_403(self, client, admin_user, mongo_db):
        await _insert_scan(mongo_db, scan_id="s6", user_id=admin_user["id"])
        r = client.get(self.URL.format(scan_id="s6", node_id="n1"))
        assert r.status_code == 403


class TestPathDetailsEndpoint:
    URL = "/api/v1/graphs/{scan_id}/paths/{path_id}"

    def test_unknown_scan_returns_404(self, client):
        r = client.get(self.URL.format(scan_id="nope", path_id="p1"))
        assert r.status_code == 404

    async def test_owner_gets_path_details(self, client, normal_user, mongo_db):
        await _insert_scan(mongo_db, scan_id="s7", user_id=normal_user["id"])
        r = client.get(self.URL.format(scan_id="s7", path_id="p1"))
        assert r.status_code == 200
        assert r.json()["path_id"] == "p1"

    async def test_non_owner_gets_403(self, client, admin_user, mongo_db):
        await _insert_scan(mongo_db, scan_id="s8", user_id=admin_user["id"])
        r = client.get(self.URL.format(scan_id="s8", path_id="p1"))
        assert r.status_code == 403
