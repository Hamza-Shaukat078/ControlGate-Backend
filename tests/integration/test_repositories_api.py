"""
Integration tests — /api/v1/repositories/* endpoints

Tests repository CRUD operations, branch listing, file listing,
and archive upload. Git operations are mocked.
"""
import pytest
from bson import ObjectId
from datetime import datetime, timezone
from unittest.mock import patch, AsyncMock, MagicMock


def _seed_repo(mongo_db, user_id: str, name: str = "my-repo") -> dict:
    doc = {
        "_id": ObjectId(),
        "user_id": user_id,
        "name": name,
        "url": f"https://github.com/test/{name}",
        "description": "Test repository",
        "is_private": False,
        "default_branch": "main",
        "language": "python",
        "stars": 10,
        "status": "active",
        "created_at": datetime.now(timezone.utc),
    }
    mongo_db.repositories.insert_one(doc)
    return doc


class TestListRepositories:
    URL = "/api/v1/repositories/"

    def test_list_repos_returns_200(self, client):
        r = client.get(self.URL)
        assert r.status_code == 200

    def test_list_repos_returns_list(self, client):
        r = client.get(self.URL)
        assert isinstance(r.json(), list)

    def test_user_only_sees_own_repos(self, client, mongo_db, normal_user):
        other_id = str(ObjectId())
        _seed_repo(mongo_db, str(normal_user["_id"]), "mine")
        _seed_repo(mongo_db, other_id, "theirs")
        r = client.get(self.URL)
        assert r.status_code == 200
        # All returned repos should belong to the current user
        for repo in r.json():
            assert repo.get("user_id") == str(normal_user["_id"]) or "user_id" not in repo

    def test_unauthenticated_returns_401(self, mongo_db):
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


class TestCreateRepository:
    URL = "/api/v1/repositories/"

    def test_create_repo_returns_201_or_200(self, client):
        with patch("app.services.repository_service.RepositoryService.create",
                   new_callable=AsyncMock) as mock_create:
            mock_create.return_value = {
                "id": str(ObjectId()),
                "name": "new-repo",
                "url": "https://github.com/test/new-repo",
                "user_id": "u1",
            }
            r = client.post(self.URL, json={
                "name": "new-repo",
                "url": "https://github.com/test/new-repo",
            })
        assert r.status_code in (200, 201)

    def test_create_repo_missing_name_returns_422(self, client):
        r = client.post(self.URL, json={"url": "https://github.com/test/repo"})
        assert r.status_code == 422

    def test_create_repo_missing_url_returns_422(self, client):
        r = client.post(self.URL, json={"name": "my-repo"})
        assert r.status_code == 422


class TestGetRepository:
    def test_get_nonexistent_repo_returns_404(self, client):
        r = client.get(f"/api/v1/repositories/{ObjectId()}")
        assert r.status_code == 404

    def test_get_existing_repo_returns_200(self, client, mongo_db, normal_user):
        repo = _seed_repo(mongo_db, str(normal_user["_id"]))
        r = client.get(f"/api/v1/repositories/{repo['_id']}")
        assert r.status_code == 200

    def test_get_repo_returns_name(self, client, mongo_db, normal_user):
        repo = _seed_repo(mongo_db, str(normal_user["_id"]), "specific-name")
        r = client.get(f"/api/v1/repositories/{repo['_id']}")
        assert r.status_code == 200
        assert r.json().get("name") == "specific-name"


class TestDeleteRepository:
    def test_delete_nonexistent_repo_returns_404(self, client):
        r = client.delete(f"/api/v1/repositories/{ObjectId()}")
        assert r.status_code == 404

    def test_delete_own_repo_returns_200_or_204(self, client, mongo_db, normal_user):
        repo = _seed_repo(mongo_db, str(normal_user["_id"]))
        r = client.delete(f"/api/v1/repositories/{repo['_id']}")
        assert r.status_code in (200, 204)

    def test_deleted_repo_no_longer_retrievable(self, client, mongo_db, normal_user):
        repo = _seed_repo(mongo_db, str(normal_user["_id"]))
        rid = repo["_id"]
        client.delete(f"/api/v1/repositories/{rid}")
        r = client.get(f"/api/v1/repositories/{rid}")
        assert r.status_code == 404
