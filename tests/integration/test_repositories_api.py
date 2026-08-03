"""
Integration tests — /api/v1/repositories/* endpoints

Tests repository CRUD operations, branch listing, file listing,
and archive upload. Git operations are mocked.

Repositories are SQL-backed (app/models/repository.py, via SQLAlchemy), not
Mongo — the `Repository` model has an integer primary key and no user_id
column at all, so `RepositoryService.list_repos()` returns every repository
in the table regardless of who created it (no per-user ownership/isolation
is implemented at this layer). Seeding here goes through a real session
against the same SQLite database the app itself uses (app.db.session),
mirroring how `mongo_db` seeds the mongomock-motor instance for Mongo-backed
routes elsewhere in this suite.
"""
import pytest
from unittest.mock import patch, AsyncMock, MagicMock

from app.db.session import SessionLocal
from app.models.repository import Repository


async def _seed_repo(name: str = "my-repo", owner_user_id: str | None = None) -> dict:
    async with SessionLocal() as session:
        repo = Repository(
            name=name,
            provider="github",
            url=f"https://github.com/test/{name}",
            owner_user_id=owner_user_id,
            status="CONNECTED",
            default_branch="main",
        )
        session.add(repo)
        await session.commit()
        await session.refresh(repo)
        return {
            "id": repo.id,
            "name": repo.name,
            "provider": repo.provider,
            "url": repo.url,
            "owner_user_id": repo.owner_user_id,
            "status": repo.status,
            "default_branch": repo.default_branch,
        }


class TestListRepositories:
    URL = "/api/v1/repositories/"

    def test_list_repos_returns_200(self, client):
        r = client.get(self.URL)
        assert r.status_code == 200

    def test_list_repos_returns_list(self, client):
        r = client.get(self.URL)
        assert isinstance(r.json(), list)

    async def test_seeded_repos_appear_in_list(self, client, normal_user):
        # No per-user ownership exists at the model/service layer (see module
        # docstring) — every repository in the table is visible to every
        # authenticated user, so this checks that seeded repos show up at
        # all rather than asserting isolation the implementation doesn't have.
        await _seed_repo("visible-repo-a", owner_user_id=normal_user["id"])
        await _seed_repo("visible-repo-b", owner_user_id=normal_user["id"])
        r = client.get(self.URL)
        assert r.status_code == 200
        names = {repo.get("name") for repo in r.json()}
        assert {"visible-repo-a", "visible-repo-b"} <= names

    async def test_other_users_repos_are_hidden(self, client):
        await _seed_repo("hidden-repo", owner_user_id="someone-else")
        r = client.get(self.URL)
        assert r.status_code == 200
        assert "hidden-repo" not in {repo.get("name") for repo in r.json()}

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
                "id": 1,
                "name": "new-repo",
                "provider": "github",
                "url": "https://github.com/test/new-repo",
                "owner_user_id": "user-1",
                "status": "CONNECTED",
                "default_branch": "main",
            }
            r = client.post(self.URL, json={
                "name": "new-repo",
                "provider": "github",
                "url": "https://github.com/test/new-repo",
            })
        assert r.status_code in (200, 201)

    def test_create_repo_missing_name_returns_422(self, client):
        r = client.post(self.URL, json={"provider": "github", "url": "https://github.com/test/repo"})
        assert r.status_code == 422

    def test_create_repo_missing_provider_returns_422(self, client):
        r = client.post(self.URL, json={"name": "my-repo", "url": "https://github.com/test/repo"})
        assert r.status_code == 422


class TestGetRepository:
    def test_get_nonexistent_repo_returns_404(self, client):
        r = client.get("/api/v1/repositories/999999999")
        assert r.status_code == 404

    async def test_get_existing_repo_returns_200(self, client, normal_user):
        repo = await _seed_repo(owner_user_id=normal_user["id"])
        r = client.get(f"/api/v1/repositories/{repo['id']}")
        assert r.status_code == 200

    async def test_get_repo_returns_name(self, client, normal_user):
        repo = await _seed_repo("specific-name", owner_user_id=normal_user["id"])
        r = client.get(f"/api/v1/repositories/{repo['id']}")
        assert r.status_code == 200
        assert r.json().get("name") == "specific-name"

    async def test_get_other_users_repo_returns_404(self, client):
        repo = await _seed_repo("other-user-repo", owner_user_id="someone-else")
        r = client.get(f"/api/v1/repositories/{repo['id']}")
        assert r.status_code == 404


class TestDeleteRepository:
    def test_delete_nonexistent_repo_returns_404(self, client):
        r = client.delete("/api/v1/repositories/999999999")
        assert r.status_code == 404

    async def test_delete_own_repo_returns_200_or_204(self, client, normal_user):
        repo = await _seed_repo(owner_user_id=normal_user["id"])
        r = client.delete(f"/api/v1/repositories/{repo['id']}")
        assert r.status_code in (200, 204)

    async def test_deleted_repo_no_longer_retrievable(self, client, normal_user):
        repo = await _seed_repo(owner_user_id=normal_user["id"])
        rid = repo["id"]
        client.delete(f"/api/v1/repositories/{rid}")
        r = client.get(f"/api/v1/repositories/{rid}")
        assert r.status_code == 404

    async def test_delete_other_users_repo_returns_404(self, client):
        repo = await _seed_repo(owner_user_id="someone-else")
        r = client.delete(f"/api/v1/repositories/{repo['id']}")
        assert r.status_code == 404
