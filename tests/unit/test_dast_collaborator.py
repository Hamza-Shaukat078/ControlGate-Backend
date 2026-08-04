"""Out-of-band collaborator (Track A2) — a real HTTP listener, so these
tests hit it over real loopback sockets rather than mocking anything;
same "prove the plumbing actually works" reasoning as
tests/integration/test_dast_live.py, just scoped to this one small module
instead of needing the full fixture-server harness.
"""
import httpx
import pytest

from app.domain.analysis.dast.collaborator import CollaboratorServer


@pytest.fixture(scope="module")
def collab():
    # Module-scoped (one real server for the whole file, same pattern as
    # test_dast_live.py's live_server fixture) — each test uses its own
    # fresh token, so sharing the server doesn't compromise isolation and
    # avoids 7x the thread start/shutdown-poll overhead of a fresh server
    # per test.
    with CollaboratorServer() as server:
        yield server


class TestCollaboratorServer:
    @pytest.mark.asyncio
    async def test_no_hits_for_unused_token(self, collab):
        token = collab.new_token()
        assert collab.hits_for(token) == []

    @pytest.mark.asyncio
    async def test_records_a_get_hit(self, collab):
        token = collab.new_token()
        url = collab.callback_url(token)
        async with httpx.AsyncClient() as client:
            resp = await client.get(url)
        assert resp.status_code == 200

        hits = collab.hits_for(token)
        assert len(hits) == 1
        assert hits[0].method == "GET"
        assert hits[0].token == token
        assert hits[0].remote_addr in ("127.0.0.1", "::1")

    @pytest.mark.asyncio
    async def test_records_a_post_hit(self, collab):
        token = collab.new_token()
        url = collab.callback_url(token)
        async with httpx.AsyncClient() as client:
            await client.post(url, content=b"body")

        hits = collab.hits_for(token)
        assert len(hits) == 1
        assert hits[0].method == "POST"

    @pytest.mark.asyncio
    async def test_records_multiple_hits_for_the_same_token(self, collab):
        token = collab.new_token()
        url = collab.callback_url(token)
        async with httpx.AsyncClient() as client:
            await client.get(url)
            await client.get(url)

        assert len(collab.hits_for(token)) == 2

    @pytest.mark.asyncio
    async def test_different_tokens_do_not_cross_contaminate(self, collab):
        token_a = collab.new_token()
        token_b = collab.new_token()
        async with httpx.AsyncClient() as client:
            await client.get(collab.callback_url(token_a))

        assert len(collab.hits_for(token_a)) == 1
        assert collab.hits_for(token_b) == []

    def test_callback_url_embeds_the_token(self, collab):
        token = collab.new_token()
        assert collab.callback_url(token) == f"{collab.base_url}/{token}"

    def test_tokens_are_unique(self, collab):
        tokens = {collab.new_token() for _ in range(20)}
        assert len(tokens) == 20
