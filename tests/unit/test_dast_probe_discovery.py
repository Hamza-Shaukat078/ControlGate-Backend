"""Probe auto-discovery (Track: GUI 'Discover probe targets' step) —
probe_discovery.py's GET sweep that turns a JSON "list of my resources"
endpoint into IDOR/mass-assignment probe candidates for the GUI to pre-fill.

Same MockTransport pattern as test_dast_session.py — no real sockets.
"""
import httpx
import pytest

from app.domain.analysis.dast.config import ActorConfig, AuthMode
from app.domain.analysis.dast.probe_discovery import discover_probe_candidates
from app.domain.analysis.dast.session import DastSession


class TestIdorCandidateDiscovery:
    @pytest.mark.asyncio
    async def test_json_array_response_becomes_idor_candidate(self):
        """The bare-array shape: GET /orders -> [{"id": "..."}]."""

        def handler(request: httpx.Request) -> httpx.Response:
            if not request.headers.get("authorization"):
                return httpx.Response(401)  # a genuinely protected resource
            if request.url.path == "/orders":
                return httpx.Response(200, json=[{"id": "order-1", "status": "PENDING"}])
            return httpx.Response(404)

        actor = ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="tok")
        transport = httpx.MockTransport(handler)
        async with DastSession(actor, resolve=False, transport=transport) as session:
            result = await discover_probe_candidates(session, ["https://target.example/orders"])

        assert len(result.idor_candidates) == 1
        assert result.idor_candidates[0].owner_resource_url == "https://target.example/orders/order-1"
        assert result.idor_candidates[0].method == "GET"

    @pytest.mark.asyncio
    async def test_enveloped_json_response_becomes_idor_candidate(self):
        """The common enveloped shape this was built against (the
        marketplace app): {"success": true, "data": {"orders": [{...}]}}."""

        def handler(request: httpx.Request) -> httpx.Response:
            if not request.headers.get("authorization"):
                return httpx.Response(401)  # a genuinely protected resource
            return httpx.Response(
                200,
                json={"success": True, "data": {"orders": [{"id": "order-9", "user_id": "u1"}]}},
            )

        actor = ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="tok")
        transport = httpx.MockTransport(handler)
        async with DastSession(actor, resolve=False, transport=transport) as session:
            result = await discover_probe_candidates(session, ["https://target.example/orders"])

        assert len(result.idor_candidates) == 1
        assert result.idor_candidates[0].owner_resource_url == "https://target.example/orders/order-9"

    @pytest.mark.asyncio
    async def test_publicly_readable_resource_not_flagged_as_idor(self):
        """Regression — GET /products/:id is intentionally public in the
        real marketplace app (no auth middleware on that route at all), so
        a second actor's 200 there isn't evidence of a missing ownership
        check, just the catalog working as designed. Confirmed false
        positive against a real scan. An anonymous request succeeding too
        means there's no ownership boundary to test in the first place."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=[{"id": "p1", "seller_id": "someone"}])  # 200 regardless of auth

        actor = ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="tok")
        transport = httpx.MockTransport(handler)
        async with DastSession(actor, resolve=False, transport=transport) as session:
            result = await discover_probe_candidates(session, ["https://target.example/products"])

        assert result.idor_candidates == []

    @pytest.mark.asyncio
    async def test_non_json_response_contributes_nothing(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="<html>not an API</html>")

        actor = ActorConfig(auth_mode=AuthMode.NONE)
        transport = httpx.MockTransport(handler)
        async with DastSession(actor, resolve=False, transport=transport) as session:
            result = await discover_probe_candidates(session, ["https://target.example/"])

        assert result.idor_candidates == []
        assert result.mass_assignment_candidates == []
        assert "No JSON resource-list endpoints" in result.notes[0]

    @pytest.mark.asyncio
    async def test_duplicate_ids_across_targets_deduplicated(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if not request.headers.get("authorization"):
                return httpx.Response(401)  # a genuinely protected resource
            return httpx.Response(200, json=[{"id": "same-id"}])

        actor = ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="tok")
        transport = httpx.MockTransport(handler)
        async with DastSession(actor, resolve=False, transport=transport) as session:
            result = await discover_probe_candidates(
                session, ["https://target.example/orders", "https://target.example/products"]
            )

        assert len(result.idor_candidates) == 1

    @pytest.mark.asyncio
    async def test_resource_heavy_origin_does_not_starve_sibling_origins(self):
        """Regression — a single origin with many resources (product-
        service's whole catalog) used to fill the global cap before a
        sibling origin's own endpoint (order-service's /orders) ever got
        walked, so a multi-target sweep silently returned candidates for
        only the first origin. Per-origin caps keep the results spread
        across every target instead of one crowding out the rest."""

        def handler(request: httpx.Request) -> httpx.Response:
            if not request.headers.get("authorization"):
                return httpx.Response(401)  # a genuinely protected resource
            if "products" in request.url.path:
                return httpx.Response(200, json=[{"id": f"p{i}"} for i in range(20)])
            if "orders" in request.url.path:
                return httpx.Response(200, json=[{"id": "order-1"}])
            return httpx.Response(404)

        actor = ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="tok")
        transport = httpx.MockTransport(handler)
        async with DastSession(actor, resolve=False, transport=transport) as session:
            result = await discover_probe_candidates(
                session,
                ["http://product-svc.example/products", "http://order-svc.example/orders"],
            )

        urls = {c.owner_resource_url for c in result.idor_candidates}
        assert any("order-svc.example" in u for u in urls), (
            "order-service's single resource got crowded out by product-service's catalog"
        )
        assert any("product-svc.example" in u for u in urls)


class TestMassAssignmentCandidateDiscovery:
    @pytest.mark.asyncio
    async def test_ownership_field_preferred_over_role_guess(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=[{"id": "p1", "seller_id": "orig-owner", "role": "irrelevant"}])

        actor = ActorConfig(auth_mode=AuthMode.NONE)
        transport = httpx.MockTransport(handler)
        async with DastSession(actor, resolve=False, transport=transport) as session:
            result = await discover_probe_candidates(session, ["https://target.example/products"])

        assert len(result.mass_assignment_candidates) == 1
        candidate = result.mass_assignment_candidates[0]
        assert candidate.injected_field == "seller_id"
        assert candidate.update_url == "https://target.example/products/p1"

    @pytest.mark.asyncio
    async def test_second_actor_id_resolved_and_used_as_injected_value(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/me":
                return httpx.Response(200, json={"id": "second-actor-real-id"})
            if request.url.path == "/products":
                return httpx.Response(200, json=[{"id": "p1", "seller_id": "orig-owner"}])
            return httpx.Response(404)

        primary = ActorConfig(auth_mode=AuthMode.NONE)
        second = ActorConfig(auth_mode=AuthMode.NONE)
        transport = httpx.MockTransport(handler)
        async with DastSession(primary, resolve=False, transport=transport) as p_session, \
                DastSession(second, resolve=False, transport=transport) as s_session:
            result = await discover_probe_candidates(
                p_session, ["https://target.example/products"], second_actor_session=s_session,
            )

        assert result.mass_assignment_candidates[0].injected_value == "second-actor-real-id"

    @pytest.mark.asyncio
    async def test_second_actor_id_resolved_from_nested_enveloped_whoami_response(self):
        """Regression — the real shape this was built against (the
        marketplace's GET /auth/me): {"success": true, "data": {"user":
        {"id": "..."}}}. The id is a bare nested object, never inside an
        array, so the list-only JSON walker used for resource discovery
        can't find it — this needs _find_first_id_bearing_object instead."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/auth/me":
                return httpx.Response(
                    200,
                    json={"success": True, "data": {"user": {"id": "nested-second-actor-id", "email": "b@b.com"}}},
                )
            if request.url.path == "/products":
                return httpx.Response(200, json=[{"id": "p1", "seller_id": "orig-owner"}])
            return httpx.Response(404)

        primary = ActorConfig(auth_mode=AuthMode.NONE)
        second = ActorConfig(auth_mode=AuthMode.NONE)
        transport = httpx.MockTransport(handler)
        async with DastSession(primary, resolve=False, transport=transport) as p_session, \
                DastSession(second, resolve=False, transport=transport) as s_session:
            result = await discover_probe_candidates(
                p_session, ["https://target.example/products"], second_actor_session=s_session,
            )

        assert result.mass_assignment_candidates[0].injected_value == "nested-second-actor-id"

    @pytest.mark.asyncio
    async def test_no_ownership_or_role_field_yields_no_mass_assignment_candidate(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if not request.headers.get("authorization"):
                return httpx.Response(401)  # a genuinely protected resource
            return httpx.Response(200, json=[{"id": "p1", "name": "Widget", "price": 9.99}])

        actor = ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="tok")
        transport = httpx.MockTransport(handler)
        async with DastSession(actor, resolve=False, transport=transport) as session:
            result = await discover_probe_candidates(session, ["https://target.example/products"])

        assert len(result.idor_candidates) == 1
        assert result.mass_assignment_candidates == []
