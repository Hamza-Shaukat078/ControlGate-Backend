"""Track C6 — state/form-transition crawl: submits already-discovered forms
and follows whatever page comes next, reaching multi-step flows (login ->
dashboard, request-reset -> confirm-reset, cart -> checkout) that a pure
link-following crawl can't. All against httpx.MockTransport.
"""
import httpx
import pytest

from app.domain.analysis.dast.config import ActorConfig
from app.domain.analysis.dast.crawler import DiscoveredForm
from app.domain.analysis.dast.session import DastSession
from app.domain.analysis.dast.state_crawler import crawl_form_transitions

BASE = "https://target.example"


def _session(handler) -> DastSession:
    return DastSession(ActorConfig(), resolve=False, transport=httpx.MockTransport(handler))


def _login_form() -> DiscoveredForm:
    return DiscoveredForm(
        action_url=f"{BASE}/login", method="POST", fields=["user", "pass"], source_url=f"{BASE}/login",
    )


class TestActiveModeGating:
    @pytest.mark.asyncio
    async def test_inactive_mode_returns_empty_and_sends_no_requests(self):
        calls = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request.url.path)
            return httpx.Response(200, text="<p>should never be reached</p>")

        async with _session(handler) as session:
            result = await crawl_form_transitions(session, [_login_form()], BASE, active_mode=False)

        assert result.urls == []
        assert result.forms == []
        assert calls == []

    @pytest.mark.asyncio
    async def test_no_seed_forms_returns_empty(self):
        async with _session(lambda r: httpx.Response(200)) as session:
            result = await crawl_form_transitions(session, [], BASE, active_mode=True)
        assert result.urls == []
        assert result.forms == []


class TestFormTransition:
    @pytest.mark.asyncio
    async def test_login_form_submission_reveals_dashboard_links_and_forms(self):
        submitted_bodies = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/login" and request.method == "GET":
                return httpx.Response(200, text="<form></form>", headers={"content-type": "text/html"})
            if request.url.path == "/login" and request.method == "POST":
                submitted_bodies.append(request.content.decode())
                return httpx.Response(
                    200,
                    text='<a href="/dashboard">Dashboard</a>'
                         '<form action="/profile/update" method="POST">'
                         '<input name="display_name"></form>',
                    headers={"content-type": "text/html"},
                    request=request,
                )
            return httpx.Response(200, text="<p>ok</p>", headers={"content-type": "text/html"})

        async with _session(handler) as session:
            result = await crawl_form_transitions(session, [_login_form()], BASE, active_mode=True, max_depth=1)

        assert "user=dastprobe1" in submitted_bodies[0]
        assert "pass=dastprobe1" in submitted_bodies[0]
        assert f"{BASE}/dashboard" in result.urls
        assert any(f.action_url == f"{BASE}/profile/update" for f in result.forms)

    @pytest.mark.asyncio
    async def test_csrf_shaped_field_preserved_from_fresh_get(self):
        submitted_bodies = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/login" and request.method == "GET":
                return httpx.Response(
                    200,
                    text='<input type="hidden" name="csrf_token" value="freshTok">'
                         '<input type="text" name="user" value="">',
                    headers={"content-type": "text/html"},
                )
            if request.url.path == "/login" and request.method == "POST":
                submitted_bodies.append(request.content.decode())
                return httpx.Response(200, text="<p>ok</p>", headers={"content-type": "text/html"}, request=request)
            return httpx.Response(404)

        form = DiscoveredForm(
            action_url=f"{BASE}/login", method="POST", fields=["csrf_token", "user"], source_url=f"{BASE}/login",
        )
        async with _session(handler) as session:
            await crawl_form_transitions(session, [form], BASE, active_mode=True)

        assert "csrf_token=freshTok" in submitted_bodies[0]
        assert "user=dastprobe1" in submitted_bodies[0]

    @pytest.mark.asyncio
    async def test_respects_max_forms_cap(self):
        forms = [
            DiscoveredForm(action_url=f"{BASE}/f{i}", method="POST", fields=["x"], source_url=f"{BASE}/f{i}")
            for i in range(5)
        ]
        submitted = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                submitted.append(request.url.path)
            return httpx.Response(200, text="<p>ok</p>", headers={"content-type": "text/html"})

        async with _session(handler) as session:
            await crawl_form_transitions(session, forms, BASE, active_mode=True, max_forms=2)

        assert len(submitted) == 2

    @pytest.mark.asyncio
    async def test_cross_origin_form_action_is_skipped(self):
        form = DiscoveredForm(
            action_url="https://evil.example/steal", method="POST", fields=["x"], source_url=f"{BASE}/page",
        )
        calls = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(str(request.url))
            return httpx.Response(200, text="<p>ok</p>")

        async with _session(handler) as session:
            result = await crawl_form_transitions(session, [form], BASE, active_mode=True)

        assert calls == []
        assert result.urls == []

    @pytest.mark.asyncio
    async def test_failed_submission_does_not_abort_remaining_forms(self):
        forms = [
            DiscoveredForm(action_url=f"{BASE}/broken", method="POST", fields=["x"], source_url=f"{BASE}/broken"),
            DiscoveredForm(action_url=f"{BASE}/ok", method="POST", fields=["x"], source_url=f"{BASE}/ok"),
        ]

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/broken" and request.method == "POST":
                raise httpx.ConnectError("boom")
            if request.url.path == "/ok" and request.method == "POST":
                return httpx.Response(
                    200, text='<a href="/next">Next</a>', headers={"content-type": "text/html"}, request=request,
                )
            return httpx.Response(200, text="<p>ok</p>", headers={"content-type": "text/html"})

        async with _session(handler) as session:
            result = await crawl_form_transitions(session, forms, BASE, active_mode=True)

        assert f"{BASE}/next" in result.urls

    @pytest.mark.asyncio
    async def test_non_html_response_yields_no_new_urls_or_forms(self):
        form = DiscoveredForm(action_url=f"{BASE}/export", method="POST", fields=["x"], source_url=f"{BASE}/export")

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                return httpx.Response(200, json={"ok": True}, headers={"content-type": "application/json"})
            return httpx.Response(200, text="<p>ok</p>", headers={"content-type": "text/html"})

        async with _session(handler) as session:
            result = await crawl_form_transitions(session, [form], BASE, active_mode=True)

        assert result.urls == []
        assert result.forms == []

    @pytest.mark.asyncio
    async def test_chained_depth_two_reaches_second_hop_form(self):
        """login (depth 0) -> reveals /step2 form (depth 1) -> reveals a
        link only visible after /step2 is itself submitted (depth 2)."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/login" and request.method == "POST":
                return httpx.Response(
                    200,
                    text='<form action="/step2" method="POST"><input name="otp"></form>',
                    headers={"content-type": "text/html"}, request=request,
                )
            if request.url.path == "/step2" and request.method == "POST":
                return httpx.Response(
                    200, text='<a href="/final">Final</a>',
                    headers={"content-type": "text/html"}, request=request,
                )
            return httpx.Response(200, text="<p>ok</p>", headers={"content-type": "text/html"})

        async with _session(handler) as session:
            result = await crawl_form_transitions(
                session, [_login_form()], BASE, active_mode=True, max_depth=2, max_forms=5,
            )

        assert f"{BASE}/final" in result.urls
