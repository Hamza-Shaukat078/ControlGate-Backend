"""Phase 3 — crawler: same-origin only, GET-only discovery, forms captured
but never submitted. All against httpx.MockTransport.
"""
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from app.domain.analysis.dast.config import ActorConfig
from app.domain.analysis.dast.crawler import crawl
from app.domain.analysis.dast.session import DastSession

BASE = "https://target.example"


def _session(handler) -> DastSession:
    return DastSession(ActorConfig(), resolve=False, transport=httpx.MockTransport(handler))


class TestSameOriginDiscovery:
    @pytest.mark.asyncio
    async def test_follows_same_origin_links_only(self):
        pages = {
            "/": '<a href="/about">About</a><a href="https://evil.example/phish">Ext</a>',
            "/about": "<p>about page</p>",
        }

        def handler(request: httpx.Request) -> httpx.Response:
            body = pages.get(request.url.path)
            if body is None:
                return httpx.Response(404)
            return httpx.Response(200, text=body, headers={"content-type": "text/html"})

        async with _session(handler) as session:
            result = await crawl(session, BASE)

        assert BASE in result.urls
        assert f"{BASE}/about" in result.urls
        assert not any("evil.example" in u for u in result.urls)

    @pytest.mark.asyncio
    async def test_ignores_javascript_and_mailto_links(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/":
                return httpx.Response(
                    200,
                    text='<a href="javascript:void(0)">JS</a><a href="mailto:x@example.com">Mail</a>',
                    headers={"content-type": "text/html"},
                )
            return httpx.Response(404)

        async with _session(handler) as session:
            result = await crawl(session, BASE)

        assert result.urls == [BASE]

    @pytest.mark.asyncio
    async def test_respects_max_pages(self):
        def handler(request: httpx.Request) -> httpx.Response:
            n = int(request.url.path.strip("/") or 0)
            return httpx.Response(
                200, text=f'<a href="/{n + 1}">next</a>', headers={"content-type": "text/html"},
            )

        async with _session(handler) as session:
            result = await crawl(session, BASE, max_pages=3, max_depth=10)

        assert len(result.urls) == 3

    @pytest.mark.asyncio
    async def test_respects_max_depth(self):
        def handler(request: httpx.Request) -> httpx.Response:
            n = int(request.url.path.strip("/") or 0)
            return httpx.Response(
                200, text=f'<a href="/{n + 1}">next</a>', headers={"content-type": "text/html"},
            )

        async with _session(handler) as session:
            result = await crawl(session, BASE, max_pages=100, max_depth=1)

        # depth 0 = "/", depth 1 = "/1" — "/2" would need depth 2, never queued
        assert result.urls == [BASE, f"{BASE}/1"]

    @pytest.mark.asyncio
    async def test_non_html_response_is_not_parsed_for_links(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/":
                return httpx.Response(
                    200, json={"note": '<a href="/should-not-be-followed">x</a>'},
                    headers={"content-type": "application/json"},
                )
            return httpx.Response(200)

        async with _session(handler) as session:
            result = await crawl(session, BASE)

        assert result.urls == [BASE]

    @pytest.mark.asyncio
    async def test_unreachable_page_is_skipped_not_fatal(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/":
                return httpx.Response(
                    200, text='<a href="/broken">broken</a><a href="/ok">ok</a>',
                    headers={"content-type": "text/html"},
                )
            if request.url.path == "/broken":
                raise httpx.ConnectError("boom")
            return httpx.Response(200, text="fine", headers={"content-type": "text/html"})

        async with _session(handler) as session:
            result = await crawl(session, BASE)

        assert f"{BASE}/ok" in result.urls
        assert f"{BASE}/broken" not in result.urls


class TestFormCapture:
    @pytest.mark.asyncio
    async def test_captures_form_action_method_and_fields_without_submitting(self):
        submitted = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/":
                return httpx.Response(
                    200,
                    text='<form action="/search" method="post">'
                         '<input name="q"><input name="category"></form>',
                    headers={"content-type": "text/html"},
                )
            submitted.append(request.url.path)
            return httpx.Response(200)

        async with _session(handler) as session:
            result = await crawl(session, BASE)

        assert len(result.forms) == 1
        form = result.forms[0]
        assert form.action_url == f"{BASE}/search"
        assert form.method == "POST"
        assert set(form.fields) == {"q", "category"}
        assert "/search" not in submitted  # never actually POSTed

    @pytest.mark.asyncio
    async def test_form_without_method_defaults_to_get(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/":
                return httpx.Response(
                    200, text='<form action="/subscribe"><input name="email"></form>',
                    headers={"content-type": "text/html"},
                )
            return httpx.Response(200)

        async with _session(handler) as session:
            result = await crawl(session, BASE)

        assert result.forms[0].method == "GET"

    @pytest.mark.asyncio
    async def test_form_without_action_defaults_to_source_page(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/contact":
                return httpx.Response(
                    200, text='<form><input name="message"></form>',
                    headers={"content-type": "text/html"},
                )
            return httpx.Response(200, text="", headers={"content-type": "text/html"})

        async with _session(handler) as session:
            result = await crawl(session, f"{BASE}/contact", max_depth=0)

        assert result.forms[0].action_url == f"{BASE}/contact"


class TestRequestPacing:
    @pytest.mark.asyncio
    async def test_default_no_delay_between_requests(self):
        pages = {"/": '<a href="/about">About</a>', "/about": "<p>about</p>"}

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text=pages.get(request.url.path, ""), headers={"content-type": "text/html"})

        with patch("app.domain.analysis.dast.crawler.asyncio.sleep", new=AsyncMock()) as sleep_mock:
            async with _session(handler) as session:
                await crawl(session, BASE)

        sleep_mock.assert_not_called()

    @pytest.mark.asyncio
    async def test_request_delay_paces_every_request_after_the_first(self):
        pages = {
            "/": '<a href="/a">a</a><a href="/b">b</a>',
            "/a": "<p>a</p>", "/b": "<p>b</p>",
        }

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text=pages.get(request.url.path, ""), headers={"content-type": "text/html"})

        with patch("app.domain.analysis.dast.crawler.asyncio.sleep", new=AsyncMock()) as sleep_mock:
            async with _session(handler) as session:
                result = await crawl(session, BASE, request_delay=0.15)

        # 3 pages visited (/, /a, /b) -> 2 delays (before every request after the first).
        assert sleep_mock.call_count == len(result.urls) - 1
        sleep_mock.assert_called_with(0.15)
