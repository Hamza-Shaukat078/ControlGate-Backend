"""Track C2 — browser_crawler.crawl_with_browser(), tested against a fake
Playwright object graph (async_playwright()/chromium.launch()/new_context()/
new_page()), same "fake the heavy external dependency, test the
orchestration logic" split this codebase already uses for
_FakeSessionPair/_FakeCollaboratorServer (test_scan_service_dynamic_dispatch.py)
— no real browser process involved here at all.
"""
from unittest.mock import patch

import pytest

from app.domain.analysis.dast.browser_crawler import crawl_with_browser

BASE = "https://target.example"


class _FakePage:
    def __init__(self, pages: dict, calls: list):
        self._pages = pages
        self._calls = calls
        self.closed = False

    async def goto(self, url, wait_until=None, timeout=None):
        self._calls.append(("goto", url))
        if url not in self._pages:
            raise RuntimeError(f"no fake content registered for {url}")
        if self._pages[url] is None:  # simulates an unreachable page
            raise RuntimeError("navigation failed")

    async def content(self) -> str:
        # goto() already raised for a missing/unreachable entry, so this is
        # always looked up right after a successful goto() to the same URL.
        return self._pages[self._calls[-1][1]]

    async def close(self):
        self.closed = True


class _FakeContext:
    def __init__(self, pages: dict):
        self._pages = pages
        self.calls: list = []
        self.added_cookies = None
        self.extra_headers = None
        self.pages_opened: list = []

    async def add_cookies(self, cookies):
        self.added_cookies = cookies

    async def set_extra_http_headers(self, headers):
        self.extra_headers = headers

    async def new_page(self):
        page = _FakePage(self._pages, self.calls)
        self.pages_opened.append(page)
        return page


class _FakeBrowser:
    def __init__(self, pages: dict):
        self._pages = pages
        self.contexts_created: list = []
        self.closed = False

    async def new_context(self):
        ctx = _FakeContext(self._pages)
        self.contexts_created.append(ctx)
        return ctx

    async def close(self):
        self.closed = True


class _FakeChromium:
    def __init__(self, pages: dict):
        self._pages = pages
        self.launch_calls = 0
        self.browsers: list = []

    async def launch(self, headless=True):
        self.launch_calls += 1
        browser = _FakeBrowser(self._pages)
        self.browsers.append(browser)
        return browser


class _FakePlaywright:
    def __init__(self, pages: dict):
        self.chromium = _FakeChromium(pages)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False


def _fake_async_playwright(pages: dict):
    """Returns a zero-arg callable matching async_playwright()'s own
    signature — playwright.async_api.async_playwright() itself takes no
    arguments and returns an async-context-manager object."""
    pw = _FakePlaywright(pages)
    return lambda: pw


def _patch_playwright(pages: dict):
    return patch("playwright.async_api.async_playwright", _fake_async_playwright(pages))


class TestRendersJsProducedContent:
    async def test_crawls_links_only_present_after_js_render(self):
        # The whole point of this module: a raw HTTP body wouldn't have
        # this link at all (imagine an empty <div id="root"> shell) — only
        # the *rendered* DOM (what content() returns post-JS) does.
        pages = {
            BASE: '<html><body><div id="root"><a href="/spa-page">SPA link</a></div></body></html>',
            f"{BASE}/spa-page": "<html><body>rendered</body></html>",
        }
        with _patch_playwright(pages):
            result = await crawl_with_browser(BASE)

        assert BASE in result.urls
        assert f"{BASE}/spa-page" in result.urls


class TestSameOriginAndCaps:
    async def test_follows_same_origin_links_only(self):
        pages = {
            BASE: f'<a href="/about">About</a><a href="https://evil.example/phish">Ext</a>',
            f"{BASE}/about": "<p>about</p>",
        }
        with _patch_playwright(pages):
            result = await crawl_with_browser(BASE)

        assert f"{BASE}/about" in result.urls
        assert not any("evil.example" in u for u in result.urls)

    async def test_respects_max_pages(self):
        pages = {f"{BASE}/{n}": f'<a href="/{n + 1}">next</a>' for n in range(10)}
        pages[BASE] = '<a href="/0">start</a>'
        with _patch_playwright(pages):
            result = await crawl_with_browser(BASE, max_pages=3, max_depth=10)

        assert len(result.urls) == 3

    async def test_respects_max_depth(self):
        pages = {f"{BASE}/{n}": f'<a href="/{n + 1}">next</a>' for n in range(10)}
        pages[BASE] = '<a href="/0">start</a>'
        with _patch_playwright(pages):
            result = await crawl_with_browser(BASE, max_pages=100, max_depth=1)

        # depth 0 = BASE, depth 1 = /0 — /1 would need depth 2, never queued
        assert result.urls == [BASE, f"{BASE}/0"]


class TestFormCapture:
    async def test_captures_form_without_submitting(self):
        pages = {
            BASE: '<form action="/search" method="post"><input name="q"></form>',
        }
        with _patch_playwright(pages):
            result = await crawl_with_browser(BASE)

        assert len(result.forms) == 1
        assert result.forms[0].action_url == f"{BASE}/search"
        assert result.forms[0].method == "POST"


class TestUnreachablePageIsSkippedNotFatal:
    async def test_navigation_failure_does_not_abort_crawl(self):
        pages = {
            BASE: '<a href="/broken">broken</a><a href="/ok">ok</a>',
            f"{BASE}/broken": None,  # simulates goto() raising
            f"{BASE}/ok": "<p>fine</p>",
        }
        with _patch_playwright(pages):
            result = await crawl_with_browser(BASE)

        assert f"{BASE}/ok" in result.urls
        assert f"{BASE}/broken" not in result.urls


class TestSingleBrowserLaunchedPerScan:
    async def test_browser_and_context_created_exactly_once_for_a_multi_page_crawl(self):
        pages = {f"{BASE}/{n}": f'<a href="/{n + 1}">next</a>' for n in range(5)}
        pages[BASE] = '<a href="/0">start</a>'
        fake_pw = _FakePlaywright(pages)
        with patch("playwright.async_api.async_playwright", lambda: fake_pw):
            await crawl_with_browser(BASE, max_pages=5, max_depth=5)

        assert fake_pw.chromium.launch_calls == 1
        assert len(fake_pw.chromium.browsers[0].contexts_created) == 1
        # But a fresh tab per page visited, not one page reused for everything.
        assert len(fake_pw.chromium.browsers[0].contexts_created[0].pages_opened) == 5

    async def test_browser_closed_after_crawl_completes(self):
        pages = {BASE: "<p>only page</p>"}
        fake_pw = _FakePlaywright(pages)
        with patch("playwright.async_api.async_playwright", lambda: fake_pw):
            await crawl_with_browser(BASE)

        assert fake_pw.chromium.browsers[0].closed is True


class TestAuthStateImportedIntoContext:
    async def test_cookies_and_headers_passed_to_context(self):
        pages = {BASE: "<p>ok</p>"}
        fake_pw = _FakePlaywright(pages)
        cookies = [{"name": "session", "value": "abc", "domain": "target.example", "path": "/"}]
        headers = {"Authorization": "Bearer tok123"}
        with patch("playwright.async_api.async_playwright", lambda: fake_pw):
            await crawl_with_browser(BASE, cookies=cookies, extra_headers=headers)

        ctx = fake_pw.chromium.browsers[0].contexts_created[0]
        assert ctx.added_cookies == cookies
        assert ctx.extra_headers == headers

    async def test_no_auth_state_leaves_context_untouched(self):
        pages = {BASE: "<p>ok</p>"}
        fake_pw = _FakePlaywright(pages)
        with patch("playwright.async_api.async_playwright", lambda: fake_pw):
            await crawl_with_browser(BASE)

        ctx = fake_pw.chromium.browsers[0].contexts_created[0]
        assert ctx.added_cookies is None
        assert ctx.extra_headers is None
