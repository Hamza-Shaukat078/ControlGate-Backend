"""Track C2 — dom_xss_probe.run_dom_xss_probe(), tested against a fake
Playwright BrowserContext/Page (goto/evaluate/close), same "fake the heavy
external dependency" split as test_dast_browser_crawler.py — no real
browser process involved.
"""
import pytest

from app.domain.analysis.dast.dom_xss_probe import run_dom_xss_probe
from app.domain.analysis.dast.verdict import Verdict

URL = "https://target.example/spa"


class _FakePage:
    def __init__(self, marker_fires: bool, goto_error: Exception = None, evaluate_error: Exception = None):
        self._marker_fires = marker_fires
        self._goto_error = goto_error
        self._evaluate_error = evaluate_error
        self.goto_calls: list = []
        self.closed = False
        self._observed_marker = None

    async def goto(self, url, wait_until=None, timeout=None):
        self.goto_calls.append(url)
        if self._goto_error:
            raise self._goto_error
        if self._marker_fires:
            # Simulates the target's own vulnerable JS: it read the payload
            # out of location.hash (the URL fragment this test put it in)
            # and executed it unescaped, exactly as a real onerror handler
            # would when el.innerHTML = location.hash.
            marker = url.split("__dast_marker='", 1)[1].split("'", 1)[0]
            self._observed_marker = marker

    async def evaluate(self, script: str):
        if self._evaluate_error:
            raise self._evaluate_error
        assert script == "window.__dast_marker"
        return self._observed_marker

    async def close(self):
        self.closed = True


class _FakeBrowserContext:
    def __init__(self, page: _FakePage):
        self._page = page

    async def new_page(self):
        return self._page


class TestActiveModeGating:
    async def test_skipped_without_active_mode(self):
        page = _FakePage(marker_fires=True)
        ctx = _FakeBrowserContext(page)
        finding = await run_dom_xss_probe(ctx, URL, active_mode=False)

        assert finding.verdict == Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION
        assert finding.rule_id == "DOM_XSS_LIVE"
        assert not page.goto_calls  # never navigated at all — no active_mode, no request


class TestVulnerablePage:
    async def test_marker_execution_is_flagged_fail(self):
        page = _FakePage(marker_fires=True)
        ctx = _FakeBrowserContext(page)
        finding = await run_dom_xss_probe(ctx, URL, active_mode=True)

        assert finding.verdict == Verdict.FAIL
        assert finding.rule_id == "DOM_XSS_LIVE"
        assert finding.url == URL

    async def test_payload_placed_in_fragment_not_query(self):
        # The whole premise: the payload must never be sent to the server —
        # it belongs after '#', never as a '?' query parameter.
        page = _FakePage(marker_fires=True)
        ctx = _FakeBrowserContext(page)
        await run_dom_xss_probe(ctx, URL, active_mode=True)

        navigated_url = page.goto_calls[0]
        assert "#" in navigated_url
        fragment = navigated_url.split("#", 1)[1]
        assert "<img" in fragment
        assert "onerror" in fragment

    async def test_existing_fragment_on_url_is_replaced_not_duplicated(self):
        page = _FakePage(marker_fires=True)
        ctx = _FakeBrowserContext(page)
        await run_dom_xss_probe(ctx, f"{URL}#old-fragment", active_mode=True)

        navigated_url = page.goto_calls[0]
        assert "old-fragment" not in navigated_url
        assert navigated_url.count("#") == 1


class TestSafePage:
    async def test_no_marker_execution_is_pass(self):
        page = _FakePage(marker_fires=False)
        ctx = _FakeBrowserContext(page)
        finding = await run_dom_xss_probe(ctx, URL, active_mode=True)

        assert finding.verdict == Verdict.PASS


class TestNavigationAndEvaluateFailures:
    async def test_goto_failure_is_not_tested_not_fail(self):
        page = _FakePage(marker_fires=False, goto_error=RuntimeError("nav failed"))
        ctx = _FakeBrowserContext(page)
        finding = await run_dom_xss_probe(ctx, URL, active_mode=True)

        assert finding.verdict == Verdict.NOT_TESTED

    async def test_evaluate_failure_is_not_tested_not_fail(self):
        page = _FakePage(marker_fires=False, evaluate_error=RuntimeError("eval failed"))
        ctx = _FakeBrowserContext(page)
        finding = await run_dom_xss_probe(ctx, URL, active_mode=True)

        assert finding.verdict == Verdict.NOT_TESTED

    async def test_page_closed_even_on_goto_failure(self):
        page = _FakePage(marker_fires=False, goto_error=RuntimeError("nav failed"))
        ctx = _FakeBrowserContext(page)
        await run_dom_xss_probe(ctx, URL, active_mode=True)

        assert page.closed is True
