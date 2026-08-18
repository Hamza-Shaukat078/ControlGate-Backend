"""V3.7.3 — redirect_warning_probe.run_redirect_warning_probe(), tested
against a fake Playwright BrowserContext/Page (goto/eval_on_selector_all/
click/close), same "fake the heavy external dependency" split as
test_dast_dom_xss_probe.py — no real browser process involved.
"""
import pytest

from app.domain.analysis.dast.redirect_warning_probe import run_redirect_warning_probe
from app.domain.analysis.dast.verdict import Verdict

URL = "https://target.example/page"
EXTERNAL_URL = "https://outside.example/landing"


class _FakePage:
    def __init__(
        self,
        links: list | None = None,
        click_navigates_to: str | None = None,
        goto_error: Exception = None,
        eval_error: Exception = None,
        click_error: Exception = None,
    ):
        self._links = links if links is not None else []
        self._click_navigates_to = click_navigates_to
        self._goto_error = goto_error
        self._eval_error = eval_error
        self._click_error = click_error
        self.goto_calls: list = []
        self.click_calls: list = []
        self.closed = False
        self.url = URL

    async def goto(self, url, wait_until=None, timeout=None):
        self.goto_calls.append(url)
        if self._goto_error:
            raise self._goto_error
        self.url = url

    async def eval_on_selector_all(self, selector, script):
        if self._eval_error:
            raise self._eval_error
        return self._links

    async def click(self, selector, timeout=None):
        self.click_calls.append(selector)
        if self._click_error:
            raise self._click_error
        if self._click_navigates_to:
            self.url = self._click_navigates_to

    async def wait_for_timeout(self, ms):
        pass

    async def close(self):
        self.closed = True


class _FakeBrowserContext:
    def __init__(self, page: _FakePage):
        self._page = page

    async def new_page(self):
        return self._page


class TestActiveModeGating:
    async def test_skipped_without_active_mode(self):
        page = _FakePage()
        ctx = _FakeBrowserContext(page)
        finding = await run_redirect_warning_probe(ctx, URL, active_mode=False)

        assert finding.verdict == Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION
        assert finding.rule_id == "REDIRECT_WARNING_LIVE"
        assert not page.goto_calls  # never navigated at all — no active_mode, no request


class TestNoOutboundLink:
    async def test_no_external_link_is_not_tested(self):
        page = _FakePage(links=[{"href": f"{URL}/other", "target": ""}])  # same-host only
        ctx = _FakeBrowserContext(page)
        finding = await run_redirect_warning_probe(ctx, URL, active_mode=True)

        assert finding.verdict == Verdict.NOT_TESTED
        assert not page.click_calls

    async def test_no_links_at_all_is_not_tested(self):
        page = _FakePage(links=[])
        ctx = _FakeBrowserContext(page)
        finding = await run_redirect_warning_probe(ctx, URL, active_mode=True)

        assert finding.verdict == Verdict.NOT_TESTED


class TestNewTabLink:
    async def test_target_blank_link_is_not_tested_not_guessed_either_way(self):
        # A new-tab link never navigates the original app page away — a
        # materially different shape from the same-tab silent redirect this
        # control is about. Left for a human, not guessed at as pass or fail.
        page = _FakePage(links=[{"href": EXTERNAL_URL, "target": "_blank"}])
        ctx = _FakeBrowserContext(page)
        finding = await run_redirect_warning_probe(ctx, URL, active_mode=True)

        assert finding.verdict == Verdict.NOT_TESTED
        assert "_blank" in finding.note
        assert not page.click_calls  # never even attempted the click


class TestImmediateSilentRedirect:
    async def test_immediate_same_tab_navigation_is_fail(self):
        page = _FakePage(
            links=[{"href": EXTERNAL_URL, "target": ""}],
            click_navigates_to=EXTERNAL_URL,
        )
        ctx = _FakeBrowserContext(page)
        finding = await run_redirect_warning_probe(ctx, URL, active_mode=True)

        assert finding.verdict == Verdict.FAIL
        assert finding.rule_id == "REDIRECT_WARNING_LIVE"
        assert finding.confidence == 0.75
        assert page.click_calls


class TestNoImmediateNavigation:
    async def test_no_navigation_after_click_is_pass_at_lower_confidence(self):
        # click_navigates_to=None: the page's own URL never moves — consistent
        # with an interstitial intercepting the click, but this probe can't
        # confirm that's what actually happened.
        page = _FakePage(links=[{"href": EXTERNAL_URL, "target": ""}])
        ctx = _FakeBrowserContext(page)
        finding = await run_redirect_warning_probe(ctx, URL, active_mode=True)

        assert finding.verdict == Verdict.PASS
        # The whole epistemic point of this probe: a clean result is weaker
        # evidence than a failing one, same asymmetry as dom_xss_probe.py.
        assert finding.confidence == 0.45
        assert finding.confidence < 0.75


class TestNavigationAndInteractionFailures:
    async def test_goto_failure_is_not_tested_not_fail(self):
        page = _FakePage(goto_error=RuntimeError("nav failed"))
        ctx = _FakeBrowserContext(page)
        finding = await run_redirect_warning_probe(ctx, URL, active_mode=True)

        assert finding.verdict == Verdict.NOT_TESTED

    async def test_link_enumeration_failure_is_not_tested_not_fail(self):
        page = _FakePage(eval_error=RuntimeError("eval failed"))
        ctx = _FakeBrowserContext(page)
        finding = await run_redirect_warning_probe(ctx, URL, active_mode=True)

        assert finding.verdict == Verdict.NOT_TESTED

    async def test_click_failure_is_not_tested_not_fail(self):
        page = _FakePage(
            links=[{"href": EXTERNAL_URL, "target": ""}],
            click_error=RuntimeError("click failed"),
        )
        ctx = _FakeBrowserContext(page)
        finding = await run_redirect_warning_probe(ctx, URL, active_mode=True)

        assert finding.verdict == Verdict.NOT_TESTED

    async def test_page_closed_even_on_goto_failure(self):
        page = _FakePage(goto_error=RuntimeError("nav failed"))
        ctx = _FakeBrowserContext(page)
        await run_redirect_warning_probe(ctx, URL, active_mode=True)

        assert page.closed is True
