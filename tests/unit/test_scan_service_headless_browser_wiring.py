"""Track C2 wiring — dynamic_use_headless_browser on ScanStart, threaded
through _run_dynamic_checks into (a) crawl_with_browser's URLs/forms folded
into check_urls/discovered_forms alongside the regex crawler's own output,
and (b) a DOM-XSS probe loop over check_urls using a separately-launched
headless browser context.

Mocks crawl_with_browser/run_dom_xss_probe/playwright.async_api.async_playwright
(the browser-driving logic itself is covered by test_dast_browser_crawler.py/
test_dast_dom_xss_probe.py) — this tests only the glue, same pattern as
test_scan_service_openapi_wiring.py.
"""
import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mongomock_motor import AsyncMongoMockClient

from app.domain.analysis.dast.browser_crawler import CrawlResult as BrowserCrawlResult
from app.domain.analysis.dast.crawler import CrawlResult, DiscoveredForm
from app.domain.analysis.dast.findings import DynamicFinding
from app.domain.analysis.dast.verdict import Verdict
from app.services.scan_service import ScanService

TARGET = "https://example.com"


@pytest.fixture(autouse=True)
def _mock_dns(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))],
    )


class _FakePrimarySession:
    """Stands in for DastSession — only what _run_dynamic_checks actually
    calls on pair.primary for the headless-browser path."""

    def __init__(self, cookies=None, headers=None):
        self._auth_state = (cookies or [], headers or {})

    def browser_auth_state(self):
        return self._auth_state


class _FakeSessionPair:
    last_config = None
    last_primary: _FakePrimarySession = None

    def __init__(self, config):
        _FakeSessionPair.last_config = config
        self.primary = _FakeSessionPair.last_primary or _FakePrimarySession()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False


class _FakePwPage:
    async def close(self):
        pass


class _FakePwContext:
    def __init__(self):
        self.added_cookies = None
        self.extra_headers = None

    async def add_cookies(self, cookies):
        self.added_cookies = cookies

    async def set_extra_http_headers(self, headers):
        self.extra_headers = headers

    async def new_page(self):
        return _FakePwPage()


class _FakePwBrowser:
    def __init__(self):
        self.contexts: list = []
        self.closed = False

    async def new_context(self):
        ctx = _FakePwContext()
        self.contexts.append(ctx)
        return ctx

    async def close(self):
        self.closed = True


class _FakePwChromium:
    def __init__(self):
        self.browsers: list = []

    async def launch(self, headless=True):
        b = _FakePwBrowser()
        self.browsers.append(b)
        return b


class _FakePlaywright:
    def __init__(self):
        self.chromium = _FakePwChromium()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False


async def _make_service():
    db = AsyncMongoMockClient()["test"]
    return ScanService(db), db


class TestHeadlessBrowserDisabledByDefault:
    @pytest.mark.asyncio
    async def test_crawl_with_browser_never_called_when_disabled(self):
        svc, db = await _make_service()
        _FakeSessionPair.last_primary = _FakePrimarySession()
        crawl_with_browser_mock = AsyncMock()
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult(urls=[TARGET]))), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.browser_crawler.crawl_with_browser", crawl_with_browser_mock):
            await svc._run_dynamic_scan("scan-hb-1", TARGET)  # dynamic_use_headless_browser defaults False

        crawl_with_browser_mock.assert_not_called()

    @pytest.mark.asyncio
    async def test_dom_xss_probe_never_invoked_when_disabled(self):
        svc, db = await _make_service()
        _FakeSessionPair.last_primary = _FakePrimarySession()
        run_dom_xss_probe_mock = AsyncMock()
        fake_pw = _FakePlaywright()
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult(urls=[TARGET]))), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.dom_xss_probe.run_dom_xss_probe", run_dom_xss_probe_mock), \
             patch("playwright.async_api.async_playwright", lambda: fake_pw):
            await svc._run_dynamic_scan("scan-hb-2", TARGET)

        run_dom_xss_probe_mock.assert_not_called()
        assert fake_pw.chromium.browsers == []  # no browser launched at all


class TestBrowserCrawlUrlsAndFormsMerged:
    @pytest.mark.asyncio
    async def test_browser_discovered_urls_folded_into_check_urls(self):
        svc, db = await _make_service()
        _FakeSessionPair.last_primary = _FakePrimarySession()
        browser_result = BrowserCrawlResult(urls=[TARGET, f"{TARGET}/spa-next"], forms=[])
        run_checks_mock = AsyncMock(return_value=[])
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult(urls=[TARGET]))), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", run_checks_mock), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.browser_crawler.crawl_with_browser",
                   AsyncMock(return_value=browser_result)):
            await svc._run_dynamic_scan("scan-hb-3", TARGET, dynamic_use_headless_browser=True)

        called_urls = run_checks_mock.call_args.args[1]
        assert f"{TARGET}/spa-next" in called_urls

    @pytest.mark.asyncio
    async def test_browser_discovered_forms_reach_scan_summary_deduped(self):
        svc, db = await _make_service()
        _FakeSessionPair.last_primary = _FakePrimarySession()
        crawler_form = DiscoveredForm(action_url=f"{TARGET}/search", method="GET", fields=["q"], source_url=TARGET)
        browser_form_dup = DiscoveredForm(
            action_url=f"{TARGET}/search", method="GET", fields=["q"], source_url=TARGET,
        )
        browser_form_new = DiscoveredForm(
            action_url=f"{TARGET}/spa-form", method="POST", fields=["x"], source_url=f"{TARGET}/spa",
        )
        browser_result = BrowserCrawlResult(urls=[TARGET], forms=[browser_form_dup, browser_form_new])
        await db.scans.insert_one({"scan_id": "scan-hb-4", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl",
                   AsyncMock(return_value=CrawlResult(urls=[TARGET], forms=[crawler_form]))), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.browser_crawler.crawl_with_browser",
                   AsyncMock(return_value=browser_result)):
            await svc._run_dynamic_scan("scan-hb-4", TARGET, dynamic_use_headless_browser=True)

        doc = await db.scans.find_one({"scan_id": "scan-hb-4"})
        forms = doc["summary"]["discovered_forms"]
        action_urls = [f["action_url"] for f in forms]
        assert action_urls.count(f"{TARGET}/search") == 1  # not duplicated
        assert f"{TARGET}/spa-form" in action_urls

    @pytest.mark.asyncio
    async def test_auth_state_exported_from_session_into_browser_crawl(self):
        svc, db = await _make_service()
        cookies = [{"name": "session", "value": "abc", "domain": "example.com", "path": "/"}]
        headers = {"Authorization": "Bearer tok123"}
        _FakeSessionPair.last_primary = _FakePrimarySession(cookies=cookies, headers=headers)
        crawl_with_browser_mock = AsyncMock(return_value=BrowserCrawlResult(urls=[TARGET], forms=[]))
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult(urls=[TARGET]))), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.browser_crawler.crawl_with_browser", crawl_with_browser_mock):
            await svc._run_dynamic_scan("scan-hb-5", TARGET, dynamic_use_headless_browser=True)

        crawl_with_browser_mock.assert_awaited_once()
        assert crawl_with_browser_mock.await_args.kwargs["cookies"] == cookies
        assert crawl_with_browser_mock.await_args.kwargs["extra_headers"] == headers

    @pytest.mark.asyncio
    async def test_crawl_scope_overrides_passed_to_browser_crawl(self):
        svc, db = await _make_service()
        _FakeSessionPair.last_primary = _FakePrimarySession()
        crawl_with_browser_mock = AsyncMock(return_value=BrowserCrawlResult(urls=[TARGET], forms=[]))
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult(urls=[TARGET]))), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.browser_crawler.crawl_with_browser", crawl_with_browser_mock):
            await svc._run_dynamic_scan(
                "scan-hb-6", TARGET, dynamic_use_headless_browser=True,
                dynamic_crawl_max_pages=25, dynamic_crawl_max_depth=4,
            )

        assert crawl_with_browser_mock.await_args.kwargs["max_pages"] == 25
        assert crawl_with_browser_mock.await_args.kwargs["max_depth"] == 4


class TestBrowserCrawlGracefulDegradation:
    @pytest.mark.asyncio
    async def test_browser_crawl_failure_does_not_abort_scan(self):
        svc, db = await _make_service()
        _FakeSessionPair.last_primary = _FakePrimarySession()
        run_checks_mock = AsyncMock(return_value=[])
        await db.scans.insert_one({"scan_id": "scan-hb-7", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult(urls=[TARGET]))), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", run_checks_mock), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.browser_crawler.crawl_with_browser",
                   AsyncMock(side_effect=RuntimeError("no chromium binary"))):
            await svc._run_dynamic_scan("scan-hb-7", TARGET, dynamic_use_headless_browser=True)

        doc = await db.scans.find_one({"scan_id": "scan-hb-7"})
        assert doc["state"] == "COMPLETED"
        called_urls = run_checks_mock.call_args.args[1]
        assert called_urls == [TARGET]

    @pytest.mark.asyncio
    async def test_dom_xss_probe_playwright_failure_does_not_abort_scan(self):
        svc, db = await _make_service()
        _FakeSessionPair.last_primary = _FakePrimarySession()
        await db.scans.insert_one({"scan_id": "scan-hb-8", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult(urls=[TARGET]))), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.browser_crawler.crawl_with_browser",
                   AsyncMock(return_value=BrowserCrawlResult(urls=[TARGET], forms=[]))), \
             patch("playwright.async_api.async_playwright", side_effect=RuntimeError("playwright not installed")):
            await svc._run_dynamic_scan("scan-hb-8", TARGET, dynamic_use_headless_browser=True)

        doc = await db.scans.find_one({"scan_id": "scan-hb-8"})
        assert doc["state"] == "COMPLETED"


class TestDomXssProbeLoop:
    @pytest.mark.asyncio
    async def test_probe_runs_once_per_check_url_and_result_recorded(self):
        svc, db = await _make_service()
        _FakeSessionPair.last_primary = _FakePrimarySession()
        dom_finding = DynamicFinding(
            control_id="V1.2.1", verdict=Verdict.FAIL, rule_id="DOM_XSS_LIVE",
            url=TARGET, method="GET", note="marker executed", severity="high",
        )
        run_dom_xss_probe_mock = AsyncMock(return_value=dom_finding)
        fake_pw = _FakePlaywright()
        await db.scans.insert_one({"scan_id": "scan-hb-9", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult(urls=[TARGET]))), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.dom_xss_probe.run_dom_xss_probe", run_dom_xss_probe_mock), \
             patch("playwright.async_api.async_playwright", lambda: fake_pw):
            await svc._run_dynamic_scan(
                "scan-hb-9", TARGET, dynamic_use_headless_browser=True, dynamic_active_mode=True,
            )

        run_dom_xss_probe_mock.assert_awaited_once()
        assert run_dom_xss_probe_mock.await_args.args[1] == TARGET
        assert run_dom_xss_probe_mock.await_args.kwargs["active_mode"] is True

        doc = await db.scans.find_one({"scan_id": "scan-hb-9"})
        findings = doc["summary"]["dynamic_findings"]
        dom_result = next(f for f in findings if f["rule_id"] == "DOM_XSS_LIVE")
        assert dom_result["verdict"] == "fail"

    @pytest.mark.asyncio
    async def test_probe_bounded_to_five_urls(self):
        svc, db = await _make_service()
        _FakeSessionPair.last_primary = _FakePrimarySession()
        crawl_result = CrawlResult(urls=[TARGET] + [f"{TARGET}/p{i}" for i in range(8)], forms=[])
        pass_finding = DynamicFinding(
            control_id="V1.2.1", verdict=Verdict.PASS, rule_id="DOM_XSS_LIVE",
            url=TARGET, method="GET", note="ok", severity="high",
        )
        run_dom_xss_probe_mock = AsyncMock(return_value=pass_finding)
        fake_pw = _FakePlaywright()
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=crawl_result)), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.dom_xss_probe.run_dom_xss_probe", run_dom_xss_probe_mock), \
             patch("playwright.async_api.async_playwright", lambda: fake_pw):
            await svc._run_dynamic_scan("scan-hb-10", TARGET, dynamic_use_headless_browser=True)

        assert run_dom_xss_probe_mock.await_count == 5

    @pytest.mark.asyncio
    async def test_browser_context_gets_auth_state_for_dom_probe(self):
        svc, db = await _make_service()
        cookies = [{"name": "session", "value": "abc", "domain": "example.com", "path": "/"}]
        headers = {"Authorization": "Bearer tok123"}
        _FakeSessionPair.last_primary = _FakePrimarySession(cookies=cookies, headers=headers)
        fake_pw = _FakePlaywright()
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult(urls=[TARGET]))), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.dom_xss_probe.run_dom_xss_probe", AsyncMock()), \
             patch("playwright.async_api.async_playwright", lambda: fake_pw):
            await svc._run_dynamic_scan("scan-hb-11", TARGET, dynamic_use_headless_browser=True)

        ctx = fake_pw.chromium.browsers[0].contexts[0]
        assert ctx.added_cookies == cookies
        assert ctx.extra_headers == headers

    @pytest.mark.asyncio
    async def test_dom_xss_finding_verdict_is_audited_when_active_mode_fail(self, caplog):
        svc, db = await _make_service()
        _FakeSessionPair.last_primary = _FakePrimarySession()
        dom_finding = DynamicFinding(
            control_id="V1.2.1", verdict=Verdict.FAIL, rule_id="DOM_XSS_LIVE",
            url=TARGET, method="GET", note="marker executed", severity="high",
        )
        fake_pw = _FakePlaywright()
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult(urls=[TARGET]))), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.dom_xss_probe.run_dom_xss_probe", AsyncMock(return_value=dom_finding)), \
             patch("playwright.async_api.async_playwright", lambda: fake_pw), \
             caplog.at_level("INFO"):
            await svc._run_dynamic_scan(
                "scan-hb-12", TARGET, dynamic_use_headless_browser=True, dynamic_active_mode=True,
            )

        audit_logs = [r.getMessage() for r in caplog.records if "Active-mode" in r.getMessage()]
        assert audit_logs
        assert "DOM_XSS_LIVE" in audit_logs[0]
