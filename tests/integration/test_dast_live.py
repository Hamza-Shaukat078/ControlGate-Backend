"""Phase 1 of the static+dynamic plan: prove the DAST engine works against a
real TCP/HTTP server, not just httpx.MockTransport (which is all
tests/unit/test_dast_*.py exercises). Runs the crawler, the four payload
checks, and the race probe against tests/fixtures/dast_vuln_server.py, a
small deliberately-vulnerable local server.

validate_public_http_url() rejects loopback/private hosts by design (SSRF
guard) — correct for anything reachable from a real scan request, but it
also means there is currently no way to point this engine at a local test
target at all, live or otherwise. That's a real gap (noted in the review),
not a test bug: this file monkeypatches the guard for its own loopback
fixture rather than routing around a bypass that doesn't exist in the
product yet.
"""
from pathlib import Path

import pytest

from app.domain.analysis.dast import session as session_module
from app.domain.analysis.dast.checks import run_payload_checks
from app.domain.analysis.dast.collaborator import CollaboratorServer
from app.domain.analysis.dast.config import ActorConfig, AuthMode, DynamicScanConfig, FormLoginConfig
from app.domain.analysis.dast.crawler import DiscoveredForm, crawl
from app.domain.analysis.dast.browser_crawler import crawl_with_browser
from app.domain.analysis.dast.dom_xss_probe import run_dom_xss_probe
from app.domain.analysis.dast.idor_probe import IdorProbeConfig, run_idor_probe
from app.domain.analysis.dast.openapi_discovery import fetch_openapi_spec, parse_openapi_spec
from app.domain.analysis.dast.race_probe import RaceProbeConfig, run_race_probe
from app.domain.analysis.dast.rule_loader import load_dynamic_queries
from app.domain.analysis.dast.session import DastSession, DastSessionPair
from app.domain.analysis.dast.ssrf_probe import run_ssrf_probe
from app.domain.analysis.dast.verdict import Verdict
from app.domain.analysis.dast.xss_probe import run_stored_xss_probe
from tests.fixtures.dast_vuln_server import (
    LOGIN_PASSWORD,
    LOGIN_USERNAME,
    OWNER_BEARER_TOKEN,
    VulnFixtureServer,
)

RULES = load_dynamic_queries(Path(__file__).resolve().parents[2] / "queries" / "dynamic_queries.json")


def _chromium_available() -> bool:
    """pytest.importorskip("playwright") alone only proves the *package* is
    installed — a pip install without the separate `playwright install
    chromium` step leaves the package importable but every real launch
    failing. This actually launches (and immediately closes) a browser, via
    the sync API since this runs at collection time, outside any
    pytest-asyncio event loop, same rationale as C5's _docker_available()
    doing a real `docker info` rather than just checking PATH."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            browser.close()
        return True
    except Exception:
        return False


requires_chromium = pytest.mark.skipif(
    not _chromium_available(), reason="Playwright/Chromium not available in this environment",
)


@pytest.fixture(autouse=True)
def _allow_loopback_targets(monkeypatch):
    monkeypatch.setattr(session_module, "validate_public_http_url", lambda url, **kwargs: url)


@pytest.fixture(scope="module")
def live_server():
    with VulnFixtureServer() as server:
        yield server


@pytest.fixture
def base_url(live_server):
    return live_server.base_url


async def _session() -> DastSession:
    return DastSession(ActorConfig())


class TestCrawlerLive:
    async def test_discovers_pages_and_forms(self, base_url):
        async with await _session() as session:
            result = await crawl(session, base_url + "/")

        discovered = {u.replace(base_url, "") for u in result.urls}
        assert "/page1" in discovered
        assert "/page2" in discovered
        assert any(f.action_url.endswith("/redeem-vulnerable") for f in result.forms)
        assert all(f.method == "POST" or f.action_url.endswith("/redeem-vulnerable") for f in result.forms)


class TestPayloadChecksLive:
    async def test_open_redirect_and_crlf_detected(self, base_url):
        target = base_url + "/redirect"
        async with await _session() as session:
            findings = await run_payload_checks(session, target, RULES, active_mode=False)

        by_rule = {f.rule_id: f for f in findings}
        assert by_rule["OPEN_REDIRECT_LIVE"].verdict == Verdict.FAIL
        assert by_rule["CRLF_HEADER_REFLECTION"].verdict == Verdict.FAIL

    async def test_double_decode_bypass_detected(self, base_url):
        target = base_url + "/traverse"
        async with await _session() as session:
            findings = await run_payload_checks(session, target, RULES, active_mode=False)

        by_rule = {f.rule_id: f for f in findings}
        assert by_rule["DOUBLE_DECODE_BYPASS"].verdict == Verdict.FAIL

    async def test_smuggling_probe_completes_a_real_round_trip(self, base_url):
        # Single naive server, not a real front-end/back-end proxy pair, so a
        # true desync (FAIL) isn't reproducible here — this asserts the raw
        # socket path (_send_raw_smuggling_probe) actually connects, sends,
        # and receives over real TCP instead of raising, which is the one
        # thing MockTransport-based unit tests structurally cannot check.
        target = base_url + "/"
        async with await _session() as session:
            findings = await run_payload_checks(session, target, RULES, active_mode=True)

        smuggling = next(f for f in findings if f.rule_id == "REQUEST_SMUGGLING")
        assert smuggling.verdict in (Verdict.PASS, Verdict.FAIL)

    async def test_smuggling_probe_skipped_without_active_mode(self, base_url):
        target = base_url + "/"
        async with await _session() as session:
            findings = await run_payload_checks(session, target, RULES, active_mode=False)

        smuggling = next(f for f in findings if f.rule_id == "REQUEST_SMUGGLING")
        assert smuggling.verdict == Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION


class TestRaceProbeLive:
    async def test_detects_unsynchronized_endpoint(self, base_url, live_server):
        live_server.reset_race_state()
        config = DynamicScanConfig(target_url=base_url, actor=ActorConfig())
        pair = DastSessionPair(config)
        async with pair:
            finding = await run_race_probe(
                pair,
                RaceProbeConfig(
                    scenario_id="RACE_REDEEM_VULNERABLE",
                    url=base_url + "/redeem-vulnerable",
                    concurrency=5,
                    max_expected_successes=1,
                ),
                active_mode=True,
            )

        assert finding.verdict == Verdict.FAIL

    async def test_passes_for_locked_endpoint(self, base_url, live_server):
        live_server.reset_race_state()
        config = DynamicScanConfig(target_url=base_url, actor=ActorConfig())
        pair = DastSessionPair(config)
        async with pair:
            finding = await run_race_probe(
                pair,
                RaceProbeConfig(
                    scenario_id="RACE_REDEEM_SAFE",
                    url=base_url + "/redeem-safe",
                    concurrency=5,
                    max_expected_successes=1,
                ),
                active_mode=True,
            )

        assert finding.verdict == Verdict.PASS

    async def test_skipped_without_active_mode(self, base_url):
        config = DynamicScanConfig(target_url=base_url, actor=ActorConfig())
        pair = DastSessionPair(config)
        async with pair:
            finding = await run_race_probe(
                pair,
                RaceProbeConfig(scenario_id="RACE_REDEEM_VULNERABLE", url=base_url + "/redeem-vulnerable"),
                active_mode=False,
            )

        assert finding.verdict == Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION


class TestIdorProbeLive:
    def _pair(self, base_url):
        config = DynamicScanConfig(
            target_url=base_url,
            actor=ActorConfig(auth_mode=AuthMode.BEARER, bearer_token=OWNER_BEARER_TOKEN),
            second_actor=ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="attacker-token"),
        )
        return DastSessionPair(config)

    async def test_ownership_enforced_endpoint_passes(self, base_url):
        async with self._pair(base_url) as pair:
            finding = await run_idor_probe(
                pair, IdorProbeConfig(scenario_id="IDOR_ORDER", owner_resource_url=base_url + "/orders/42"),
            )
        assert finding.verdict == Verdict.PASS

    async def test_unenforced_endpoint_fails(self, base_url):
        async with self._pair(base_url) as pair:
            finding = await run_idor_probe(
                pair, IdorProbeConfig(scenario_id="IDOR_PROFILE", owner_resource_url=base_url + "/profile/42"),
            )
        assert finding.verdict == Verdict.FAIL


class TestCsrfTokenValidationLive:
    async def test_unprotected_form_fails(self, base_url):
        async with await _session() as session:
            findings = await run_payload_checks(
                session, base_url + "/transfer-form", RULES, active_mode=True,
            )
        finding = next(f for f in findings if f.rule_id == "CSRF_TOKEN_NOT_VALIDATED")
        assert finding.verdict == Verdict.FAIL

    async def test_protected_form_passes(self, base_url):
        async with await _session() as session:
            findings = await run_payload_checks(
                session, base_url + "/transfer-form-safe", RULES, active_mode=True,
            )
        finding = next(f for f in findings if f.rule_id == "CSRF_TOKEN_NOT_VALIDATED")
        assert finding.verdict == Verdict.PASS

    async def test_skipped_without_active_mode(self, base_url):
        async with await _session() as session:
            findings = await run_payload_checks(session, base_url + "/transfer-form", RULES, active_mode=False)
        finding = next(f for f in findings if f.rule_id == "CSRF_TOKEN_NOT_VALIDATED")
        assert finding.verdict == Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION


class TestUnauthenticatedAccessLive:
    def _authed_session(self) -> DastSession:
        return DastSession(ActorConfig(auth_mode=AuthMode.BEARER, bearer_token=OWNER_BEARER_TOKEN))

    async def test_enforced_route_passes(self, base_url):
        async with self._authed_session() as session:
            findings = await run_payload_checks(session, base_url + "/admin", RULES, active_mode=False)
        finding = next(f for f in findings if f.rule_id == "UNAUTHENTICATED_ACCESS_ALLOWED")
        assert finding.verdict == Verdict.PASS

    async def test_open_route_fails(self, base_url):
        async with self._authed_session() as session:
            findings = await run_payload_checks(session, base_url + "/admin-open", RULES, active_mode=False)
        finding = next(f for f in findings if f.rule_id == "UNAUTHENTICATED_ACCESS_ALLOWED")
        assert finding.verdict == Verdict.FAIL

    async def test_unauthenticated_scan_is_not_configured(self, base_url):
        async with await _session() as session:  # AuthMode.NONE
            findings = await run_payload_checks(session, base_url + "/admin", RULES, active_mode=False)
        finding = next(f for f in findings if f.rule_id == "UNAUTHENTICATED_ACCESS_ALLOWED")
        assert finding.verdict == Verdict.NOT_CONFIGURED


class TestStoredXssProbeLive:
    async def test_unescaped_wall_fails(self, base_url, live_server):
        live_server.reset_comment_state()
        form = DiscoveredForm(
            action_url=base_url + "/comment", method="POST", fields=["comment"],
            source_url=base_url + "/comment-form",
        )
        async with await _session() as session:
            finding = await run_stored_xss_probe(
                session, form, [base_url + "/comment-wall"], active_mode=True,
            )
        assert finding.verdict == Verdict.FAIL
        assert finding.url == base_url + "/comment-wall"

    async def test_escaped_wall_passes(self, base_url, live_server):
        live_server.reset_comment_state()
        form = DiscoveredForm(
            action_url=base_url + "/comment-safe", method="POST", fields=["comment"],
            source_url=base_url + "/comment-form-safe",
        )
        async with await _session() as session:
            finding = await run_stored_xss_probe(
                session, form, [base_url + "/comment-wall-safe"], active_mode=True,
            )
        assert finding.verdict == Verdict.PASS

    async def test_skipped_without_active_mode(self, base_url):
        form = DiscoveredForm(
            action_url=base_url + "/comment", method="POST", fields=["comment"],
            source_url=base_url + "/comment-form",
        )
        async with await _session() as session:
            finding = await run_stored_xss_probe(session, form, [base_url + "/comment-wall"])
        assert finding.verdict == Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION

    async def test_crawler_discovered_form_feeds_probe_end_to_end(self, base_url, live_server):
        # The actual production path (scan_service._run_dynamic_checks): crawl
        # first to discover the form, then feed exactly what the crawler found
        # (not a hand-built DiscoveredForm) into the probe.
        live_server.reset_comment_state()
        async with await _session() as session:
            crawl_result = await crawl(session, base_url + "/comment-form")
            form = next(f for f in crawl_result.forms if f.action_url == base_url + "/comment")
            finding = await run_stored_xss_probe(
                session, form, [base_url + "/comment-wall"], active_mode=True,
            )
        assert finding.verdict == Verdict.FAIL


class TestReflectedXssLive:
    async def test_unescaped_search_fails(self, base_url):
        async with await _session() as session:
            findings = await run_payload_checks(session, base_url + "/search?q=hello", RULES)
        finding = next(f for f in findings if f.rule_id == "REFLECTED_XSS_LIVE")
        assert finding.verdict == Verdict.FAIL

    async def test_escaped_search_passes(self, base_url):
        async with await _session() as session:
            findings = await run_payload_checks(session, base_url + "/search-safe?q=hello", RULES)
        finding = next(f for f in findings if f.rule_id == "REFLECTED_XSS_LIVE")
        assert finding.verdict == Verdict.PASS

    async def test_no_query_string_is_not_tested(self, base_url):
        async with await _session() as session:
            findings = await run_payload_checks(session, base_url + "/page1", RULES)
        finding = next(f for f in findings if f.rule_id == "REFLECTED_XSS_LIVE")
        assert finding.verdict == Verdict.NOT_TESTED


class TestSqlInjectionLive:
    async def test_unescaped_query_fails(self, base_url):
        async with await _session() as session:
            findings = await run_payload_checks(
                session, base_url + "/products?id=1", RULES, active_mode=True,
            )
        finding = next(f for f in findings if f.rule_id == "SQL_INJECTION_LIVE")
        assert finding.verdict == Verdict.FAIL

    async def test_parameterized_query_passes(self, base_url):
        async with await _session() as session:
            findings = await run_payload_checks(
                session, base_url + "/products-safe?id=1", RULES, active_mode=True,
            )
        finding = next(f for f in findings if f.rule_id == "SQL_INJECTION_LIVE")
        assert finding.verdict == Verdict.PASS

    async def test_skipped_without_active_mode(self, base_url):
        async with await _session() as session:
            findings = await run_payload_checks(session, base_url + "/products?id=1", RULES, active_mode=False)
        finding = next(f for f in findings if f.rule_id == "SQL_INJECTION_LIVE")
        assert finding.verdict == Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION


class TestSsrfProbeLive:
    # The real proof of Track A2: the fixture server (/fetch) makes a real
    # server-side HTTP request to the collaborator, over a real loopback
    # socket the collaborator itself is listening on — not mocked at any
    # layer. This is the whole point of the out-of-band design.
    async def test_vulnerable_fetch_endpoint_fails(self, base_url):
        with CollaboratorServer() as collab:
            async with await _session() as session:
                finding = await run_ssrf_probe(
                    session, base_url + "/fetch", collab, active_mode=True,
                    callback_wait_seconds=1.0, candidate_params=["url"],
                )
        assert finding.verdict == Verdict.FAIL
        assert "url" in finding.note

    async def test_safe_fetch_endpoint_passes(self, base_url):
        with CollaboratorServer() as collab:
            async with await _session() as session:
                finding = await run_ssrf_probe(
                    session, base_url + "/fetch-safe", collab, active_mode=True,
                    callback_wait_seconds=1.0, candidate_params=["url"],
                )
        assert finding.verdict == Verdict.PASS

    async def test_skipped_without_active_mode(self, base_url):
        with CollaboratorServer() as collab:
            async with await _session() as session:
                finding = await run_ssrf_probe(session, base_url + "/fetch", collab, candidate_params=["url"])
        assert finding.verdict == Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION


class TestSessionRefreshLive:
    # /protected-data's session expires after 2 successful accesses
    # (dast_vuln_server.py's _LOGIN_EXPIRE_AFTER) — the 3rd request here
    # would come back 401 without Track C4's real re-login-and-retry over
    # an actual socket.
    async def test_expired_session_is_transparently_refreshed(self, base_url, live_server):
        live_server.reset_login_state()
        form = FormLoginConfig(
            login_url=base_url + "/login", username_field="username", password_field="password",
            username=LOGIN_USERNAME, password=LOGIN_PASSWORD,
        )
        actor = ActorConfig(auth_mode=AuthMode.FORM_LOGIN, form_login=form)
        async with DastSession(actor) as session:
            r1 = await session.request("GET", base_url + "/protected-data")
            r2 = await session.request("GET", base_url + "/protected-data")
            r3 = await session.request("GET", base_url + "/protected-data")

        assert r1.status_code == 200
        assert r2.status_code == 200
        assert r3.status_code == 200


@requires_chromium
class TestBrowserCrawlerLive:
    # /spa's raw HTTP body has no <a href> at all — crawler.crawl() (the
    # regex crawler) would see nothing here. Only a real headless browser,
    # letting /spa's own inline <script> run and write the link into the
    # DOM, discovers /spa-next at all.
    async def test_discovers_js_rendered_link_and_form(self, base_url):
        result = await crawl_with_browser(base_url + "/spa", max_pages=5, max_depth=1)

        assert base_url + "/spa" in result.urls
        assert base_url + "/spa-next" in result.urls


@requires_chromium
class TestDomXssProbeLive:
    # Real headless Chromium, real JS execution — proves the FAIL/PASS
    # split isn't a mocked assumption: /spa's decodeURIComponent(location.hash)
    # -> innerHTML really does execute the marker payload, and /spa-safe's
    # textContent-based sink really doesn't.
    async def test_vulnerable_spa_hash_sink_flagged_fail(self, base_url):
        from playwright.async_api import async_playwright

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                context = await browser.new_context()
                finding = await run_dom_xss_probe(context, base_url + "/spa", active_mode=True)
            finally:
                await browser.close()

        assert finding.verdict == Verdict.FAIL

    async def test_safe_spa_text_content_sink_passes(self, base_url):
        from playwright.async_api import async_playwright

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                context = await browser.new_context()
                finding = await run_dom_xss_probe(context, base_url + "/spa-safe", active_mode=True)
            finally:
                await browser.close()

        assert finding.verdict == Verdict.PASS

    async def test_skipped_without_active_mode(self, base_url):
        from playwright.async_api import async_playwright

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                context = await browser.new_context()
                finding = await run_dom_xss_probe(context, base_url + "/spa", active_mode=False)
            finally:
                await browser.close()

        assert finding.verdict == Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION


class TestOpenApiDiscoveryLive:
    # Proves the integration point, not a new check: discovery produces real
    # URLs (fetched + parsed against an actual socket, not a mock), and
    # those URLs get correctly flagged FAIL by the *existing*
    # REFLECTED_XSS_LIVE / SQL_INJECTION_LIVE checks — exactly the same as
    # if the crawler itself had found /search and /products.
    async def test_fetch_and_parse_real_spec(self, base_url):
        async with await _session() as session:
            spec = await fetch_openapi_spec(session, base_url + "/openapi.json")
            endpoints = parse_openapi_spec(spec, base_url)

        urls = {e.url for e in endpoints}
        assert f"{base_url}/search?q=test" in urls
        assert f"{base_url}/products?id=1" in urls

    async def test_discovered_urls_are_flagged_by_existing_live_checks(self, base_url):
        async with await _session() as session:
            spec = await fetch_openapi_spec(session, base_url + "/openapi.json")
            endpoints = parse_openapi_spec(spec, base_url)

            # active_mode=True: SQL_INJECTION_LIVE (unlike REFLECTED_XSS_LIVE)
            # is requires_active_mode in dynamic_queries.json, since its
            # boolean-blind probe reaches a real query rather than just
            # reading a response back.
            findings_by_url = {}
            for endpoint in endpoints:
                findings_by_url[endpoint.url] = await run_payload_checks(
                    session, endpoint.url, RULES, active_mode=True,
                )

        search_findings = findings_by_url[f"{base_url}/search?q=test"]
        by_rule = {f.rule_id: f for f in search_findings}
        assert by_rule["REFLECTED_XSS_LIVE"].verdict == Verdict.FAIL

        products_findings = findings_by_url[f"{base_url}/products?id=1"]
        by_rule = {f.rule_id: f for f in products_findings}
        assert by_rule["SQL_INJECTION_LIVE"].verdict == Verdict.FAIL
