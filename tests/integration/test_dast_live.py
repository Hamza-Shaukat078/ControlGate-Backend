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
from app.domain.analysis.dast.config import ActorConfig, AuthMode, DynamicScanConfig
from app.domain.analysis.dast.crawler import DiscoveredForm, crawl
from app.domain.analysis.dast.idor_probe import IdorProbeConfig, run_idor_probe
from app.domain.analysis.dast.race_probe import RaceProbeConfig, run_race_probe
from app.domain.analysis.dast.rule_loader import load_dynamic_queries
from app.domain.analysis.dast.session import DastSession, DastSessionPair
from app.domain.analysis.dast.verdict import Verdict
from app.domain.analysis.dast.xss_probe import run_stored_xss_probe
from tests.fixtures.dast_vuln_server import OWNER_BEARER_TOKEN, VulnFixtureServer

RULES = load_dynamic_queries(Path(__file__).resolve().parents[2] / "queries" / "dynamic_queries.json")


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
