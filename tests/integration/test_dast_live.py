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
from app.domain.analysis.dast.config import ActorConfig, DynamicScanConfig
from app.domain.analysis.dast.crawler import crawl
from app.domain.analysis.dast.race_probe import RaceProbeConfig, run_race_probe
from app.domain.analysis.dast.rule_loader import load_dynamic_queries
from app.domain.analysis.dast.session import DastSession, DastSessionPair
from app.domain.analysis.dast.verdict import Verdict
from tests.fixtures.dast_vuln_server import VulnFixtureServer

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
