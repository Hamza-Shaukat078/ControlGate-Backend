"""Track B of the static+dynamic completion plan — a regression corpus for
the dynamic rule catalog, the same role tests/integration/test_sample_app_scan.py
plays for the static one: one authoritative table of "this exact route is
known-vulnerable / known-safe for this exact rule", run against the real
fixture server (tests/fixtures/dast_vuln_server.py), asserting the whole
verdict matrix in one place.

Every individual check already has its own live tests in test_dast_live.py
— those catch a single check regressing. This file exists for a different
failure mode: a shared helper (e.g. _responses_differ_significantly,
DastSession.request, run_payload_checks' rule-filtering) silently breaking
*several* rules at once, or a new rule shadowing/interfering with an
existing one when they run back-to-back against the same target. Nothing
today would catch that except re-running every check by hand.

test_corpus_covers_every_payload_check is the actual regression gate for
future rule additions: it fails the build if a new rule_id lands in
checks.py's _CHECK_FUNCTIONS (or xss_probe.py's fixed rule_id) without a
matching entry in the tables below — the same "you must not forget this"
enforcement _same_finding/_dedupe_vulnerabilities' tests give the static
dedupe logic.
"""
from pathlib import Path

import pytest

from app.domain.analysis.dast import session as session_module
from app.domain.analysis.dast.checks import _CHECK_FUNCTIONS, run_payload_checks
from app.domain.analysis.dast.collaborator import CollaboratorServer
from app.domain.analysis.dast.config import ActorConfig, AuthMode, DynamicScanConfig
from app.domain.analysis.dast.crawler import DiscoveredForm
from app.domain.analysis.dast.idor_probe import IdorProbeConfig, run_idor_probe
from app.domain.analysis.dast.race_probe import RaceProbeConfig, run_race_probe
from app.domain.analysis.dast.rule_loader import load_dynamic_queries
from app.domain.analysis.dast.session import DastSession, DastSessionPair
from app.domain.analysis.dast.ssrf_probe import run_ssrf_probe
from app.domain.analysis.dast.verdict import Verdict
from app.domain.analysis.dast.xss_probe import run_stored_xss_probe
from tests.fixtures.dast_vuln_server import OWNER_BEARER_TOKEN, VulnFixtureServer

RULES = load_dynamic_queries(Path(__file__).resolve().parents[2] / "queries" / "dynamic_queries.json")

# rule_id -> (vulnerable path, safe path or None if no deterministic safe
# fixture exists yet). REQUEST_SMUGGLING has no entry: a single naive
# http.server can't reproduce a real front-end/back-end desync either way
# (documented limitation, see test_dast_live.py's smuggling test) — it's
# deliberately excluded from the verdict matrix, not silently forgotten.
_PAYLOAD_CHECK_TARGETS = {
    "DOUBLE_DECODE_BYPASS": ("/traverse", "/traverse-safe"),
    "CRLF_HEADER_REFLECTION": ("/redirect?next=/page1", "/redirect-safe?next=/page1"),
    "OPEN_REDIRECT_LIVE": ("/redirect?next=/page1", "/redirect-safe?next=/page1"),
    "CSRF_TOKEN_NOT_VALIDATED": ("/transfer-form", "/transfer-form-safe"),
    "UNAUTHENTICATED_ACCESS_ALLOWED": ("/admin-open", "/admin"),
    "REFLECTED_XSS_LIVE": ("/search?q=hello", "/search-safe?q=hello"),
    "SQL_INJECTION_LIVE": ("/products?id=1", "/products-safe?id=1"),
}
_NO_DETERMINISTIC_FIXTURE = {"REQUEST_SMUGGLING"}

# UNAUTHENTICATED_ACCESS_ALLOWED needs an authenticated baseline session to
# compare against (NOT_CONFIGURED otherwise) — every other check here is
# fine unauthenticated.
_RULES_NEEDING_AUTH = {"UNAUTHENTICATED_ACCESS_ALLOWED"}


def _actor_for(rule_id: str) -> ActorConfig:
    if rule_id in _RULES_NEEDING_AUTH:
        return ActorConfig(auth_mode=AuthMode.BEARER, bearer_token=OWNER_BEARER_TOKEN)
    return ActorConfig()


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


class TestCorpusCompleteness:
    def test_corpus_covers_every_payload_check(self):
        covered = set(_PAYLOAD_CHECK_TARGETS) | _NO_DETERMINISTIC_FIXTURE
        assert covered == set(_CHECK_FUNCTIONS.keys()), (
            "A rule_id was added to/removed from checks.py's _CHECK_FUNCTIONS without "
            "updating this corpus's expected-verdict table (or _NO_DETERMINISTIC_FIXTURE, "
            "for a rule with no deterministic vulnerable/safe fixture) — add it above."
        )


class TestPayloadCheckCorpus:
    @pytest.mark.parametrize("rule_id", sorted(_PAYLOAD_CHECK_TARGETS))
    async def test_vulnerable_route_fails(self, rule_id, base_url):
        vulnerable_path, _ = _PAYLOAD_CHECK_TARGETS[rule_id]
        async with DastSession(_actor_for(rule_id)) as session:
            findings = await run_payload_checks(
                session, base_url + vulnerable_path, {rule_id: RULES[rule_id]}, active_mode=True,
            )
        assert findings[0].verdict == Verdict.FAIL, (
            f"{rule_id} was expected to FAIL against its known-vulnerable fixture "
            f"route ({vulnerable_path}) but got {findings[0].verdict}: {findings[0].note}"
        )

    @pytest.mark.parametrize("rule_id", sorted(_PAYLOAD_CHECK_TARGETS))
    async def test_safe_route_passes(self, rule_id, base_url):
        _, safe_path = _PAYLOAD_CHECK_TARGETS[rule_id]
        async with DastSession(_actor_for(rule_id)) as session:
            findings = await run_payload_checks(
                session, base_url + safe_path, {rule_id: RULES[rule_id]}, active_mode=True,
            )
        assert findings[0].verdict == Verdict.PASS, (
            f"{rule_id} was expected to PASS against its known-safe fixture route "
            f"({safe_path}) but got {findings[0].verdict}: {findings[0].note}"
        )


class TestStoredXssCorpus:
    async def test_vulnerable_form_fails(self, base_url, live_server):
        live_server.reset_comment_state()
        form = DiscoveredForm(
            action_url=base_url + "/comment", method="POST", fields=["comment"],
            source_url=base_url + "/comment-form",
        )
        async with DastSession(ActorConfig()) as session:
            finding = await run_stored_xss_probe(
                session, form, [base_url + "/comment-wall"], active_mode=True,
            )
        assert finding.verdict == Verdict.FAIL

    async def test_safe_form_passes(self, base_url, live_server):
        live_server.reset_comment_state()
        form = DiscoveredForm(
            action_url=base_url + "/comment-safe", method="POST", fields=["comment"],
            source_url=base_url + "/comment-form-safe",
        )
        async with DastSession(ActorConfig()) as session:
            finding = await run_stored_xss_probe(
                session, form, [base_url + "/comment-wall-safe"], active_mode=True,
            )
        assert finding.verdict == Verdict.PASS


class TestRaceProbeCorpus:
    async def test_vulnerable_endpoint_fails(self, base_url, live_server):
        live_server.reset_race_state()
        config = DynamicScanConfig(target_url=base_url, actor=ActorConfig())
        async with DastSessionPair(config) as pair:
            finding = await run_race_probe(
                pair,
                RaceProbeConfig(
                    scenario_id="CORPUS_RACE", url=base_url + "/redeem-vulnerable",
                    concurrency=5, max_expected_successes=1,
                ),
                active_mode=True,
            )
        assert finding.verdict == Verdict.FAIL

    async def test_safe_endpoint_passes(self, base_url, live_server):
        live_server.reset_race_state()
        config = DynamicScanConfig(target_url=base_url, actor=ActorConfig())
        async with DastSessionPair(config) as pair:
            finding = await run_race_probe(
                pair,
                RaceProbeConfig(
                    scenario_id="CORPUS_RACE", url=base_url + "/redeem-safe",
                    concurrency=5, max_expected_successes=1,
                ),
                active_mode=True,
            )
        assert finding.verdict == Verdict.PASS


class TestIdorProbeCorpus:
    def _pair(self, base_url):
        config = DynamicScanConfig(
            target_url=base_url,
            actor=ActorConfig(auth_mode=AuthMode.BEARER, bearer_token=OWNER_BEARER_TOKEN),
            second_actor=ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="attacker-token"),
        )
        return DastSessionPair(config)

    async def test_vulnerable_endpoint_fails(self, base_url):
        async with self._pair(base_url) as pair:
            finding = await run_idor_probe(
                pair, IdorProbeConfig(scenario_id="CORPUS_IDOR", owner_resource_url=base_url + "/profile/42"),
            )
        assert finding.verdict == Verdict.FAIL

    async def test_safe_endpoint_passes(self, base_url):
        async with self._pair(base_url) as pair:
            finding = await run_idor_probe(
                pair, IdorProbeConfig(scenario_id="CORPUS_IDOR", owner_resource_url=base_url + "/orders/42"),
            )
        assert finding.verdict == Verdict.PASS


class TestSsrfProbeCorpus:
    async def test_vulnerable_endpoint_fails(self, base_url):
        with CollaboratorServer() as collab:
            async with DastSession(ActorConfig()) as session:
                finding = await run_ssrf_probe(
                    session, base_url + "/fetch", collab, active_mode=True,
                    callback_wait_seconds=1.0, candidate_params=["url"],
                )
        assert finding.verdict == Verdict.FAIL

    async def test_safe_endpoint_passes(self, base_url):
        with CollaboratorServer() as collab:
            async with DastSession(ActorConfig()) as session:
                finding = await run_ssrf_probe(
                    session, base_url + "/fetch-safe", collab, active_mode=True,
                    callback_wait_seconds=1.0, candidate_params=["url"],
                )
        assert finding.verdict == Verdict.PASS
