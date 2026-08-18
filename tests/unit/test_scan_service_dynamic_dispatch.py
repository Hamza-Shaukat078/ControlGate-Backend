"""Phase 2B API wiring — ScanService._run_dynamic_scan building the correct
ActorConfig from dynamic_auth_mode/dynamic_bearer_token/dynamic_form_login,
and correctly gating the LOGOUT_INVALIDATES_SESSION scenario on whether auth
is configured and whether a logout endpoint was discovered.

Mocks DastSessionPair/run_payload_checks/discover_logout_url/run_scenario so
no real network calls happen — this tests the *glue*, not the checks
themselves (those are covered by test_dast_session.py/test_dast_checks.py/
test_dast_scenario.py already).
"""
import asyncio
import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mongomock_motor import AsyncMongoMockClient

from app.domain.analysis.dast.config import AuthMode
from app.domain.analysis.dast.crawler import CrawlResult, DiscoveredForm
from app.domain.analysis.dast.findings import DynamicFinding
from app.domain.analysis.dast.verdict import Verdict
from app.services.scan_service import ScanService

TARGET = "https://example.com"  # validate_public_http_url() at the top of _run_dynamic_scan
# resolves this for real (resolve=True, not overridable from here) — DNS is mocked below
# so these tests don't depend on real network, matching test_ingestion_hardening.py's pattern.


@pytest.fixture(autouse=True)
def _mock_dns(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))],
    )


class _FakeCollaboratorServer:
    """No real socket/thread — every dynamic_active_mode=True test in this
    file now also exercises the SSRF probe's collaborator startup
    (scan_service._run_dynamic_checks starts one whenever active_mode is
    set, regardless of what else the test cares about); autouse-patching
    this class file-wide keeps those tests fast the same way DastSessionPair
    is faked, rather than touching every active_mode=True call site."""

    def __init__(self, *args, **kwargs):
        pass

    def new_token(self) -> str:
        return "fake-token"

    def callback_url(self, token: str) -> str:
        return f"http://fake-collaborator.invalid/{token}"

    def hits_for(self, token: str) -> list:
        return []

    def start(self) -> "_FakeCollaboratorServer":
        return self

    def stop(self) -> None:
        pass

    def __enter__(self) -> "_FakeCollaboratorServer":
        return self.start()

    def __exit__(self, *exc_info) -> bool:
        return False


@pytest.fixture(autouse=True)
def _fake_collaborator(monkeypatch):
    monkeypatch.setattr(
        "app.domain.analysis.dast.collaborator.CollaboratorServer", _FakeCollaboratorServer,
    )


class _FakePrimarySession:
    """Stands in for pair.primary — just enough surface for the
    logout-invalidates-session baseline check (request_unauthenticated) to
    call. Defaults to "not public" (raises, like a plain object() would)
    so every pre-existing test that doesn't care about this baseline check
    keeps falling through to run_scenario exactly as before."""

    def __init__(self, baseline_status: int | None = None):
        self.baseline_status = baseline_status

    async def request_unauthenticated(self, method, url, **kwargs):
        if self.baseline_status is None:
            raise AttributeError("request_unauthenticated not configured for this test")
        return MagicMock(status_code=self.baseline_status)


class _FakeSessionPair:
    """Captures the DynamicScanConfig it was constructed with so tests can
    assert on it, and behaves as an async context manager like the real one."""

    last_config = None
    baseline_status = None  # class-level knob tests can set before calling _run_dynamic_scan

    def __init__(self, config):
        _FakeSessionPair.last_config = config
        self.primary = _FakePrimarySession(_FakeSessionPair.baseline_status)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False


async def _make_service():
    db = AsyncMongoMockClient()["test"]
    return ScanService(db), db


class TestActorConfigConstruction:
    @pytest.mark.asyncio
    async def test_bearer_mode_builds_actor_with_token(self):
        svc, db = await _make_service()
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)):
            await svc._run_dynamic_scan(
                "scan-1", TARGET, dynamic_auth_mode="bearer", dynamic_bearer_token="tok-abc",
            )
        actor = _FakeSessionPair.last_config.actor
        assert actor.auth_mode == AuthMode.BEARER
        assert actor.bearer_token == "tok-abc"

    @pytest.mark.asyncio
    async def test_form_login_mode_builds_actor_with_form_config(self):
        svc, db = await _make_service()
        form = {
            "login_url": f"{TARGET}/login", "username_field": "user", "password_field": "pass",
            "username": "alice", "password": "hunter2",
        }
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)):
            await svc._run_dynamic_scan(
                "scan-2", TARGET, dynamic_auth_mode="form_login", dynamic_form_login=form,
            )
        actor = _FakeSessionPair.last_config.actor
        assert actor.auth_mode == AuthMode.FORM_LOGIN
        assert actor.form_login.username == "alice"
        assert actor.form_login.password == "hunter2"

    @pytest.mark.asyncio
    async def test_no_second_actor_by_default(self):
        svc, db = await _make_service()
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)):
            await svc._run_dynamic_scan("scan-2b", TARGET)
        assert _FakeSessionPair.last_config.second_actor is None

    @pytest.mark.asyncio
    async def test_second_actor_bearer_mode_builds_correctly(self):
        svc, db = await _make_service()
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)):
            await svc._run_dynamic_scan(
                "scan-2c", TARGET,
                dynamic_second_actor_auth_mode="bearer", dynamic_second_actor_bearer_token="tok-second",
            )
        second_actor = _FakeSessionPair.last_config.second_actor
        assert second_actor is not None
        assert second_actor.auth_mode == AuthMode.BEARER
        assert second_actor.bearer_token == "tok-second"

    @pytest.mark.asyncio
    async def test_primary_and_second_actor_are_independent(self):
        svc, db = await _make_service()
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)):
            await svc._run_dynamic_scan(
                "scan-2d", TARGET,
                dynamic_auth_mode="bearer", dynamic_bearer_token="tok-primary",
                dynamic_second_actor_auth_mode="bearer", dynamic_second_actor_bearer_token="tok-second",
            )
        config = _FakeSessionPair.last_config
        assert config.actor.bearer_token == "tok-primary"
        assert config.second_actor.bearer_token == "tok-second"

    @pytest.mark.asyncio
    async def test_none_mode_leaves_actor_unauthenticated(self):
        svc, db = await _make_service()
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])):
            await svc._run_dynamic_scan("scan-3", TARGET)
        actor = _FakeSessionPair.last_config.actor
        assert actor.auth_mode == AuthMode.NONE


class TestLogoutScenarioGating:
    @pytest.mark.asyncio
    async def test_no_logout_scenario_attempted_when_auth_is_none(self):
        svc, db = await _make_service()
        discover_mock = AsyncMock(return_value=f"{TARGET}/logout")
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", discover_mock):
            await svc._run_dynamic_scan("scan-4", TARGET)  # dynamic_auth_mode defaults to "none"
        discover_mock.assert_not_called()

    @pytest.mark.asyncio
    async def test_not_tested_finding_when_no_logout_discovered(self):
        svc, db = await _make_service()
        await db.scans.insert_one({"scan_id": "scan-5", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)):
            await svc._run_dynamic_scan(
                "scan-5", TARGET, dynamic_auth_mode="bearer", dynamic_bearer_token="tok",
            )
        doc = await db.scans.find_one({"scan_id": "scan-5"})
        findings = doc["summary"]["dynamic_findings"]
        logout_finding = next(f for f in findings if f["rule_id"] == "LOGOUT_INVALIDATES_SESSION")
        assert logout_finding["verdict"] == "not_tested"

    @pytest.mark.asyncio
    async def test_scenario_runs_and_result_is_recorded_when_logout_discovered(self):
        svc, db = await _make_service()
        scenario_finding = DynamicFinding(
            control_id="V7.4.1", verdict=Verdict.PASS, rule_id="LOGOUT_INVALIDATES_SESSION",
            url=TARGET, method="GET", note="ok", severity="high",
        )
        await db.scans.insert_one({"scan_id": "scan-6", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url",
                   AsyncMock(return_value=f"{TARGET}/logout")), \
             patch("app.domain.analysis.dast.scenario_runner.run_scenario",
                   AsyncMock(return_value=scenario_finding)):
            await svc._run_dynamic_scan(
                "scan-6", TARGET, dynamic_auth_mode="bearer", dynamic_bearer_token="tok",
            )
        doc = await db.scans.find_one({"scan_id": "scan-6"})
        findings = doc["summary"]["dynamic_findings"]
        logout_finding = next(f for f in findings if f["rule_id"] == "LOGOUT_INVALIDATES_SESSION")
        assert logout_finding["verdict"] == "pass"

    @pytest.mark.asyncio
    async def test_publicly_reachable_target_skips_scenario_as_not_tested(self):
        # target_url is very often a bare origin root — a public SPA shell
        # or a public service-info/health endpoint — never actually gated
        # by the session. Running the post-logout assertion against it
        # produces a misleading FAIL (it's reachable after logout because
        # it's *always* reachable). Confirmed false positive against a real
        # scan. A baseline unauthenticated request establishes this and
        # skips the scenario instead of running it.
        svc, db = await _make_service()
        run_scenario_mock = AsyncMock()
        await db.scans.insert_one({"scan_id": "scan-6b", "state": "PENDING"})
        _FakeSessionPair.baseline_status = 200
        try:
            with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
                 patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
                 patch("app.domain.analysis.dynamic_probe.DynamicProbe.probe", AsyncMock(return_value=[])), \
                 patch("app.domain.analysis.dast.logout_discovery.discover_logout_url",
                       AsyncMock(return_value=f"{TARGET}/logout")), \
                 patch("app.domain.analysis.dast.scenario_runner.run_scenario", run_scenario_mock):
                await svc._run_dynamic_scan(
                    "scan-6b", TARGET, dynamic_auth_mode="bearer", dynamic_bearer_token="tok",
                )
        finally:
            _FakeSessionPair.baseline_status = None
        run_scenario_mock.assert_not_called()
        doc = await db.scans.find_one({"scan_id": "scan-6b"})
        findings = doc["summary"]["dynamic_findings"]
        logout_finding = next(f for f in findings if f["rule_id"] == "LOGOUT_INVALIDATES_SESSION")
        assert logout_finding["verdict"] == "not_tested"
        assert "publicly reachable" in logout_finding["note"]

    @pytest.mark.asyncio
    async def test_protected_target_still_runs_the_scenario(self):
        # The baseline unauthenticated request comes back gated (403) —
        # target_url IS a protected resource, so the scenario should run
        # exactly as before this fix.
        svc, db = await _make_service()
        scenario_finding = DynamicFinding(
            control_id="V7.4.1", verdict=Verdict.PASS, rule_id="LOGOUT_INVALIDATES_SESSION",
            url=TARGET, method="GET", note="ok", severity="high",
        )
        run_scenario_mock = AsyncMock(return_value=scenario_finding)
        await db.scans.insert_one({"scan_id": "scan-6c", "state": "PENDING"})
        _FakeSessionPair.baseline_status = 403
        try:
            with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
                 patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
                 patch("app.domain.analysis.dynamic_probe.DynamicProbe.probe", AsyncMock(return_value=[])), \
                 patch("app.domain.analysis.dast.logout_discovery.discover_logout_url",
                       AsyncMock(return_value=f"{TARGET}/logout")), \
                 patch("app.domain.analysis.dast.scenario_runner.run_scenario", run_scenario_mock):
                await svc._run_dynamic_scan(
                    "scan-6c", TARGET, dynamic_auth_mode="bearer", dynamic_bearer_token="tok",
                )
        finally:
            _FakeSessionPair.baseline_status = None
        run_scenario_mock.assert_called_once()
        doc = await db.scans.find_one({"scan_id": "scan-6c"})
        findings = doc["summary"]["dynamic_findings"]
        logout_finding = next(f for f in findings if f["rule_id"] == "LOGOUT_INVALIDATES_SESSION")
        assert logout_finding["verdict"] == "pass"

    @pytest.mark.asyncio
    async def test_baseline_check_failure_falls_back_to_running_the_scenario(self):
        # If the baseline request itself errors out (network hiccup, etc.),
        # this must not silently drop the check — fall back to running the
        # scenario exactly as before this fix existed.
        svc, db = await _make_service()
        scenario_finding = DynamicFinding(
            control_id="V7.4.1", verdict=Verdict.PASS, rule_id="LOGOUT_INVALIDATES_SESSION",
            url=TARGET, method="GET", note="ok", severity="high",
        )
        run_scenario_mock = AsyncMock(return_value=scenario_finding)
        await db.scans.insert_one({"scan_id": "scan-6d", "state": "PENDING"})
        _FakeSessionPair.baseline_status = None  # _FakePrimarySession raises AttributeError
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dynamic_probe.DynamicProbe.probe", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url",
                   AsyncMock(return_value=f"{TARGET}/logout")), \
             patch("app.domain.analysis.dast.scenario_runner.run_scenario", run_scenario_mock):
            await svc._run_dynamic_scan(
                "scan-6d", TARGET, dynamic_auth_mode="bearer", dynamic_bearer_token="tok",
            )
        run_scenario_mock.assert_called_once()


class TestScanDocRecordsAuthMode:
    @pytest.mark.asyncio
    async def test_scan_doc_records_non_secret_auth_mode_only(self):
        svc, db = await _make_service()
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)):
            scan_id, _ = await svc.start(
                user_id="507f1f77bcf86cd799439011", scan_type="dynamic", target_url=TARGET,
                dynamic_auth_mode="bearer", dynamic_bearer_token="super-secret-token",
            )
            for _ in range(50):
                doc = await db.scans.find_one({"scan_id": scan_id})
                if doc["state"] in ("COMPLETED", "FAILED"):
                    break
                await asyncio.sleep(0.05)
        assert doc["dynamic_auth_mode"] == "bearer"
        assert "super-secret-token" not in str(doc)


class TestCrawlerWiring:
    """Phase 3 — crawler output must widen which URLs get payload-checked,
    capped, deduped against target_url, and captured forms must reach the
    scan summary without ever being submitted (that's the crawler's own
    job, verified in test_dast_crawler.py; this just checks the glue)."""

    @pytest.mark.asyncio
    async def test_discovered_urls_are_passed_to_payload_checks_capped_at_five(self):
        svc, db = await _make_service()
        from app.domain.analysis.dast.crawler import CrawlResult

        crawl_result = CrawlResult(urls=[TARGET] + [f"{TARGET}/p{i}" for i in range(8)], forms=[])
        run_checks_mock = AsyncMock(return_value=[])
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=crawl_result)), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", run_checks_mock), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)):
            await svc._run_dynamic_scan("scan-7", TARGET)

        called_urls = run_checks_mock.call_args.args[1]
        assert called_urls[0] == TARGET
        assert len(called_urls) == 1 + 5  # target_url + capped 5 additional

    @pytest.mark.asyncio
    async def test_discovered_forms_reach_scan_summary_uncalled(self):
        svc, db = await _make_service()
        from app.domain.analysis.dast.crawler import CrawlResult, DiscoveredForm

        form = DiscoveredForm(action_url=f"{TARGET}/search", method="POST", fields=["q"], source_url=TARGET)
        crawl_result = CrawlResult(urls=[TARGET], forms=[form])
        await db.scans.insert_one({"scan_id": "scan-8", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=crawl_result)), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)):
            await svc._run_dynamic_scan("scan-8", TARGET)

        doc = await db.scans.find_one({"scan_id": "scan-8"})
        forms = doc["summary"]["discovered_forms"]
        assert len(forms) == 1
        assert forms[0]["action_url"] == f"{TARGET}/search"
        assert forms[0]["method"] == "POST"

    @pytest.mark.asyncio
    async def test_crawler_failure_falls_back_to_target_url_only(self):
        svc, db = await _make_service()
        run_checks_mock = AsyncMock(return_value=[])
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(side_effect=RuntimeError("boom"))), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", run_checks_mock), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)):
            await svc._run_dynamic_scan("scan-9", TARGET)

        called_urls = run_checks_mock.call_args.args[1]
        assert called_urls == [TARGET]


class TestDynamicProbeWiring:
    """A pure scan_type="dynamic" run's whole point is testing a live
    target_url — DynamicProbe (the TLS/HTTPS/cert/HSTS/.git-exposure live
    checks backing the catalog's 8 dynamic_probe-labeled ASVS controls) must
    run for it, not only for the hybrid (repo + target_url) path. Regression
    coverage for the gap where dynamic_probe_findings was never populated
    for scan_type="dynamic", leaving those controls permanently not_tested
    for exactly the scan type they matter most for."""

    @pytest.mark.asyncio
    async def test_probe_findings_reach_scan_summary(self):
        svc, db = await _make_service()
        from app.domain.analysis.dynamic_probe import ProbeFinding

        probe_results = [
            ProbeFinding(control_id="V12.1.1", verdict="pass", note="TLS 1.3", confidence=0.85),
            ProbeFinding(control_id="V13.4.1", verdict="fail", note=".git exposed", confidence=0.9),
        ]
        await db.scans.insert_one({"scan_id": "scan-probe-1", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.services.scan_service.DynamicProbe") as mock_probe_cls:
            mock_probe_cls.return_value.probe = AsyncMock(return_value=probe_results)
            await svc._run_dynamic_scan("scan-probe-1", TARGET)

        doc = await db.scans.find_one({"scan_id": "scan-probe-1"})
        findings = doc["summary"]["dynamic_probe_findings"]
        assert len(findings) == 2
        assert {f["control_id"] for f in findings} == {"V12.1.1", "V13.4.1"}

    @pytest.mark.asyncio
    async def test_probe_failure_does_not_abort_scan(self):
        svc, db = await _make_service()
        await db.scans.insert_one({"scan_id": "scan-probe-2", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.services.scan_service.DynamicProbe") as mock_probe_cls:
            mock_probe_cls.return_value.probe = AsyncMock(side_effect=RuntimeError("boom"))
            await svc._run_dynamic_scan("scan-probe-2", TARGET)

        doc = await db.scans.find_one({"scan_id": "scan-probe-2"})
        assert doc["state"] == "COMPLETED"
        assert doc["summary"]["dynamic_probe_findings"] == []


class TestUserSuppliedScenarios:
    """User-supplied dynamic_scenarios (V7.4.3/V8.3.2/V2.3.1-style app-specific
    checks) — verifies the API-shape-to-domain-Scenario conversion actually
    gets invoked and its result recorded, without needing a real target
    (run_scenario itself is covered by test_dast_scenario.py already)."""

    @pytest.mark.asyncio
    async def test_user_scenario_is_converted_and_run(self):
        svc, db = await _make_service()
        scenario_finding = DynamicFinding(
            control_id="V2.3.1", verdict=Verdict.PASS, rule_id="ORDER_STEP_SKIP",
            url=TARGET, method="GET", note="ok", severity="medium",
        )
        run_scenario_mock = AsyncMock(return_value=scenario_finding)
        await db.scans.insert_one({"scan_id": "scan-10", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.scenario_runner.run_scenario", run_scenario_mock):
            await svc._run_dynamic_scan(
                "scan-10", TARGET,
                dynamic_scenarios=[{
                    "scenario_id": "ORDER_STEP_SKIP", "asvs_controls": ["V2.3.1"],
                    "steps": [{"method": "GET", "url": f"{TARGET}/confirm-order",
                               "assert_status_in": [400, 403, 409]}],
                }],
            )

        run_scenario_mock.assert_called_once()
        ran_scenario = run_scenario_mock.call_args.args[1]
        assert ran_scenario.scenario_id == "ORDER_STEP_SKIP"

        doc = await db.scans.find_one({"scan_id": "scan-10"})
        findings = doc["summary"]["dynamic_findings"]
        user_finding = next(f for f in findings if f["rule_id"] == "ORDER_STEP_SKIP")
        assert user_finding["verdict"] == "pass"

    @pytest.mark.asyncio
    async def test_multiple_user_scenarios_all_run(self):
        svc, db = await _make_service()
        run_scenario_mock = AsyncMock(side_effect=[
            DynamicFinding(control_id="V2.3.1", verdict=Verdict.PASS, rule_id="SCENARIO_A",
                           url=TARGET, method="GET", note="ok", severity="medium"),
            DynamicFinding(control_id="V7.4.3", verdict=Verdict.FAIL, rule_id="SCENARIO_B",
                           url=TARGET, method="GET", note="fail", severity="high"),
        ])
        await db.scans.insert_one({"scan_id": "scan-11", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.scenario_runner.run_scenario", run_scenario_mock):
            await svc._run_dynamic_scan(
                "scan-11", TARGET,
                dynamic_scenarios=[
                    {"scenario_id": "SCENARIO_A", "steps": [{"method": "GET", "url": f"{TARGET}/a"}]},
                    {"scenario_id": "SCENARIO_B", "steps": [{"method": "GET", "url": f"{TARGET}/b"}]},
                ],
            )

        assert run_scenario_mock.call_count == 2
        doc = await db.scans.find_one({"scan_id": "scan-11"})
        rule_ids = {f["rule_id"] for f in doc["summary"]["dynamic_findings"]}
        assert {"SCENARIO_A", "SCENARIO_B"}.issubset(rule_ids)

    @pytest.mark.asyncio
    async def test_one_scenario_failing_to_run_does_not_abort_the_scan(self):
        svc, db = await _make_service()
        await db.scans.insert_one({"scan_id": "scan-12", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)):
            # Missing "steps" key — build_scenario_from_request raises KeyError.
            await svc._run_dynamic_scan(
                "scan-12", TARGET,
                dynamic_scenarios=[{"scenario_id": "BROKEN"}],
            )

        doc = await db.scans.find_one({"scan_id": "scan-12"})
        assert doc["state"] == "COMPLETED"

    @pytest.mark.asyncio
    async def test_no_scenarios_supplied_is_a_no_op(self):
        svc, db = await _make_service()
        run_scenario_mock = AsyncMock()
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.scenario_runner.run_scenario", run_scenario_mock):
            await svc._run_dynamic_scan("scan-13", TARGET)
        run_scenario_mock.assert_not_called()


class TestRaceProbeWiring:
    @pytest.mark.asyncio
    async def test_race_probe_is_built_and_run(self):
        svc, db = await _make_service()
        race_finding = DynamicFinding(
            control_id="V2.3.4", verdict=Verdict.FAIL, rule_id="DOUBLE_REDEEM",
            url=f"{TARGET}/redeem", method="POST", note="2 of 5 succeeded", severity="high",
        )
        run_race_probe_mock = AsyncMock(return_value=race_finding)
        await db.scans.insert_one({"scan_id": "scan-14", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.race_probe.run_race_probe", run_race_probe_mock):
            await svc._run_dynamic_scan(
                "scan-14", TARGET,
                dynamic_active_mode=True,
                dynamic_race_probes=[{
                    "scenario_id": "DOUBLE_REDEEM", "url": f"{TARGET}/redeem",
                    "concurrency": 5, "max_expected_successes": 1,
                }],
            )

        run_race_probe_mock.assert_called_once()
        called_config = run_race_probe_mock.call_args.args[1]
        assert called_config.scenario_id == "DOUBLE_REDEEM"
        assert called_config.concurrency == 5

        doc = await db.scans.find_one({"scan_id": "scan-14"})
        findings = doc["summary"]["dynamic_findings"]
        race_result = next(f for f in findings if f["rule_id"] == "DOUBLE_REDEEM")
        assert race_result["verdict"] == "fail"

    @pytest.mark.asyncio
    async def test_broken_race_probe_config_does_not_abort_scan(self):
        svc, db = await _make_service()
        await db.scans.insert_one({"scan_id": "scan-15", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)):
            # Missing required "url" — RaceProbeConfig(**race_data) raises TypeError.
            await svc._run_dynamic_scan(
                "scan-15", TARGET, dynamic_race_probes=[{"scenario_id": "BROKEN"}],
            )
        doc = await db.scans.find_one({"scan_id": "scan-15"})
        assert doc["state"] == "COMPLETED"

    @pytest.mark.asyncio
    async def test_no_race_probes_supplied_is_a_no_op(self):
        svc, db = await _make_service()
        run_race_probe_mock = AsyncMock()
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.race_probe.run_race_probe", run_race_probe_mock):
            await svc._run_dynamic_scan("scan-16", TARGET)
        run_race_probe_mock.assert_not_called()


class TestIdorProbeWiring:
    @pytest.mark.asyncio
    async def test_idor_probe_is_built_and_run(self):
        svc, db = await _make_service()
        idor_finding = DynamicFinding(
            control_id="V8.2.1", verdict=Verdict.FAIL, rule_id="IDOR_ORDER",
            url=f"{TARGET}/orders/42", method="GET", note="second actor got 200", severity="high",
        )
        run_idor_probe_mock = AsyncMock(return_value=idor_finding)
        await db.scans.insert_one({"scan_id": "scan-17", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.idor_probe.run_idor_probe", run_idor_probe_mock):
            await svc._run_dynamic_scan(
                "scan-17", TARGET,
                dynamic_active_mode=True,
                dynamic_idor_probes=[{
                    "scenario_id": "IDOR_ORDER", "owner_resource_url": f"{TARGET}/orders/42",
                }],
            )

        run_idor_probe_mock.assert_called_once()
        called_config = run_idor_probe_mock.call_args.args[1]
        assert called_config.scenario_id == "IDOR_ORDER"
        assert called_config.owner_resource_url == f"{TARGET}/orders/42"

        doc = await db.scans.find_one({"scan_id": "scan-17"})
        findings = doc["summary"]["dynamic_findings"]
        idor_result = next(f for f in findings if f["rule_id"] == "IDOR_ORDER")
        assert idor_result["verdict"] == "fail"

    @pytest.mark.asyncio
    async def test_broken_idor_probe_config_does_not_abort_scan(self):
        svc, db = await _make_service()
        await db.scans.insert_one({"scan_id": "scan-18", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)):
            # Missing required "owner_resource_url" — IdorProbeConfig(**idor_data) raises TypeError.
            await svc._run_dynamic_scan(
                "scan-18", TARGET, dynamic_idor_probes=[{"scenario_id": "BROKEN"}],
            )
        doc = await db.scans.find_one({"scan_id": "scan-18"})
        assert doc["state"] == "COMPLETED"

    @pytest.mark.asyncio
    async def test_no_idor_probes_supplied_is_a_no_op(self):
        svc, db = await _make_service()
        run_idor_probe_mock = AsyncMock()
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.idor_probe.run_idor_probe", run_idor_probe_mock):
            await svc._run_dynamic_scan("scan-19", TARGET)
        run_idor_probe_mock.assert_not_called()


class TestMassAssignmentProbeWiring:
    @pytest.mark.asyncio
    async def test_mass_assignment_probe_is_built_and_run(self):
        svc, db = await _make_service()
        mass_assignment_finding = DynamicFinding(
            control_id="V15.3.3", verdict=Verdict.CONFIRMED, rule_id="MASS_ASSIGN_PROFILE",
            url=f"{TARGET}/profile", method="PATCH", note="role took", severity="high",
        )
        run_mass_assignment_probe_mock = AsyncMock(return_value=mass_assignment_finding)
        await db.scans.insert_one({"scan_id": "scan-20", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch(
                 "app.domain.analysis.dast.mass_assignment_probe.run_mass_assignment_probe",
                 run_mass_assignment_probe_mock,
             ):
            await svc._run_dynamic_scan(
                "scan-20", TARGET,
                dynamic_active_mode=True,
                dynamic_mass_assignment_probes=[{
                    "scenario_id": "MASS_ASSIGN_PROFILE", "update_url": f"{TARGET}/profile",
                }],
            )

        run_mass_assignment_probe_mock.assert_called_once()
        called_config = run_mass_assignment_probe_mock.call_args.args[1]
        assert called_config.scenario_id == "MASS_ASSIGN_PROFILE"
        assert called_config.update_url == f"{TARGET}/profile"

        doc = await db.scans.find_one({"scan_id": "scan-20"})
        findings = doc["summary"]["dynamic_findings"]
        result = next(f for f in findings if f["rule_id"] == "MASS_ASSIGN_PROFILE")
        assert result["verdict"] == "confirmed"

    @pytest.mark.asyncio
    async def test_broken_mass_assignment_probe_config_does_not_abort_scan(self):
        svc, db = await _make_service()
        await db.scans.insert_one({"scan_id": "scan-21", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)):
            # Missing required "update_url" — MassAssignmentProbeConfig(**data) raises TypeError.
            await svc._run_dynamic_scan(
                "scan-21", TARGET, dynamic_mass_assignment_probes=[{"scenario_id": "BROKEN"}],
            )
        doc = await db.scans.find_one({"scan_id": "scan-21"})
        assert doc["state"] == "COMPLETED"

    @pytest.mark.asyncio
    async def test_no_mass_assignment_probes_supplied_is_a_no_op(self):
        svc, db = await _make_service()
        run_mass_assignment_probe_mock = AsyncMock()
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch(
                 "app.domain.analysis.dast.mass_assignment_probe.run_mass_assignment_probe",
                 run_mass_assignment_probe_mock,
             ):
            await svc._run_dynamic_scan("scan-22", TARGET)
        run_mass_assignment_probe_mock.assert_not_called()


class TestTimingComparisonProbeWiring:
    """V11.2.5 — the dedicated dynamic_timing_probes request shape, same
    build-config-then-run-then-record wiring as race/IDOR/mass-assignment
    probes above, but with variant_a/variant_b needing conversion from
    plain dicts (API shape) to TimingProbeVariant (domain shape) first."""

    @pytest.mark.asyncio
    async def test_timing_probe_is_built_and_run(self):
        svc, db = await _make_service()
        timing_finding = DynamicFinding(
            control_id="V11.2.5", verdict=Verdict.FAIL, rule_id="PADDING_ORACLE_CHECK",
            url=f"{TARGET}/decrypt", method="POST", note="timing-distinguishable", severity="medium",
        )
        run_timing_probe_mock = AsyncMock(return_value=timing_finding)
        await db.scans.insert_one({"scan_id": "scan-30", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch(
                 "app.domain.analysis.dast.padding_oracle_probe.run_timing_comparison_probe",
                 run_timing_probe_mock,
             ):
            await svc._run_dynamic_scan(
                "scan-30", TARGET,
                dynamic_active_mode=True,
                dynamic_timing_probes=[{
                    "scenario_id": "PADDING_ORACLE_CHECK", "url": f"{TARGET}/decrypt",
                    "variant_a": {"data": {"ciphertext": "valid-padding-wrong-content"}},
                    "variant_b": {"data": {"ciphertext": "invalid-padding"}},
                }],
            )

        run_timing_probe_mock.assert_called_once()
        called_config = run_timing_probe_mock.call_args.args[1]
        assert called_config.scenario_id == "PADDING_ORACLE_CHECK"
        assert called_config.variant_a.data == {"ciphertext": "valid-padding-wrong-content"}
        assert called_config.variant_b.data == {"ciphertext": "invalid-padding"}

        doc = await db.scans.find_one({"scan_id": "scan-30"})
        findings = doc["summary"]["dynamic_findings"]
        result = next(f for f in findings if f["rule_id"] == "PADDING_ORACLE_CHECK")
        assert result["verdict"] == "fail"

    @pytest.mark.asyncio
    async def test_broken_timing_probe_config_does_not_abort_scan(self):
        svc, db = await _make_service()
        await db.scans.insert_one({"scan_id": "scan-31", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)):
            # Missing required "variant_a"/"variant_b" keys -> KeyError building the config.
            await svc._run_dynamic_scan(
                "scan-31", TARGET, dynamic_timing_probes=[{"scenario_id": "BROKEN", "url": f"{TARGET}/x"}],
            )
        doc = await db.scans.find_one({"scan_id": "scan-31"})
        assert doc["state"] == "COMPLETED"

    @pytest.mark.asyncio
    async def test_no_timing_probes_supplied_is_a_no_op(self):
        svc, db = await _make_service()
        run_timing_probe_mock = AsyncMock()
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch(
                 "app.domain.analysis.dast.padding_oracle_probe.run_timing_comparison_probe",
                 run_timing_probe_mock,
             ):
            await svc._run_dynamic_scan("scan-32", TARGET)
        run_timing_probe_mock.assert_not_called()


class TestSignalingFuzzProbeWiring:
    """V17.3.2 — dynamic_signaling_fuzz_probes wiring. Doesn't route through
    DastSessionPair (websocket_fuzz_probe.py drives `websockets` directly),
    so only run_websocket_fuzz_probe itself needs mocking here — no _pair
    fixture involved."""

    @pytest.mark.asyncio
    async def test_signaling_probe_is_built_and_run(self):
        svc, db = await _make_service()
        signaling_finding = DynamicFinding(
            control_id="V17.3.2", verdict=Verdict.FAIL, rule_id="SIGNALING_FUZZ",
            url="wss://target.example/signaling", method="WEBSOCKET",
            note="handshake failed after payload #2", severity="high",
        )
        run_signaling_probe_mock = AsyncMock(return_value=signaling_finding)
        await db.scans.insert_one({"scan_id": "scan-40", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch(
                 "app.domain.analysis.dast.websocket_fuzz_probe.run_websocket_fuzz_probe",
                 run_signaling_probe_mock,
             ):
            await svc._run_dynamic_scan(
                "scan-40", TARGET,
                dynamic_active_mode=True,
                dynamic_signaling_fuzz_probes=[{
                    "scenario_id": "SIGNALING_FUZZ", "url": "wss://target.example/signaling",
                    "payloads": ["not json", '{"type": null}'],
                }],
            )

        run_signaling_probe_mock.assert_called_once()
        called_config = run_signaling_probe_mock.call_args.args[0]
        assert called_config.scenario_id == "SIGNALING_FUZZ"
        assert called_config.payloads == ["not json", '{"type": null}']

        doc = await db.scans.find_one({"scan_id": "scan-40"})
        findings = doc["summary"]["dynamic_findings"]
        result = next(f for f in findings if f["rule_id"] == "SIGNALING_FUZZ")
        assert result["verdict"] == "fail"

    @pytest.mark.asyncio
    async def test_omitted_payloads_uses_the_default_corpus(self):
        svc, db = await _make_service()
        run_signaling_probe_mock = AsyncMock(return_value=DynamicFinding(
            control_id="V17.3.2", verdict=Verdict.PASS, rule_id="SIGNALING_FUZZ",
            url="wss://target.example/signaling", method="WEBSOCKET", note="ok", severity="high",
        ))
        await db.scans.insert_one({"scan_id": "scan-41", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch(
                 "app.domain.analysis.dast.websocket_fuzz_probe.run_websocket_fuzz_probe",
                 run_signaling_probe_mock,
             ):
            await svc._run_dynamic_scan(
                "scan-41", TARGET,
                dynamic_active_mode=True,
                # "payloads" omitted entirely (matches the API default of None).
                dynamic_signaling_fuzz_probes=[{
                    "scenario_id": "SIGNALING_FUZZ", "url": "wss://target.example/signaling",
                }],
            )

        called_config = run_signaling_probe_mock.call_args.args[0]
        assert len(called_config.payloads) > 5  # the built-in default corpus, not empty

    @pytest.mark.asyncio
    async def test_broken_signaling_probe_config_does_not_abort_scan(self):
        svc, db = await _make_service()
        await db.scans.insert_one({"scan_id": "scan-42", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)):
            # Missing required "scenario_id" -> TypeError building the config.
            await svc._run_dynamic_scan(
                "scan-42", TARGET, dynamic_signaling_fuzz_probes=[{"url": "wss://target.example/x"}],
            )
        doc = await db.scans.find_one({"scan_id": "scan-42"})
        assert doc["state"] == "COMPLETED"

    @pytest.mark.asyncio
    async def test_no_signaling_probes_supplied_is_a_no_op(self):
        svc, db = await _make_service()
        run_signaling_probe_mock = AsyncMock()
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch(
                 "app.domain.analysis.dast.websocket_fuzz_probe.run_websocket_fuzz_probe",
                 run_signaling_probe_mock,
             ):
            await svc._run_dynamic_scan("scan-43", TARGET)
        run_signaling_probe_mock.assert_not_called()


class TestWebRtcProbeWiring:
    """V17.2.3/V17.2.4/V17.2.5 — confirms the dict-to-dataclass conversion
    (nested WebRtcConnectionConfig objects, hex-decoded payloads) each loop
    does before calling its probe function. The probes themselves (real
    aiortc peer connections) are covered by test_dast_webrtc_probe.py; here
    only the mock's call_args need inspecting."""

    @pytest.mark.asyncio
    async def test_media_flood_probe_is_built_and_run(self):
        svc, db = await _make_service()
        flood_finding = DynamicFinding(
            control_id="V17.2.5", verdict=Verdict.PASS, rule_id="MEDIA_FLOOD",
            url="", method="WEBRTC", note="ok", severity="high",
        )
        run_flood_mock = AsyncMock(return_value=flood_finding)
        await db.scans.insert_one({"scan_id": "scan-50", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.webrtc_probe.run_media_flood_probe", run_flood_mock):
            await svc._run_dynamic_scan(
                "scan-50", TARGET,
                dynamic_active_mode=True,
                dynamic_media_flood_probes=[{
                    "scenario_id": "MEDIA_FLOOD",
                    "control_connection": {"signaling_url": "https://target.example/whip/control"},
                    "flood_connections": [
                        {"signaling_url": "https://target.example/whip/flood1"},
                        {"signaling_url": "https://target.example/whip/flood2"},
                    ],
                }],
            )

        run_flood_mock.assert_called_once()
        called_config = run_flood_mock.call_args.args[0]
        assert called_config.control_connection.signaling_url == "https://target.example/whip/control"
        assert len(called_config.flood_connections) == 2

        doc = await db.scans.find_one({"scan_id": "scan-50"})
        result = next(f for f in doc["summary"]["dynamic_findings"] if f["rule_id"] == "MEDIA_FLOOD")
        assert result["verdict"] == "pass"

    @pytest.mark.asyncio
    async def test_malformed_packet_probe_decodes_hex_payloads(self):
        svc, db = await _make_service()
        run_malformed_mock = AsyncMock(return_value=DynamicFinding(
            control_id="V17.2.4", verdict=Verdict.FAIL, rule_id="RTP_FUZZ",
            url="", method="WEBRTC", note="crashed", severity="critical",
        ))
        await db.scans.insert_one({"scan_id": "scan-51", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.webrtc_probe.run_malformed_packet_probe", run_malformed_mock):
            await svc._run_dynamic_scan(
                "scan-51", TARGET,
                dynamic_active_mode=True,
                dynamic_malformed_packet_probes=[{
                    "scenario_id": "RTP_FUZZ",
                    "connection": {"signaling_url": "https://target.example/whip"},
                    "payloads": ["ff00", "deadbeef"],
                }],
            )

        called_config = run_malformed_mock.call_args.args[0]
        assert called_config.payloads == [b"\xff\x00", b"\xde\xad\xbe\xef"]

    @pytest.mark.asyncio
    async def test_srtp_auth_probe_is_built_and_run(self):
        svc, db = await _make_service()
        run_srtp_mock = AsyncMock(return_value=DynamicFinding(
            control_id="V17.2.3", verdict=Verdict.NOT_TESTED, rule_id="SRTP_AUTH_CHECK",
            url="", method="WEBRTC", note="no relay observed", severity="high",
        ))
        await db.scans.insert_one({"scan_id": "scan-52", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.webrtc_probe.run_srtp_auth_enforcement_probe", run_srtp_mock):
            await svc._run_dynamic_scan(
                "scan-52", TARGET,
                dynamic_active_mode=True,
                dynamic_srtp_auth_probes=[{
                    "scenario_id": "SRTP_AUTH_CHECK",
                    "attacker_connection": {"signaling_url": "https://target.example/whip/a"},
                    "observer_connection": {"signaling_url": "https://target.example/whip/b"},
                }],
            )

        run_srtp_mock.assert_called_once()
        called_config = run_srtp_mock.call_args.args[0]
        assert called_config.attacker_connection.signaling_url == "https://target.example/whip/a"
        assert called_config.observer_connection.signaling_url == "https://target.example/whip/b"

    @pytest.mark.asyncio
    async def test_broken_webrtc_probe_configs_do_not_abort_scan(self):
        svc, db = await _make_service()
        await db.scans.insert_one({"scan_id": "scan-53", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)):
            await svc._run_dynamic_scan(
                "scan-53", TARGET,
                dynamic_media_flood_probes=[{"scenario_id": "BROKEN"}],  # missing required keys
                dynamic_malformed_packet_probes=[{"scenario_id": "BROKEN"}],
                dynamic_srtp_auth_probes=[{"scenario_id": "BROKEN"}],
            )
        doc = await db.scans.find_one({"scan_id": "scan-53"})
        assert doc["state"] == "COMPLETED"


class TestStoredXssProbeWiring:
    """Unlike race/IDOR probes, stored-XSS runs automatically off whatever
    forms the crawler discovers — no user-supplied config needed."""

    @pytest.mark.asyncio
    async def test_discovered_form_triggers_probe(self):
        svc, db = await _make_service()
        form = DiscoveredForm(
            action_url=f"{TARGET}/comment", method="POST", fields=["comment"],
            source_url=f"{TARGET}/comment-form",
        )
        crawl_result = CrawlResult(urls=[TARGET], forms=[form])
        xss_finding = DynamicFinding(
            control_id="V1.2.1", verdict=Verdict.FAIL, rule_id="STORED_XSS_PROBE",
            url=f"{TARGET}/comment-wall", method="GET", note="marker reflected", severity="high",
        )
        run_xss_probe_mock = AsyncMock(return_value=xss_finding)
        await db.scans.insert_one({"scan_id": "scan-20", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=crawl_result)), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.xss_probe.run_stored_xss_probe", run_xss_probe_mock):
            await svc._run_dynamic_scan("scan-20", TARGET, dynamic_active_mode=True)

        run_xss_probe_mock.assert_called_once()
        called_form = run_xss_probe_mock.call_args.args[1]
        assert called_form.action_url == f"{TARGET}/comment"

        doc = await db.scans.find_one({"scan_id": "scan-20"})
        findings = doc["summary"]["dynamic_findings"]
        xss_result = next(f for f in findings if f["rule_id"] == "STORED_XSS_PROBE")
        assert xss_result["verdict"] == "fail"

    @pytest.mark.asyncio
    async def test_no_forms_discovered_is_a_no_op(self):
        svc, db = await _make_service()
        crawl_result = CrawlResult(urls=[TARGET], forms=[])
        run_xss_probe_mock = AsyncMock()
        await db.scans.insert_one({"scan_id": "scan-21", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=crawl_result)), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.xss_probe.run_stored_xss_probe", run_xss_probe_mock):
            await svc._run_dynamic_scan("scan-21", TARGET)
        run_xss_probe_mock.assert_not_called()

    @pytest.mark.asyncio
    async def test_probes_bounded_to_five_forms(self):
        svc, db = await _make_service()
        forms = [
            DiscoveredForm(action_url=f"{TARGET}/f{i}", method="POST", fields=[], source_url=TARGET)
            for i in range(8)
        ]
        crawl_result = CrawlResult(urls=[TARGET], forms=forms)
        pass_finding = DynamicFinding(
            control_id="V1.2.1", verdict=Verdict.PASS, rule_id="STORED_XSS_PROBE",
            url=TARGET, method="POST", note="ok", severity="high",
        )
        run_xss_probe_mock = AsyncMock(return_value=pass_finding)
        await db.scans.insert_one({"scan_id": "scan-22", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=crawl_result)), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.xss_probe.run_stored_xss_probe", run_xss_probe_mock):
            await svc._run_dynamic_scan("scan-22", TARGET, dynamic_active_mode=True)

        assert run_xss_probe_mock.await_count == 5


class TestCrawlScopeAndRuleSelectionWiring:
    """Phase 5 — dynamic_crawl_max_pages/dynamic_crawl_max_depth/dynamic_rule_ids
    on ScanStart, threaded through to crawl() and run_payload_checks()."""

    @pytest.mark.asyncio
    async def test_crawl_overrides_are_passed_through(self):
        svc, db = await _make_service()
        crawl_mock = AsyncMock(return_value=CrawlResult(urls=[TARGET], forms=[]))
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", crawl_mock), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)):
            await svc._run_dynamic_scan(
                "scan-23", TARGET, dynamic_crawl_max_pages=25, dynamic_crawl_max_depth=4,
            )

        crawl_mock.assert_awaited_once()
        kwargs = crawl_mock.await_args.kwargs
        assert kwargs["max_pages"] == 25
        assert kwargs["max_depth"] == 4
        assert kwargs["request_delay"] > 0  # C1 — always paced, not user-configurable

    @pytest.mark.asyncio
    async def test_no_crawl_overrides_leaves_crawler_defaults_untouched(self):
        svc, db = await _make_service()
        crawl_mock = AsyncMock(return_value=CrawlResult(urls=[TARGET], forms=[]))
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", crawl_mock), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)):
            await svc._run_dynamic_scan("scan-24", TARGET)

        kwargs = crawl_mock.await_args.kwargs
        assert "max_pages" not in kwargs
        assert "max_depth" not in kwargs
        assert kwargs["request_delay"] > 0  # C1 — always paced, even with no scope overrides

    @pytest.mark.asyncio
    async def test_rule_ids_filter_which_rules_are_passed(self):
        svc, db = await _make_service()
        run_payload_checks_mock = AsyncMock(return_value=[])
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult())), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", run_payload_checks_mock), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)):
            await svc._run_dynamic_scan(
                "scan-25", TARGET, dynamic_rule_ids=["OPEN_REDIRECT_LIVE", "NOT_A_REAL_RULE"],
            )

        run_payload_checks_mock.assert_awaited_once()
        passed_rules = run_payload_checks_mock.await_args.kwargs["rules"]
        assert set(passed_rules.keys()) == {"OPEN_REDIRECT_LIVE"}

    @pytest.mark.asyncio
    async def test_no_rule_ids_runs_full_default_set(self):
        svc, db = await _make_service()
        run_payload_checks_mock = AsyncMock(return_value=[])
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult())), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", run_payload_checks_mock), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)):
            await svc._run_dynamic_scan("scan-26", TARGET)

        assert run_payload_checks_mock.await_args.kwargs["rules"] is None

    @pytest.mark.asyncio
    async def test_run_payload_checks_is_paced(self):
        svc, db = await _make_service()
        run_payload_checks_mock = AsyncMock(return_value=[])
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult())), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", run_payload_checks_mock), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)):
            await svc._run_dynamic_scan("scan-27", TARGET)

        assert run_payload_checks_mock.await_args.kwargs["request_delay"] > 0


class TestActiveModeAuditLog:
    """Phase 7 — every check that actually performed a side-effecting
    request gets logged once at the end of the scan; skipped ones (no
    active_mode) never touched the target and shouldn't appear."""

    @pytest.mark.asyncio
    async def test_executed_race_probe_is_logged(self, caplog):
        svc, db = await _make_service()
        race_finding = DynamicFinding(
            control_id="V2.3.4", verdict=Verdict.FAIL, rule_id="DOUBLE_REDEEM",
            url=f"{TARGET}/redeem", method="POST", note="2 of 5 succeeded", severity="high",
        )
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult())), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.race_probe.run_race_probe", AsyncMock(return_value=race_finding)), \
             caplog.at_level("INFO"):
            await svc._run_dynamic_scan(
                "scan-27", TARGET, dynamic_active_mode=True,
                dynamic_race_probes=[{"scenario_id": "DOUBLE_REDEEM", "url": f"{TARGET}/redeem"}],
            )

        audit_logs = [r.getMessage() for r in caplog.records if "Active-mode" in r.getMessage()]
        assert audit_logs
        assert "DOUBLE_REDEEM" in audit_logs[0]

    @pytest.mark.asyncio
    async def test_skipped_probe_is_not_logged(self, caplog):
        svc, db = await _make_service()
        skipped_finding = DynamicFinding(
            control_id="V2.3.4", verdict=Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION,
            rule_id="DOUBLE_REDEEM", url=f"{TARGET}/redeem", method="POST", note="skipped", severity="high",
        )
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult())), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.race_probe.run_race_probe", AsyncMock(return_value=skipped_finding)), \
             caplog.at_level("INFO"):
            await svc._run_dynamic_scan(
                "scan-28", TARGET, dynamic_active_mode=False,
                dynamic_race_probes=[{"scenario_id": "DOUBLE_REDEEM", "url": f"{TARGET}/redeem"}],
            )

        audit_logs = [r.getMessage() for r in caplog.records if "Active-mode" in r.getMessage()]
        assert not audit_logs

    @pytest.mark.asyncio
    async def test_read_only_open_redirect_finding_is_not_audited(self, caplog):
        svc, db = await _make_service()
        redirect_finding = DynamicFinding(
            control_id="V3.7.2", verdict=Verdict.FAIL, rule_id="OPEN_REDIRECT_LIVE",
            url=f"{TARGET}/next-link", method="GET", note="redirect", severity="medium",
        )
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult())), \
             patch(
                 "app.domain.analysis.dast.checks.run_payload_checks",
                 AsyncMock(return_value=[redirect_finding]),
             ), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             caplog.at_level("INFO"):
            await svc._run_dynamic_scan("scan-29", TARGET)

        audit_logs = [r.getMessage() for r in caplog.records if "Active-mode" in r.getMessage()]
        assert not audit_logs


class TestSsrfProbeWiring:
    """Track A2 — unlike race/IDOR probes, SSRF runs automatically against
    crawled/target URLs whenever dynamic_active_mode is set, no user-supplied
    config needed (same shape as stored-XSS)."""

    @pytest.mark.asyncio
    async def test_ssrf_probe_runs_when_active_mode_enabled(self):
        svc, db = await _make_service()
        ssrf_finding = DynamicFinding(
            control_id="V5.3.2", verdict=Verdict.FAIL, rule_id="SSRF_LIVE",
            url=TARGET, method="GET", note="callback received", severity="high",
        )
        run_ssrf_probe_mock = AsyncMock(return_value=ssrf_finding)
        await db.scans.insert_one({"scan_id": "scan-30", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult())), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.ssrf_probe.run_ssrf_probe", run_ssrf_probe_mock):
            await svc._run_dynamic_scan("scan-30", TARGET, dynamic_active_mode=True)

        run_ssrf_probe_mock.assert_awaited_once()
        assert run_ssrf_probe_mock.await_args.args[1] == TARGET  # url is the 2nd positional arg
        assert run_ssrf_probe_mock.await_args.kwargs["active_mode"] is True

        doc = await db.scans.find_one({"scan_id": "scan-30"})
        findings = doc["summary"]["dynamic_findings"]
        ssrf_result = next(f for f in findings if f["rule_id"] == "SSRF_LIVE")
        assert ssrf_result["verdict"] == "fail"

    @pytest.mark.asyncio
    async def test_ssrf_probe_and_collaborator_not_started_without_active_mode(self):
        svc, db = await _make_service()
        run_ssrf_probe_mock = AsyncMock()
        collaborator_mock = MagicMock()
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult())), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.ssrf_probe.run_ssrf_probe", run_ssrf_probe_mock), \
             patch("app.domain.analysis.dast.collaborator.CollaboratorServer", collaborator_mock):
            await svc._run_dynamic_scan("scan-31", TARGET)  # dynamic_active_mode defaults False

        run_ssrf_probe_mock.assert_not_called()
        collaborator_mock.assert_not_called()

    @pytest.mark.asyncio
    async def test_collaborator_host_and_port_are_passed_through(self):
        svc, db = await _make_service()
        collaborator_mock = MagicMock()
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult())), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.ssrf_probe.run_ssrf_probe", AsyncMock()), \
             patch("app.domain.analysis.dast.collaborator.CollaboratorServer", collaborator_mock):
            await svc._run_dynamic_scan(
                "scan-32", TARGET, dynamic_active_mode=True,
                dynamic_ssrf_collaborator_host="collab.example.internal",
                dynamic_ssrf_collaborator_port=9999,
            )

        collaborator_mock.assert_called_once_with(host="collab.example.internal", port=9999)

    @pytest.mark.asyncio
    async def test_no_host_or_port_override_uses_collaborator_defaults(self):
        svc, db = await _make_service()
        collaborator_mock = MagicMock()
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult())), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.ssrf_probe.run_ssrf_probe", AsyncMock()), \
             patch("app.domain.analysis.dast.collaborator.CollaboratorServer", collaborator_mock):
            await svc._run_dynamic_scan("scan-33", TARGET, dynamic_active_mode=True)

        collaborator_mock.assert_called_once_with()

    @pytest.mark.asyncio
    async def test_ssrf_probes_bounded_to_five_urls(self):
        svc, db = await _make_service()
        crawl_result = CrawlResult(urls=[f"{TARGET}/p{i}" for i in range(8)], forms=[])
        pass_finding = DynamicFinding(
            control_id="V5.3.2", verdict=Verdict.PASS, rule_id="SSRF_LIVE",
            url=TARGET, method="GET", note="no callback", severity="high",
        )
        run_ssrf_probe_mock = AsyncMock(return_value=pass_finding)
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=crawl_result)), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.ssrf_probe.run_ssrf_probe", run_ssrf_probe_mock):
            await svc._run_dynamic_scan("scan-34", TARGET, dynamic_active_mode=True)

        assert run_ssrf_probe_mock.await_count == 5

    @pytest.mark.asyncio
    async def test_bridge_ssrf_target_uses_run_ssrf_probe_not_payload_checks(self):
        # bridge.py maps static SSRF findings to SSRF_LIVE, but that rule
        # isn't a checks.py payload check (it needs the collaborator, not
        # just a rule) — _run_dynamic_checks's bridge loop must special-case
        # it rather than routing it through run_payload_checks like every
        # other bridge target.
        from app.domain.analysis.dast.bridge import BridgeTarget

        svc, db = await _make_service()
        bridge_target = BridgeTarget(
            static_finding_id="vuln-1", static_rule_id="SSRF", dynamic_rule_id="SSRF_LIVE",
            asvs_controls=["V5.3.2"], url=f"{TARGET}/proxy?url=1", method="GET",
            source_file="app.py", source_line=9,
        )
        # Distinct return values per call site (not a shared object) so the
        # assertions below can unambiguously tell the bridge-triggered call
        # apart from the general probe-against-crawled-urls loop's own call.
        def _fake_run_ssrf_probe(session, url, collaborator, **kwargs):
            if kwargs.get("candidate_params"):
                return DynamicFinding(
                    control_id="V5.3.2", verdict=Verdict.FAIL, rule_id="SSRF_LIVE",
                    url=url, method="GET", note="callback received (bridge)", severity="high",
                )
            return DynamicFinding(
                control_id="V5.3.2", verdict=Verdict.PASS, rule_id="SSRF_LIVE",
                url=url, method="GET", note="no callback (general loop)", severity="high",
            )

        run_ssrf_probe_mock = AsyncMock(side_effect=_fake_run_ssrf_probe)
        run_payload_checks_mock = AsyncMock(return_value=[])
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult())), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", run_payload_checks_mock), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.ssrf_probe.run_ssrf_probe", run_ssrf_probe_mock):
            dynamic_findings, _ = await svc._run_dynamic_checks(
                "scan-35", TARGET, dynamic_active_mode=True, bridge_targets=[bridge_target],
            )

        # Called twice: once for the bridge target, once more for the
        # general probe-against-crawled-urls loop (check_urls defaults to
        # just [target_url] here since crawl() is mocked empty) — find the
        # bridge-specific call by its candidate_params kwarg.
        bridge_calls = [c for c in run_ssrf_probe_mock.await_args_list if c.kwargs.get("candidate_params")]
        assert len(bridge_calls) == 1
        assert bridge_calls[0].args[1] == f"{TARGET}/proxy?url=1"
        assert bridge_calls[0].kwargs["candidate_params"] == ["url"]
        run_payload_checks_mock.assert_awaited_once()  # only the top-level check_urls call, not the bridge one

        bridge_result = next(
            f for f in dynamic_findings if f["rule_id"] == "SSRF_LIVE" and f.get("evidence")
        )
        assert bridge_result["verdict"] == "fail"
        assert bridge_result["evidence"] == "bridge:vuln-1:app.py:9"


class TestSsrfCollaboratorLoopbackWarning:
    """The SSRF collaborator's default listener only binds loopback — it
    can't catch an OOB callback from a real external target, only one on
    the same host/network as the scanner. That limitation used to only live
    in the field's schema description; it's now also a scan-log line so a
    user reading scan output (not the API docs) sees it."""

    @pytest.mark.asyncio
    async def test_warning_logged_when_no_collaborator_host_supplied(self):
        svc, db = await _make_service()
        await db.scans.insert_one({"scan_id": "scan-36", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult())), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)):
            await svc._run_dynamic_scan("scan-36", TARGET, dynamic_active_mode=True)

        doc = await db.scans.find_one({"scan_id": "scan-36"})
        assert any("loopback listener" in line for line in doc.get("logs", []))

    @pytest.mark.asyncio
    async def test_no_warning_when_collaborator_host_supplied(self):
        svc, db = await _make_service()
        await db.scans.insert_one({"scan_id": "scan-37", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult())), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)):
            await svc._run_dynamic_scan(
                "scan-37", TARGET, dynamic_active_mode=True,
                dynamic_ssrf_collaborator_host="collab.example.com",
            )

        doc = await db.scans.find_one({"scan_id": "scan-37"})
        assert not any("loopback listener" in line for line in doc.get("logs", []))

    @pytest.mark.asyncio
    async def test_no_warning_without_active_mode(self):
        svc, db = await _make_service()
        await db.scans.insert_one({"scan_id": "scan-38", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult())), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)):
            await svc._run_dynamic_scan("scan-38", TARGET)  # dynamic_active_mode defaults False

        doc = await db.scans.find_one({"scan_id": "scan-38"})
        assert not any("loopback listener" in line for line in doc.get("logs", []))


class TestMultiTargetDynamicScan:
    """dynamic_additional_target_urls (the fix for a microservice app
    fragmenting into unrelated 'Direct Code' scans, one per service) —
    _run_dynamic_scan/_run_repository_scan should sweep every target within
    ONE scan document, merging findings rather than needing a separate
    ScanStart per origin. Mocks _run_dynamic_checks itself (the whole
    per-target sweep) rather than its internals — this tests the loop/merge
    glue, not the DAST engine, same spirit as the rest of this file."""

    @pytest.mark.asyncio
    async def test_run_dynamic_checks_called_once_per_target_in_order(self):
        svc, db = await _make_service()
        await db.scans.insert_one({"scan_id": "scan-multi-1", "state": "PENDING"})

        seen_targets = []

        async def fake_run_dynamic_checks(self, *, scan_id, target_url, **kwargs):
            seen_targets.append(target_url)
            return ([{"control_id": f"C-{target_url}", "verdict": "fail", "severity": "high"}], [])

        with patch.object(ScanService, "_run_dynamic_checks", fake_run_dynamic_checks), \
             patch("app.domain.analysis.dynamic_probe.DynamicProbe.probe", AsyncMock(return_value=[])):
            await svc._run_dynamic_scan(
                "scan-multi-1", TARGET,
                dynamic_additional_target_urls=[f"{TARGET}:8081", f"{TARGET}:8082"],
            )

        assert seen_targets == [TARGET, f"{TARGET}:8081", f"{TARGET}:8082"]

    @pytest.mark.asyncio
    async def test_findings_from_every_target_merged_into_one_scan_document(self):
        svc, db = await _make_service()
        await db.scans.insert_one({"scan_id": "scan-multi-2", "state": "PENDING"})

        async def fake_run_dynamic_checks(self, *, scan_id, target_url, **kwargs):
            return ([{"control_id": f"C-{target_url}", "verdict": "fail", "severity": "high"}], [])

        with patch.object(ScanService, "_run_dynamic_checks", fake_run_dynamic_checks), \
             patch("app.domain.analysis.dynamic_probe.DynamicProbe.probe", AsyncMock(return_value=[])):
            await svc._run_dynamic_scan(
                "scan-multi-2", TARGET,
                dynamic_additional_target_urls=[f"{TARGET}:8081", f"{TARGET}:8082"],
            )

        doc = await db.scans.find_one({"scan_id": "scan-multi-2"})
        assert doc["state"] == "COMPLETED"
        findings = doc["summary"]["dynamic_findings"]
        assert len(findings) == 3
        assert {f["control_id"] for f in findings} == {
            f"C-{TARGET}", f"C-{TARGET}:8081", f"C-{TARGET}:8082",
        }
        # 3 fails across 3 targets, each "high" — by_severity must reflect
        # every target's contribution, not just the first one's.
        assert doc["summary"]["by_severity"]["high"] == 3

    @pytest.mark.asyncio
    async def test_one_target_failing_does_not_discard_the_others(self):
        """Regression — before this loop existed, an unhandled exception
        from a single target's sweep propagated to the outer try/except and
        marked the WHOLE scan FAILED with 0 results, even when other
        targets had already produced real findings."""
        svc, db = await _make_service()
        await db.scans.insert_one({"scan_id": "scan-multi-3", "state": "PENDING"})

        async def fake_run_dynamic_checks(self, *, scan_id, target_url, **kwargs):
            if target_url.endswith(":8081"):
                raise ConnectionError()  # empty message, same shape as the real blank-reason bug
            return ([{"control_id": f"C-{target_url}", "verdict": "fail", "severity": "medium"}], [])

        with patch.object(ScanService, "_run_dynamic_checks", fake_run_dynamic_checks), \
             patch("app.domain.analysis.dynamic_probe.DynamicProbe.probe", AsyncMock(return_value=[])):
            await svc._run_dynamic_scan(
                "scan-multi-3", TARGET,
                dynamic_additional_target_urls=[f"{TARGET}:8081", f"{TARGET}:8082"],
            )

        doc = await db.scans.find_one({"scan_id": "scan-multi-3"})
        assert doc["state"] == "COMPLETED"
        findings = doc["summary"]["dynamic_findings"]
        assert {f["control_id"] for f in findings} == {f"C-{TARGET}", f"C-{TARGET}:8082"}
        # The failing target's blank-message exception still surfaces a
        # diagnosable reason in the logs, not a silent "Reason: ".
        assert any(
            f"Dynamic checks failed for {TARGET}:8081" in line and "ConnectionError" in line
            for line in doc.get("logs", [])
        )

    @pytest.mark.asyncio
    async def test_single_target_unchanged_behavior(self):
        """No dynamic_additional_target_urls at all — the pre-existing
        single-target call shape still works exactly as before."""
        svc, db = await _make_service()
        await db.scans.insert_one({"scan_id": "scan-multi-4", "state": "PENDING"})

        async def fake_run_dynamic_checks(self, *, scan_id, target_url, **kwargs):
            assert target_url == TARGET
            return ([{"control_id": "C-only", "verdict": "pass", "severity": "low"}], [])

        with patch.object(ScanService, "_run_dynamic_checks", fake_run_dynamic_checks), \
             patch("app.domain.analysis.dynamic_probe.DynamicProbe.probe", AsyncMock(return_value=[])):
            await svc._run_dynamic_scan("scan-multi-4", TARGET)

        doc = await db.scans.find_one({"scan_id": "scan-multi-4"})
        assert len(doc["summary"]["dynamic_findings"]) == 1

    @pytest.mark.asyncio
    async def test_user_supplied_probes_attached_to_primary_target_only(self):
        """Regression — a user-supplied idor/race/mass-assignment probe
        carries its own absolute URL, independent of which target a given
        loop iteration is sweeping. Attaching it to every target (instead
        of only the first/primary one) used to run the identical probe
        once per target — worse for a race probe, where 'fire N concurrent
        requests' became N x that many real requests against the target."""
        svc, db = await _make_service()
        await db.scans.insert_one({"scan_id": "scan-multi-5", "state": "PENDING"})

        received_idor_probes = []

        async def fake_run_dynamic_checks(self, *, scan_id, target_url, dynamic_idor_probes=None, **kwargs):
            received_idor_probes.append(dynamic_idor_probes)
            return ([], [])

        idor_probes = [{"scenario_id": "idor-1", "owner_resource_url": f"{TARGET}/orders/1", "method": "GET"}]
        with patch.object(ScanService, "_run_dynamic_checks", fake_run_dynamic_checks), \
             patch("app.domain.analysis.dynamic_probe.DynamicProbe.probe", AsyncMock(return_value=[])):
            await svc._run_dynamic_scan(
                "scan-multi-5", TARGET,
                dynamic_additional_target_urls=[f"{TARGET}:8081", f"{TARGET}:8082"],
                dynamic_idor_probes=idor_probes,
            )

        assert received_idor_probes == [idor_probes, None, None]


class _FakePreAuthSession:
    """Stands in for DastSession inside _resolve_shared_multi_target_auth's
    one-time pre-authentication — __aenter__ is where the real class would
    perform the actual login, so this just returns an object whose
    browser_auth_state() reports whatever the test wants the 'completed
    login' to have produced."""

    auth_state = ([], {"Authorization": "Bearer shared-token-xyz"})

    def __init__(self, actor):
        self.actor = actor

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False

    def browser_auth_state(self):
        return self.__class__.auth_state


class TestSharedMultiTargetAuth:
    """_resolve_shared_multi_target_auth — form_login re-authenticating
    fresh on every target of a multi-target sweep can trip a shared login
    endpoint's own rate limiter (confirmed against a live app: target 1
    succeeds, targets 2+ get 429 Too Many Requests). Pre-authenticating
    once and reusing the resulting bearer token avoids the repeated
    logins entirely when the target extracts a JSON bearer token."""

    @pytest.mark.asyncio
    async def test_form_login_reused_as_bearer_across_all_targets(self):
        svc, db = await _make_service()
        await db.scans.insert_one({"scan_id": "scan-shared-1", "state": "PENDING"})

        received = []

        async def fake_run_dynamic_checks(
            self, *, scan_id, target_url, dynamic_auth_mode, dynamic_bearer_token, dynamic_form_login, **kwargs
        ):
            received.append((dynamic_auth_mode, dynamic_bearer_token, dynamic_form_login))
            return ([], [])

        form = {
            "login_url": f"{TARGET}/login", "username_field": "email", "password_field": "password",
            "username": "a@b.com", "password": "hunter2",
        }
        _FakePreAuthSession.auth_state = ([], {"Authorization": "Bearer shared-token-xyz"})
        with patch.object(ScanService, "_run_dynamic_checks", fake_run_dynamic_checks), \
             patch("app.domain.analysis.dynamic_probe.DynamicProbe.probe", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.session.DastSession", _FakePreAuthSession):
            await svc._run_dynamic_scan(
                "scan-shared-1", TARGET,
                dynamic_additional_target_urls=[f"{TARGET}:8081", f"{TARGET}:8082"],
                dynamic_auth_mode="form_login", dynamic_form_login=form,
            )

        # All 3 targets get the SAME bearer token instead of each
        # re-running form_login (which would show up as auth_mode staying
        # "form_login" 3 times here, one real login attempt per target).
        assert received == [("bearer", "shared-token-xyz", None)] * 3

    @pytest.mark.asyncio
    async def test_single_target_scan_unaffected_by_shared_auth_logic(self):
        """No dynamic_additional_target_urls at all — pre-authentication
        never runs (target_count == 1 guard), so a single-target scan's
        form_login behaves exactly as it did before this feature existed."""
        svc, db = await _make_service()
        await db.scans.insert_one({"scan_id": "scan-shared-2", "state": "PENDING"})

        received = []

        async def fake_run_dynamic_checks(self, *, scan_id, target_url, dynamic_auth_mode, **kwargs):
            received.append(dynamic_auth_mode)
            return ([], [])

        form = {
            "login_url": f"{TARGET}/login", "username_field": "email", "password_field": "password",
            "username": "a@b.com", "password": "hunter2",
        }
        with patch.object(ScanService, "_run_dynamic_checks", fake_run_dynamic_checks), \
             patch("app.domain.analysis.dynamic_probe.DynamicProbe.probe", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.session.DastSession", _FakePreAuthSession):
            await svc._run_dynamic_scan("scan-shared-2", TARGET, dynamic_auth_mode="form_login", dynamic_form_login=form)

        assert received == ["form_login"]

    @pytest.mark.asyncio
    async def test_cookie_only_login_falls_back_to_per_target_form_login(self):
        """No Authorization header in the completed login's state (a pure
        cookie-session target) — nothing to share across origins, so every
        target keeps its own fresh form_login, unchanged from before this
        feature existed."""
        svc, db = await _make_service()
        await db.scans.insert_one({"scan_id": "scan-shared-3", "state": "PENDING"})

        received = []

        async def fake_run_dynamic_checks(self, *, scan_id, target_url, dynamic_auth_mode, **kwargs):
            received.append(dynamic_auth_mode)
            return ([], [])

        form = {
            "login_url": f"{TARGET}/login", "username_field": "user", "password_field": "pass",
            "username": "alice", "password": "hunter2",
        }
        _FakePreAuthSession.auth_state = ([{"name": "session", "value": "abc123", "domain": "example.com", "path": "/"}], {})
        with patch.object(ScanService, "_run_dynamic_checks", fake_run_dynamic_checks), \
             patch("app.domain.analysis.dynamic_probe.DynamicProbe.probe", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.session.DastSession", _FakePreAuthSession):
            await svc._run_dynamic_scan(
                "scan-shared-3", TARGET,
                dynamic_additional_target_urls=[f"{TARGET}:8081"],
                dynamic_auth_mode="form_login", dynamic_form_login=form,
            )

        assert received == ["form_login", "form_login"]
