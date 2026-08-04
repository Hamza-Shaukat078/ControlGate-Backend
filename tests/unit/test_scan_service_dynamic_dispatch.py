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
from unittest.mock import AsyncMock, patch

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


class _FakeSessionPair:
    """Captures the DynamicScanConfig it was constructed with so tests can
    assert on it, and behaves as an async context manager like the real one."""

    last_config = None

    def __init__(self, config):
        _FakeSessionPair.last_config = config
        self.primary = object()

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
