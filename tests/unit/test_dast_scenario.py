"""Phase 2B — ScenarioRunner, LOGOUT_INVALIDATES_SESSION, and a manually
built step-skipping (V2.3.1) example. All against httpx.MockTransport.
"""
import httpx
import pytest

from app.domain.analysis.dast.config import ActorConfig, AuthMode, DynamicScanConfig, FormLoginConfig
from app.domain.analysis.dast.logout_discovery import build_logout_invalidates_session_scenario, discover_logout_url
from app.domain.analysis.dast.scenario import Assertion, Extractor, Scenario, Step
from app.domain.analysis.dast.scenario_runner import run_scenario
from app.domain.analysis.dast.session import DastSession, DastSessionPair
from app.domain.analysis.dast.verdict import Verdict

BASE = "https://target.example"


def _login_config() -> DynamicScanConfig:
    return DynamicScanConfig(
        target_url=BASE,
        actor=ActorConfig(
            auth_mode=AuthMode.FORM_LOGIN,
            form_login=FormLoginConfig(
                login_url=f"{BASE}/login", username_field="user", password_field="pass",
                username="alice", password="hunter2",
            ),
        ),
    )


class TestLogoutInvalidatesSessionScenario:
    @pytest.mark.asyncio
    async def test_session_properly_invalidated_passes(self):
        state = {"logged_out": False}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/login":
                return httpx.Response(200, headers={"set-cookie": "session=abc123; Path=/"})
            if request.url.path == "/logout":
                state["logged_out"] = True
                return httpx.Response(200)
            if request.url.path == "/dashboard":
                if state["logged_out"]:
                    return httpx.Response(302, headers={"location": "/login"})
                return httpx.Response(200, text="welcome")
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        async with DastSessionPair(_login_config(), resolve=False, transport=transport) as pair:
            scenario = build_logout_invalidates_session_scenario(f"{BASE}/logout", f"{BASE}/dashboard")
            finding = await run_scenario(pair, scenario)

        assert finding.verdict == Verdict.PASS
        assert finding.control_id == "V7.4.1"

    @pytest.mark.asyncio
    async def test_session_still_usable_after_logout_fails(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/login":
                return httpx.Response(200, headers={"set-cookie": "session=abc123; Path=/"})
            if request.url.path == "/logout":
                return httpx.Response(200)  # doesn't actually invalidate anything server-side
            if request.url.path == "/dashboard":
                return httpx.Response(200, text="welcome")
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        async with DastSessionPair(_login_config(), resolve=False, transport=transport) as pair:
            scenario = build_logout_invalidates_session_scenario(f"{BASE}/logout", f"{BASE}/dashboard")
            finding = await run_scenario(pair, scenario)

        assert finding.verdict == Verdict.FAIL


class TestDiscoverLogoutUrl:
    @pytest.mark.asyncio
    async def test_finds_logout_link_in_page(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/":
                return httpx.Response(200, text='<a href="/user/logout">Sign out</a>')
            return httpx.Response(404)

        async with DastSession(ActorConfig(), resolve=False, transport=httpx.MockTransport(handler)) as session:
            url = await discover_logout_url(session, BASE)
        assert url == f"{BASE}/user/logout"

    @pytest.mark.asyncio
    async def test_falls_back_to_common_path(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/":
                return httpx.Response(200, text="<p>no links here</p>")
            if request.url.path == "/signout":
                return httpx.Response(200)
            return httpx.Response(404)

        async with DastSession(ActorConfig(), resolve=False, transport=httpx.MockTransport(handler)) as session:
            url = await discover_logout_url(session, BASE)
        assert url == f"{BASE}/signout"

    @pytest.mark.asyncio
    async def test_returns_none_when_nothing_found(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        async with DastSession(ActorConfig(), resolve=False, transport=httpx.MockTransport(handler)) as session:
            url = await discover_logout_url(session, BASE)
        assert url is None


class TestScenarioRunnerGuards:
    @pytest.mark.asyncio
    async def test_requires_active_mode_is_skipped_without_authorization(self):
        scenario = Scenario(
            scenario_id="RACE_CONDITION_PROBE", asvs_controls=["V2.3.4"], requires_active_mode=True,
            steps=[Step(method="GET", url=f"{BASE}/book")],
        )
        async with DastSessionPair(DynamicScanConfig(target_url=BASE), resolve=False,
                                    transport=httpx.MockTransport(lambda r: httpx.Response(200))) as pair:
            finding = await run_scenario(pair, scenario, active_mode=False)
        assert finding.verdict == Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION

    @pytest.mark.asyncio
    async def test_no_steps_is_not_configured(self):
        scenario = Scenario(scenario_id="EMPTY", asvs_controls=["V2.3.1"], steps=[])
        async with DastSessionPair(DynamicScanConfig(target_url=BASE), resolve=False,
                                    transport=httpx.MockTransport(lambda r: httpx.Response(200))) as pair:
            finding = await run_scenario(pair, scenario)
        assert finding.verdict == Verdict.NOT_CONFIGURED

    @pytest.mark.asyncio
    async def test_missing_second_actor_is_not_configured(self):
        scenario = Scenario(
            scenario_id="CROSS_SESSION", asvs_controls=["V7.4.3"],
            steps=[Step(method="GET", url=f"{BASE}/x", session="secondary")],
        )
        async with DastSessionPair(DynamicScanConfig(target_url=BASE), resolve=False,
                                    transport=httpx.MockTransport(lambda r: httpx.Response(200))) as pair:
            finding = await run_scenario(pair, scenario)
        assert finding.verdict == Verdict.NOT_CONFIGURED


class TestExtractionAndInterpolation:
    @pytest.mark.asyncio
    async def test_value_extracted_from_step_one_is_used_in_step_two(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/token":
                return httpx.Response(200, json={"data": {"csrf": "tok-xyz"}})
            if request.url.path == "/submit":
                if request.url.params.get("csrf") == "tok-xyz":
                    return httpx.Response(200, text="ok")
                return httpx.Response(400, text="missing csrf")
            return httpx.Response(404)

        scenario = Scenario(
            scenario_id="CSRF_FLOW", asvs_controls=["V2.3.1"],
            steps=[
                Step(
                    method="GET", url=f"{BASE}/token",
                    extract=[Extractor(var="csrf_token", source="json_path", path="data.csrf")],
                ),
                Step(
                    method="GET", url=f"{BASE}/submit", params={"csrf": "{csrf_token}"},
                    assertions=[Assertion(type="status_in", expected=[200])],
                ),
            ],
        )
        async with DastSessionPair(DynamicScanConfig(target_url=BASE), resolve=False,
                                    transport=httpx.MockTransport(handler)) as pair:
            finding = await run_scenario(pair, scenario)
        assert finding.verdict == Verdict.PASS


class TestStepSkippingExample:
    """V2.3.1 — user-supplied step definitions, no auto-discovery. This
    simulates what a scan config would hand the runner: the literal
    endpoints/order for one specific app's business flow."""

    @pytest.mark.asyncio
    async def test_step_skipping_correctly_rejected_passes(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/confirm-order":
                return httpx.Response(409, text="no active cart")
            return httpx.Response(404)

        scenario = Scenario(
            scenario_id="ORDER_STEP_SKIP", asvs_controls=["V2.3.1"],
            steps=[Step(
                method="GET", url=f"{BASE}/confirm-order",
                assertions=[Assertion(type="status_in", expected=[400, 403, 409])],
            )],
        )
        async with DastSessionPair(DynamicScanConfig(target_url=BASE), resolve=False,
                                    transport=httpx.MockTransport(handler)) as pair:
            finding = await run_scenario(pair, scenario)
        assert finding.verdict == Verdict.PASS

    @pytest.mark.asyncio
    async def test_step_skipping_allowed_fails(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/confirm-order":
                return httpx.Response(200, text="order confirmed")  # business-logic flaw
            return httpx.Response(404)

        scenario = Scenario(
            scenario_id="ORDER_STEP_SKIP", asvs_controls=["V2.3.1"],
            steps=[Step(
                method="GET", url=f"{BASE}/confirm-order",
                assertions=[Assertion(type="status_in", expected=[400, 403, 409])],
            )],
        )
        async with DastSessionPair(DynamicScanConfig(target_url=BASE), resolve=False,
                                    transport=httpx.MockTransport(handler)) as pair:
            finding = await run_scenario(pair, scenario)
        assert finding.verdict == Verdict.FAIL
