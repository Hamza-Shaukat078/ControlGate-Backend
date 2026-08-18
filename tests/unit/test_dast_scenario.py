"""Phase 2B — ScenarioRunner, LOGOUT_INVALIDATES_SESSION, and a manually
built step-skipping (V2.3.1) example. All against httpx.MockTransport.
"""
import httpx
import pytest

from app.domain.analysis.dast.config import ActorConfig, AuthMode, DynamicScanConfig, FormLoginConfig
from app.domain.analysis.dast.logout_discovery import (
    build_logout_invalidates_session_scenario,
    check_logout_visible_on_every_page,
    discover_logout_url,
)
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

    @pytest.mark.asyncio
    async def test_rate_limited_post_logout_check_is_inconclusive_not_fail(self):
        # Regression — a 429 means the app's own rate limiter intercepted
        # the post-logout request before the session-invalidation question
        # was ever actually answered. Reporting that as FAIL (control
        # violated) was a confirmed false positive against a real scan: 4 of
        # 5 LOGOUT_INVALIDATES_SESSION findings were rate-limiter 429s, not
        # sessions surviving logout.
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/login":
                return httpx.Response(200, headers={"set-cookie": "session=abc123; Path=/"})
            if request.url.path == "/logout":
                return httpx.Response(200)
            if request.url.path == "/dashboard":
                return httpx.Response(429, text="Too Many Requests")
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        async with DastSessionPair(_login_config(), resolve=False, transport=transport) as pair:
            scenario = build_logout_invalidates_session_scenario(f"{BASE}/logout", f"{BASE}/dashboard")
            finding = await run_scenario(pair, scenario)

        assert finding.verdict == Verdict.INCONCLUSIVE

    @pytest.mark.asyncio
    async def test_rate_limiting_only_special_cased_for_429_other_failures_still_fail(self):
        # A different non-2xx/4xx-429 failure (e.g. the app returns 200 with
        # a generic error page) must still be treated as a real FAIL, not
        # swept into the same inconclusive bucket as rate limiting.
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/login":
                return httpx.Response(200, headers={"set-cookie": "session=abc123; Path=/"})
            if request.url.path == "/logout":
                return httpx.Response(200)
            if request.url.path == "/dashboard":
                return httpx.Response(500, text="internal error")
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


class TestCheckLogoutVisibleOnEveryPage:
    """V7.4.4 — markup-presence-only assist, fail-only per its own docstring
    and HYBRID_ATTESTATION_DYNAMIC_ELIGIBLE_CONTROLS in asvs_service.py."""

    @pytest.mark.asyncio
    async def test_no_authenticated_session_is_not_configured(self):
        async with DastSession(ActorConfig(), resolve=False,
                                transport=httpx.MockTransport(lambda r: httpx.Response(200))) as session:
            finding = await check_logout_visible_on_every_page(session, [f"{BASE}/dashboard"])
        assert finding.verdict == Verdict.NOT_CONFIGURED
        assert finding.control_id == "V7.4.4"

    @pytest.mark.asyncio
    async def test_href_logout_link_on_every_page_passes(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={"content-type": "text/html"},
                                   text='<nav><a href="/logout">Sign out</a></nav><p>dashboard</p>')

        async with DastSession(ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="tok"), resolve=False,
                                transport=httpx.MockTransport(handler)) as session:
            finding = await check_logout_visible_on_every_page(
                session, [f"{BASE}/dashboard", f"{BASE}/settings"],
            )
        assert finding.verdict == Verdict.PASS

    @pytest.mark.asyncio
    async def test_text_only_logout_button_passes(self):
        # No href at all — button text alone should still count.
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={"content-type": "text/html"},
                                   text='<header><button onclick="doLogout()">Log out</button></header>')

        async with DastSession(ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="tok"), resolve=False,
                                transport=httpx.MockTransport(handler)) as session:
            finding = await check_logout_visible_on_every_page(session, [f"{BASE}/dashboard"])
        assert finding.verdict == Verdict.PASS

    @pytest.mark.asyncio
    async def test_page_with_no_logout_control_fails(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/dashboard":
                return httpx.Response(200, headers={"content-type": "text/html"},
                                       text='<nav><a href="/logout">Sign out</a></nav>')
            if request.url.path == "/settings":
                # No logout control reachable from here at all.
                return httpx.Response(200, headers={"content-type": "text/html"}, text="<p>settings</p>")
            return httpx.Response(404)

        async with DastSession(ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="tok"), resolve=False,
                                transport=httpx.MockTransport(handler)) as session:
            finding = await check_logout_visible_on_every_page(
                session, [f"{BASE}/dashboard", f"{BASE}/settings"],
            )
        assert finding.verdict == Verdict.FAIL
        assert finding.proof["missing_count"] == 1

    @pytest.mark.asyncio
    async def test_login_page_is_excluded_from_the_sweep(self):
        # A login page never needs a logout control by definition — same
        # _PUBLIC_BY_DEFINITION_PATH_RE reasoning checks.py's
        # _check_unauthenticated_access already documents.
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/login":
                return httpx.Response(200, headers={"content-type": "text/html"}, text="<form>login</form>")
            return httpx.Response(404)

        async with DastSession(ActorConfig(auth_mode=AuthMode.BEARER, bearer_token="tok"), resolve=False,
                                transport=httpx.MockTransport(handler)) as session:
            finding = await check_logout_visible_on_every_page(session, [f"{BASE}/login"])
        assert finding.verdict == Verdict.NOT_TESTED


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


class TestStepDelay:
    """V10.4.3 — Step.delay_seconds, a real wall-clock wait applied before
    the delayed step's own request (see Step's docstring for why it belongs
    to the step that should be delayed, not the one before it)."""

    @pytest.mark.asyncio
    async def test_delay_actually_elapses_before_the_request(self):
        import time

        scenario = Scenario(
            scenario_id="AUTH_CODE_EXPIRY", asvs_controls=["V10.4.3"],
            steps=[Step(
                method="GET", url=f"{BASE}/token", delay_seconds=0.2,
                assertions=[Assertion(type="status_in", expected=[400])],
            )],
        )
        transport = httpx.MockTransport(lambda r: httpx.Response(400, text="expired_code"))
        started = time.monotonic()
        async with DastSessionPair(DynamicScanConfig(target_url=BASE), resolve=False, transport=transport) as pair:
            finding = await run_scenario(pair, scenario)
        elapsed = time.monotonic() - started
        assert elapsed >= 0.2
        assert finding.verdict == Verdict.PASS

    @pytest.mark.asyncio
    async def test_no_delay_configured_does_not_wait(self):
        import time

        scenario = Scenario(
            scenario_id="NO_DELAY", asvs_controls=["V2.3.1"],
            steps=[Step(method="GET", url=f"{BASE}/x")],
        )
        transport = httpx.MockTransport(lambda r: httpx.Response(200))
        started = time.monotonic()
        async with DastSessionPair(DynamicScanConfig(target_url=BASE), resolve=False, transport=transport) as pair:
            await run_scenario(pair, scenario)
        assert time.monotonic() - started < 0.2


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


class TestAssertionTypes:
    """scenario_runner._evaluate_assertion — types beyond the status_in/
    any_of coverage TestStepSkippingExample and TestExtractionAndInterpolation
    already exercise."""

    @pytest.mark.asyncio
    async def test_status_not_in_fails_on_a_listed_status(self):
        scenario = Scenario(
            scenario_id="STATUS_NOT_IN", asvs_controls=["V2.3.1"],
            steps=[Step(
                method="GET", url=f"{BASE}/x",
                assertions=[Assertion(type="status_not_in", expected=[403])],
            )],
        )
        transport = httpx.MockTransport(lambda r: httpx.Response(403))
        async with DastSessionPair(DynamicScanConfig(target_url=BASE), resolve=False, transport=transport) as pair:
            finding = await run_scenario(pair, scenario)
        assert finding.verdict == Verdict.FAIL

    @pytest.mark.asyncio
    async def test_body_contains_passes_when_substring_present(self):
        scenario = Scenario(
            scenario_id="BODY_CONTAINS", asvs_controls=["V2.3.1"],
            steps=[Step(
                method="GET", url=f"{BASE}/x",
                assertions=[Assertion(type="body_contains", expected="welcome")],
            )],
        )
        transport = httpx.MockTransport(lambda r: httpx.Response(200, text="welcome back"))
        async with DastSessionPair(DynamicScanConfig(target_url=BASE), resolve=False, transport=transport) as pair:
            finding = await run_scenario(pair, scenario)
        assert finding.verdict == Verdict.PASS

    @pytest.mark.asyncio
    async def test_body_not_contains_passes_when_substring_absent(self):
        # V10.4.11 — over-broad scope not granted: the disallowed scope
        # string must be genuinely absent from the response body.
        scenario = Scenario(
            scenario_id="SCOPE_NOT_OVER_ISSUED", asvs_controls=["V10.4.11"],
            steps=[Step(
                method="GET", url=f"{BASE}/x",
                assertions=[Assertion(type="body_not_contains", expected="admin:write")],
            )],
        )
        transport = httpx.MockTransport(lambda r: httpx.Response(200, text='{"scope": "profile:read"}'))
        async with DastSessionPair(DynamicScanConfig(target_url=BASE), resolve=False, transport=transport) as pair:
            finding = await run_scenario(pair, scenario)
        assert finding.verdict == Verdict.PASS

    @pytest.mark.asyncio
    async def test_body_not_contains_fails_when_substring_present(self):
        scenario = Scenario(
            scenario_id="SCOPE_NOT_OVER_ISSUED", asvs_controls=["V10.4.11"],
            steps=[Step(
                method="GET", url=f"{BASE}/x",
                assertions=[Assertion(type="body_not_contains", expected="admin:write")],
            )],
        )
        transport = httpx.MockTransport(
            lambda r: httpx.Response(200, text='{"scope": "profile:read admin:write"}'),
        )
        async with DastSessionPair(DynamicScanConfig(target_url=BASE), resolve=False, transport=transport) as pair:
            finding = await run_scenario(pair, scenario)
        assert finding.verdict == Verdict.FAIL

    @pytest.mark.asyncio
    async def test_redirect_location_contains_checks_status_and_location(self):
        scenario = Scenario(
            scenario_id="REDIRECT_CHECK", asvs_controls=["V7.4.1"],
            steps=[Step(
                method="GET", url=f"{BASE}/x", follow_redirects=False,
                assertions=[Assertion(type="redirect_location_contains", expected="login")],
            )],
        )
        transport = httpx.MockTransport(lambda r: httpx.Response(302, headers={"location": "/login?next=/x"}))
        async with DastSessionPair(DynamicScanConfig(target_url=BASE), resolve=False, transport=transport) as pair:
            finding = await run_scenario(pair, scenario)
        assert finding.verdict == Verdict.PASS

    @pytest.mark.asyncio
    async def test_redirect_location_contains_fails_on_non_redirect_status(self):
        scenario = Scenario(
            scenario_id="REDIRECT_CHECK", asvs_controls=["V7.4.1"],
            steps=[Step(
                method="GET", url=f"{BASE}/x",
                assertions=[Assertion(type="redirect_location_contains", expected="login")],
            )],
        )
        transport = httpx.MockTransport(lambda r: httpx.Response(200, text="ok"))
        async with DastSessionPair(DynamicScanConfig(target_url=BASE), resolve=False, transport=transport) as pair:
            finding = await run_scenario(pair, scenario)
        assert finding.verdict == Verdict.FAIL

    @pytest.mark.asyncio
    async def test_all_of_requires_every_sub_assertion(self):
        scenario = Scenario(
            scenario_id="ALL_OF", asvs_controls=["V2.3.1"],
            steps=[Step(
                method="GET", url=f"{BASE}/x",
                assertions=[Assertion(type="all_of", of=[
                    Assertion(type="status_in", expected=[200]),
                    Assertion(type="body_contains", expected="missing-text"),
                ])],
            )],
        )
        transport = httpx.MockTransport(lambda r: httpx.Response(200, text="present"))
        async with DastSessionPair(DynamicScanConfig(target_url=BASE), resolve=False, transport=transport) as pair:
            finding = await run_scenario(pair, scenario)
        assert finding.verdict == Verdict.FAIL  # status matched, body_contains didn't

    @pytest.mark.asyncio
    async def test_unknown_assertion_type_surfaces_as_not_tested(self):
        scenario = Scenario(
            scenario_id="BAD_ASSERTION", asvs_controls=["V2.3.1"],
            steps=[Step(
                method="GET", url=f"{BASE}/x",
                assertions=[Assertion(type="not_a_real_type", expected="x")],
            )],
        )
        transport = httpx.MockTransport(lambda r: httpx.Response(200))
        async with DastSessionPair(DynamicScanConfig(target_url=BASE), resolve=False, transport=transport) as pair:
            finding = await run_scenario(pair, scenario)
        # _evaluate_assertion raises ValueError -> caught by run_scenario's
        # broad except -> NOT_TESTED, never silently treated as a pass.
        assert finding.verdict == Verdict.NOT_TESTED


class TestExtractorSources:
    @pytest.mark.asyncio
    async def test_header_extractor_feeds_next_step(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/issue":
                return httpx.Response(200, headers={"x-csrf-token": "hdr-tok"})
            if request.url.path == "/submit":
                if request.url.params.get("csrf") == "hdr-tok":
                    return httpx.Response(200, text="ok")
                return httpx.Response(400)
            return httpx.Response(404)

        scenario = Scenario(
            scenario_id="HEADER_EXTRACT", asvs_controls=["V2.3.1"],
            steps=[
                Step(method="GET", url=f"{BASE}/issue",
                     extract=[Extractor(var="csrf_token", source="header", name="x-csrf-token")]),
                Step(method="GET", url=f"{BASE}/submit", params={"csrf": "{csrf_token}"},
                     assertions=[Assertion(type="status_in", expected=[200])]),
            ],
        )
        async with DastSessionPair(DynamicScanConfig(target_url=BASE), resolve=False,
                                    transport=httpx.MockTransport(handler)) as pair:
            finding = await run_scenario(pair, scenario)
        assert finding.verdict == Verdict.PASS

    @pytest.mark.asyncio
    async def test_regex_extractor_feeds_next_step(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/page":
                return httpx.Response(200, text='<input name="token" value="rgx-tok">')
            if request.url.path == "/submit":
                if request.url.params.get("csrf") == "rgx-tok":
                    return httpx.Response(200, text="ok")
                return httpx.Response(400)
            return httpx.Response(404)

        scenario = Scenario(
            scenario_id="REGEX_EXTRACT", asvs_controls=["V2.3.1"],
            steps=[
                Step(method="GET", url=f"{BASE}/page",
                     extract=[Extractor(var="csrf_token", source="regex", pattern=r'value="([^"]+)"')]),
                Step(method="GET", url=f"{BASE}/submit", params={"csrf": "{csrf_token}"},
                     assertions=[Assertion(type="status_in", expected=[200])]),
            ],
        )
        async with DastSessionPair(DynamicScanConfig(target_url=BASE), resolve=False,
                                    transport=httpx.MockTransport(handler)) as pair:
            finding = await run_scenario(pair, scenario)
        assert finding.verdict == Verdict.PASS

    @pytest.mark.asyncio
    async def test_extractor_that_finds_nothing_leaves_context_unset(self):
        """A step whose extractor doesn't match still runs — the template
        placeholder is left literally unsubstituted rather than raising."""
        seen_params = {}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/page":
                return httpx.Response(200, text="<p>nothing to extract</p>")
            if request.url.path == "/submit":
                seen_params["csrf"] = request.url.params.get("csrf")
                return httpx.Response(200)
            return httpx.Response(404)

        scenario = Scenario(
            scenario_id="NO_MATCH_EXTRACT", asvs_controls=["V2.3.1"],
            steps=[
                Step(method="GET", url=f"{BASE}/page",
                     extract=[Extractor(var="csrf_token", source="regex", pattern=r'value="([^"]+)"')]),
                Step(method="GET", url=f"{BASE}/submit", params={"csrf": "{csrf_token}"}),
            ],
        )
        async with DastSessionPair(DynamicScanConfig(target_url=BASE), resolve=False,
                                    transport=httpx.MockTransport(handler)) as pair:
            await run_scenario(pair, scenario)
        assert seen_params["csrf"] == "{csrf_token}"


class TestScenarioStepException:
    @pytest.mark.asyncio
    async def test_request_exception_yields_not_tested_with_redacted_note(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused")

        scenario = Scenario(
            scenario_id="CONN_FAIL", asvs_controls=["V2.3.1"],
            steps=[Step(method="GET", url=f"{BASE}/x")],
        )
        async with DastSessionPair(DynamicScanConfig(target_url=BASE), resolve=False,
                                    transport=httpx.MockTransport(handler)) as pair:
            finding = await run_scenario(pair, scenario)
        assert finding.verdict == Verdict.NOT_TESTED
        assert "connection refused" in finding.note


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
