"""build_scenario_from_request — converts the ScanStart API's flat
user-supplied scenario shape into domain Scenario/Step/Assertion objects.
"""
from app.domain.analysis.dast.api_scenario import build_scenario_from_request
from app.domain.analysis.dast.scenario import Scenario


def test_converts_minimal_scenario():
    data = {
        "scenario_id": "ORDER_STEP_SKIP",
        "asvs_controls": ["V2.3.1"],
        "steps": [{"method": "get", "url": "https://target.example/confirm-order"}],
    }
    scenario = build_scenario_from_request(data)

    assert isinstance(scenario, Scenario)
    assert scenario.scenario_id == "ORDER_STEP_SKIP"
    assert scenario.asvs_controls == ["V2.3.1"]
    assert scenario.requires_active_mode is True  # default
    assert len(scenario.steps) == 1
    assert scenario.steps[0].method == "get"
    assert scenario.steps[0].session == "primary"
    assert scenario.steps[0].assertions == []


def test_assert_status_in_becomes_an_assertion():
    data = {
        "scenario_id": "X", "steps": [
            {"method": "GET", "url": "https://target.example/x", "assert_status_in": [401, 403]},
        ],
    }
    scenario = build_scenario_from_request(data)

    assertion = scenario.steps[0].assertions[0]
    assert assertion.type == "status_in"
    assert assertion.expected == [401, 403]


def test_second_actor_session_field_passed_through():
    data = {
        "scenario_id": "CRED_CHANGE_KILLS_SESSIONS", "asvs_controls": ["V7.4.3"],
        "steps": [
            {"method": "POST", "url": "https://target.example/change-password",
             "session": "primary", "data": {"new_password": "NewP@ss123"}},
            {"method": "GET", "url": "https://target.example/dashboard",
             "session": "secondary", "assert_status_in": [401, 403]},
        ],
    }
    scenario = build_scenario_from_request(data)

    assert scenario.steps[0].session == "primary"
    assert scenario.steps[1].session == "secondary"
    assert scenario.steps[0].data == {"new_password": "NewP@ss123"}


def test_requires_active_mode_can_be_overridden():
    data = {
        "scenario_id": "X", "requires_active_mode": False,
        "steps": [{"method": "GET", "url": "https://target.example/x"}],
    }
    scenario = build_scenario_from_request(data)
    assert scenario.requires_active_mode is False


def test_severity_and_description_pass_through():
    data = {
        "scenario_id": "X", "severity": "critical", "description": "kills sessions",
        "steps": [{"method": "GET", "url": "https://target.example/x"}],
    }
    scenario = build_scenario_from_request(data)
    assert scenario.severity == "critical"
    assert scenario.description == "kills sessions"


def test_new_assert_fields_each_become_their_own_assertion():
    # V10.4.x/V10.7.1 — a status code alone can't tell a consent redirect
    # apart from a silent re-grant (both 302), so these fields exist
    # alongside assert_status_in, not instead of it.
    data = {
        "scenario_id": "X", "steps": [{
            "method": "GET", "url": "https://target.example/authorize",
            "assert_status_in": [302],
            "assert_body_contains": "scope",
            "assert_body_not_contains": "admin:write",
            "assert_redirect_location_contains": "consent",
        }],
    }
    scenario = build_scenario_from_request(data)
    types_and_expected = {a.type: a.expected for a in scenario.steps[0].assertions}
    assert types_and_expected == {
        "status_in": [302],
        "body_contains": "scope",
        "body_not_contains": "admin:write",
        "redirect_location_contains": "consent",
    }


def test_delay_seconds_passed_through_to_the_step():
    data = {
        "scenario_id": "X", "steps": [
            {"method": "GET", "url": "https://target.example/authorize"},
            {"method": "POST", "url": "https://target.example/token", "delay_seconds": 600},
        ],
    }
    scenario = build_scenario_from_request(data)
    assert scenario.steps[0].delay_seconds is None
    assert scenario.steps[1].delay_seconds == 600
