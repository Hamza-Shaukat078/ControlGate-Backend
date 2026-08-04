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
