"""ScanStart's dynamic_auth_mode/dynamic_bearer_token/dynamic_form_login
cross-field requirements (Phase 2B API wiring)."""
import pytest
from pydantic import ValidationError

from app.schemas.scan import ScanStart

TARGET = "https://example.com"


class TestBearerAuth:
    def test_bearer_with_token_is_valid(self):
        s = ScanStart(scan_type="dynamic", target_url=TARGET, dynamic_auth_mode="bearer",
                       dynamic_bearer_token="tok123")
        assert s.dynamic_bearer_token == "tok123"

    def test_bearer_without_token_is_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(scan_type="dynamic", target_url=TARGET, dynamic_auth_mode="bearer")


class TestFormLoginAuth:
    def test_form_login_with_config_is_valid(self):
        s = ScanStart(
            scan_type="dynamic", target_url=TARGET, dynamic_auth_mode="form_login",
            dynamic_form_login={
                "login_url": f"{TARGET}/login", "username_field": "user", "password_field": "pass",
                "username": "alice", "password": "hunter2",
            },
        )
        assert s.dynamic_form_login.username == "alice"

    def test_form_login_without_config_is_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(scan_type="dynamic", target_url=TARGET, dynamic_auth_mode="form_login")

    def test_form_login_url_must_be_http_or_https(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET, dynamic_auth_mode="form_login",
                dynamic_form_login={
                    "login_url": "ftp://example.com/login", "username_field": "user",
                    "password_field": "pass", "username": "alice", "password": "hunter2",
                },
            )


class TestDefaults:
    def test_default_auth_mode_is_none_and_unaffected_by_static_scans(self):
        s = ScanStart(code="print(1)", language="python")
        assert s.dynamic_auth_mode.value == "none"
        assert s.dynamic_bearer_token is None
        assert s.dynamic_form_login is None
        assert s.dynamic_second_actor_auth_mode.value == "none"


class TestSecondActorAuth:
    def test_second_actor_bearer_with_token_is_valid(self):
        s = ScanStart(
            scan_type="dynamic", target_url=TARGET,
            dynamic_second_actor_auth_mode="bearer", dynamic_second_actor_bearer_token="tok-second",
        )
        assert s.dynamic_second_actor_bearer_token == "tok-second"

    def test_second_actor_bearer_without_token_is_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(scan_type="dynamic", target_url=TARGET, dynamic_second_actor_auth_mode="bearer")

    def test_second_actor_form_login_without_config_is_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(scan_type="dynamic", target_url=TARGET, dynamic_second_actor_auth_mode="form_login")

    def test_primary_and_second_actor_are_independent_fields(self):
        s = ScanStart(
            scan_type="dynamic", target_url=TARGET,
            dynamic_auth_mode="bearer", dynamic_bearer_token="tok-primary",
            dynamic_second_actor_auth_mode="bearer", dynamic_second_actor_bearer_token="tok-second",
        )
        assert s.dynamic_bearer_token == "tok-primary"
        assert s.dynamic_second_actor_bearer_token == "tok-second"


class TestDynamicScenarios:
    def test_minimal_scenario_is_valid(self):
        s = ScanStart(
            scan_type="dynamic", target_url=TARGET,
            dynamic_scenarios=[{
                "scenario_id": "ORDER_STEP_SKIP", "asvs_controls": ["V2.3.1"],
                "steps": [{"method": "GET", "url": f"{TARGET}/confirm-order"}],
            }],
        )
        assert s.dynamic_scenarios[0].scenario_id == "ORDER_STEP_SKIP"
        assert s.dynamic_scenarios[0].requires_active_mode is True  # default

    def test_empty_steps_is_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET,
                dynamic_scenarios=[{"scenario_id": "X", "steps": []}],
            )

    def test_invalid_method_is_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET,
                dynamic_scenarios=[{
                    "scenario_id": "X",
                    "steps": [{"method": "TRACE", "url": f"{TARGET}/x"}],
                }],
            )

    def test_invalid_session_actor_is_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET,
                dynamic_scenarios=[{
                    "scenario_id": "X",
                    "steps": [{"method": "GET", "url": f"{TARGET}/x", "session": "tertiary"}],
                }],
            )

    def test_step_url_must_be_http_or_https(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET,
                dynamic_scenarios=[{
                    "scenario_id": "X",
                    "steps": [{"method": "GET", "url": "ftp://target.example/x"}],
                }],
            )

    def test_requires_active_mode_can_be_overridden_false(self):
        s = ScanStart(
            scan_type="dynamic", target_url=TARGET,
            dynamic_scenarios=[{
                "scenario_id": "X", "requires_active_mode": False,
                "steps": [{"method": "GET", "url": f"{TARGET}/x"}],
            }],
        )
        assert s.dynamic_scenarios[0].requires_active_mode is False

    def test_defaults_to_none(self):
        s = ScanStart(code="print(1)", language="python")
        assert s.dynamic_scenarios is None


class TestDynamicRaceProbes:
    def test_minimal_race_probe_is_valid(self):
        s = ScanStart(
            scan_type="dynamic", target_url=TARGET,
            dynamic_race_probes=[{"scenario_id": "DOUBLE_REDEEM", "url": f"{TARGET}/redeem"}],
        )
        probe = s.dynamic_race_probes[0]
        assert probe.asvs_controls == ["V2.3.4"]
        assert probe.concurrency == 5
        assert probe.max_expected_successes == 1
        assert probe.requires_active_mode is True

    def test_concurrency_below_minimum_is_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET,
                dynamic_race_probes=[{"scenario_id": "X", "url": f"{TARGET}/x", "concurrency": 1}],
            )

    def test_concurrency_above_maximum_is_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET,
                dynamic_race_probes=[{"scenario_id": "X", "url": f"{TARGET}/x", "concurrency": 21}],
            )

    def test_url_must_be_http_or_https(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET,
                dynamic_race_probes=[{"scenario_id": "X", "url": "ftp://target.example/x"}],
            )

    def test_defaults_to_none(self):
        s = ScanStart(code="print(1)", language="python")
        assert s.dynamic_race_probes is None


class TestDynamicIdorProbes:
    def test_minimal_idor_probe_is_valid(self):
        s = ScanStart(
            scan_type="dynamic", target_url=TARGET,
            dynamic_idor_probes=[{"scenario_id": "IDOR_ORDER", "owner_resource_url": f"{TARGET}/orders/42"}],
        )
        probe = s.dynamic_idor_probes[0]
        assert probe.asvs_controls == ["V8.2.1"]
        assert probe.method == "GET"
        assert probe.requires_active_mode is None

    def test_requires_active_mode_can_be_overridden_true(self):
        s = ScanStart(
            scan_type="dynamic", target_url=TARGET,
            dynamic_idor_probes=[{
                "scenario_id": "X", "owner_resource_url": f"{TARGET}/x", "requires_active_mode": True,
            }],
        )
        assert s.dynamic_idor_probes[0].requires_active_mode is True

    def test_method_is_uppercased(self):
        s = ScanStart(
            scan_type="dynamic", target_url=TARGET,
            dynamic_idor_probes=[{"scenario_id": "X", "owner_resource_url": f"{TARGET}/x", "method": "delete"}],
        )
        assert s.dynamic_idor_probes[0].method == "DELETE"

    def test_invalid_method_is_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET,
                dynamic_idor_probes=[{"scenario_id": "X", "owner_resource_url": f"{TARGET}/x", "method": "TRACE"}],
            )

    def test_url_must_be_http_or_https(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET,
                dynamic_idor_probes=[{"scenario_id": "X", "owner_resource_url": "ftp://target.example/x"}],
            )

    def test_defaults_to_none(self):
        s = ScanStart(code="print(1)", language="python")
        assert s.dynamic_idor_probes is None


class TestCrawlScopeAndRuleSelection:
    def test_valid_overrides_are_accepted(self):
        s = ScanStart(
            scan_type="dynamic", target_url=TARGET,
            dynamic_crawl_max_pages=25, dynamic_crawl_max_depth=4,
            dynamic_rule_ids=["OPEN_REDIRECT_LIVE", "CSRF_TOKEN_NOT_VALIDATED"],
        )
        assert s.dynamic_crawl_max_pages == 25
        assert s.dynamic_crawl_max_depth == 4
        assert s.dynamic_rule_ids == ["OPEN_REDIRECT_LIVE", "CSRF_TOKEN_NOT_VALIDATED"]

    def test_max_pages_out_of_range_is_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(scan_type="dynamic", target_url=TARGET, dynamic_crawl_max_pages=0)
        with pytest.raises(ValidationError):
            ScanStart(scan_type="dynamic", target_url=TARGET, dynamic_crawl_max_pages=101)

    def test_max_depth_out_of_range_is_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(scan_type="dynamic", target_url=TARGET, dynamic_crawl_max_depth=-1)
        with pytest.raises(ValidationError):
            ScanStart(scan_type="dynamic", target_url=TARGET, dynamic_crawl_max_depth=6)

    def test_defaults_to_none(self):
        s = ScanStart(code="print(1)", language="python")
        assert s.dynamic_crawl_max_pages is None
        assert s.dynamic_crawl_max_depth is None
        assert s.dynamic_rule_ids is None


class TestActiveModeListCaps:
    """Phase 7 — each of these is a real side-effecting request sequence
    against the target; an unbounded list is an accidental self-DoS/DoS
    vector, so ScanStart caps them at 20 (50 for the non-side-effecting
    dynamic_rule_ids filter)."""

    def test_scenarios_over_cap_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET,
                dynamic_scenarios=[
                    {"scenario_id": f"S{i}", "steps": [{"method": "GET", "url": f"{TARGET}/x"}]}
                    for i in range(21)
                ],
            )

    def test_scenarios_at_cap_accepted(self):
        s = ScanStart(
            scan_type="dynamic", target_url=TARGET,
            dynamic_scenarios=[
                {"scenario_id": f"S{i}", "steps": [{"method": "GET", "url": f"{TARGET}/x"}]}
                for i in range(20)
            ],
        )
        assert len(s.dynamic_scenarios) == 20

    def test_race_probes_over_cap_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET,
                dynamic_race_probes=[
                    {"scenario_id": f"R{i}", "url": f"{TARGET}/x"} for i in range(21)
                ],
            )

    def test_idor_probes_over_cap_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET,
                dynamic_idor_probes=[
                    {"scenario_id": f"I{i}", "owner_resource_url": f"{TARGET}/x"} for i in range(21)
                ],
            )

    def test_rule_ids_over_cap_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET,
                dynamic_rule_ids=[f"RULE_{i}" for i in range(51)],
            )


class TestSsrfCollaboratorConfig:
    def test_valid_host_and_port_accepted(self):
        s = ScanStart(
            scan_type="dynamic", target_url=TARGET,
            dynamic_ssrf_collaborator_host="collab.example.com",
            dynamic_ssrf_collaborator_port=8443,
        )
        assert s.dynamic_ssrf_collaborator_host == "collab.example.com"
        assert s.dynamic_ssrf_collaborator_port == 8443

    def test_port_out_of_range_is_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(scan_type="dynamic", target_url=TARGET, dynamic_ssrf_collaborator_port=0)
        with pytest.raises(ValidationError):
            ScanStart(scan_type="dynamic", target_url=TARGET, dynamic_ssrf_collaborator_port=70000)

    def test_defaults_to_none(self):
        s = ScanStart(code="print(1)", language="python")
        assert s.dynamic_ssrf_collaborator_host is None
        assert s.dynamic_ssrf_collaborator_port is None


class TestOpenApiSpecSource:
    """Track C3 — dynamic_openapi_spec_url/dynamic_openapi_spec are mutually
    exclusive (ambiguous which one should win otherwise), same shape as the
    field-level checks above but a model_validator since either one may be
    entirely absent."""

    def test_url_alone_is_valid(self):
        s = ScanStart(scan_type="dynamic", target_url=TARGET, dynamic_openapi_spec_url=f"{TARGET}/openapi.json")
        assert s.dynamic_openapi_spec_url == f"{TARGET}/openapi.json"
        assert s.dynamic_openapi_spec is None

    def test_inline_text_alone_is_valid(self):
        s = ScanStart(
            scan_type="dynamic", target_url=TARGET,
            dynamic_openapi_spec='{"paths": {"/health": {"get": {}}}}',
        )
        assert s.dynamic_openapi_spec == '{"paths": {"/health": {"get": {}}}}'
        assert s.dynamic_openapi_spec_url is None

    def test_both_supplied_is_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET,
                dynamic_openapi_spec_url=f"{TARGET}/openapi.json",
                dynamic_openapi_spec='{"paths": {}}',
            )

    def test_neither_supplied_defaults_to_none(self):
        s = ScanStart(code="print(1)", language="python")
        assert s.dynamic_openapi_spec_url is None
        assert s.dynamic_openapi_spec is None


class TestUseHeadlessBrowser:
    def test_defaults_to_false(self):
        s = ScanStart(code="print(1)", language="python")
        assert s.dynamic_use_headless_browser is False

    def test_can_be_enabled(self):
        s = ScanStart(scan_type="dynamic", target_url=TARGET, dynamic_use_headless_browser=True)
        assert s.dynamic_use_headless_browser is True
