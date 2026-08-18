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


class TestCsrfFormLoginAuth:
    """Track C6 — COOKIE + CSRF: csrf_field/csrf_source_url are optional but
    must be supplied together."""

    def test_form_login_with_csrf_fields_is_valid(self):
        s = ScanStart(
            scan_type="dynamic", target_url=TARGET, dynamic_auth_mode="form_login",
            dynamic_form_login={
                "login_url": f"{TARGET}/login", "username_field": "user", "password_field": "pass",
                "username": "alice", "password": "hunter2",
                "csrf_field": "csrf_token", "csrf_source_url": f"{TARGET}/login",
            },
        )
        assert s.dynamic_form_login.csrf_field == "csrf_token"

    def test_form_login_without_csrf_fields_is_valid(self):
        s = ScanStart(
            scan_type="dynamic", target_url=TARGET, dynamic_auth_mode="form_login",
            dynamic_form_login={
                "login_url": f"{TARGET}/login", "username_field": "user", "password_field": "pass",
                "username": "alice", "password": "hunter2",
            },
        )
        assert s.dynamic_form_login.csrf_field is None
        assert s.dynamic_form_login.csrf_source_url is None

    def test_csrf_field_without_source_url_is_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET, dynamic_auth_mode="form_login",
                dynamic_form_login={
                    "login_url": f"{TARGET}/login", "username_field": "user", "password_field": "pass",
                    "username": "alice", "password": "hunter2", "csrf_field": "csrf_token",
                },
            )

    def test_csrf_source_url_must_be_http_or_https(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET, dynamic_auth_mode="form_login",
                dynamic_form_login={
                    "login_url": f"{TARGET}/login", "username_field": "user", "password_field": "pass",
                    "username": "alice", "password": "hunter2",
                    "csrf_field": "csrf_token", "csrf_source_url": "ftp://example.com/login",
                },
            )


class TestOAuth2Auth:
    def test_client_credentials_grant_is_valid(self):
        s = ScanStart(
            scan_type="dynamic", target_url=TARGET, dynamic_auth_mode="oauth2",
            dynamic_oauth2={
                "token_url": f"{TARGET}/oauth/token", "client_id": "cid", "client_secret": "csecret",
            },
        )
        assert s.dynamic_oauth2.grant_type == "client_credentials"

    def test_password_grant_requires_username_and_password(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET, dynamic_auth_mode="oauth2",
                dynamic_oauth2={"token_url": f"{TARGET}/oauth/token", "grant_type": "password"},
            )

    def test_password_grant_with_credentials_is_valid(self):
        s = ScanStart(
            scan_type="dynamic", target_url=TARGET, dynamic_auth_mode="oauth2",
            dynamic_oauth2={
                "token_url": f"{TARGET}/oauth/token", "grant_type": "password",
                "username": "alice", "password": "hunter2",
            },
        )
        assert s.dynamic_oauth2.username == "alice"

    def test_invalid_grant_type_is_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET, dynamic_auth_mode="oauth2",
                dynamic_oauth2={"token_url": f"{TARGET}/oauth/token", "grant_type": "implicit"},
            )

    def test_oauth2_mode_without_config_is_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(scan_type="dynamic", target_url=TARGET, dynamic_auth_mode="oauth2")

    def test_token_url_must_be_http_or_https(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET, dynamic_auth_mode="oauth2",
                dynamic_oauth2={"token_url": "ftp://example.com/token"},
            )


class TestApiKeyAuth:
    def test_api_key_with_header_and_value_is_valid(self):
        s = ScanStart(
            scan_type="dynamic", target_url=TARGET, dynamic_auth_mode="api_key",
            dynamic_api_key_header="X-API-Key", dynamic_api_key_value="secret-key",
        )
        assert s.dynamic_api_key_header == "X-API-Key"

    def test_api_key_mode_without_header_is_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET, dynamic_auth_mode="api_key",
                dynamic_api_key_value="secret-key",
            )

    def test_api_key_mode_without_value_is_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET, dynamic_auth_mode="api_key",
                dynamic_api_key_header="X-API-Key",
            )


class TestSecondActorNewAuthModes:
    def test_second_actor_oauth2_without_config_is_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(scan_type="dynamic", target_url=TARGET, dynamic_second_actor_auth_mode="oauth2")

    def test_second_actor_api_key_without_value_is_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET, dynamic_second_actor_auth_mode="api_key",
                dynamic_second_actor_api_key_header="X-API-Key",
            )

    def test_second_actor_oauth2_independent_of_primary(self):
        s = ScanStart(
            scan_type="dynamic", target_url=TARGET,
            dynamic_auth_mode="oauth2", dynamic_oauth2={"token_url": f"{TARGET}/token1"},
            dynamic_second_actor_auth_mode="oauth2",
            dynamic_second_actor_oauth2={"token_url": f"{TARGET}/token2"},
        )
        assert s.dynamic_oauth2.token_url == f"{TARGET}/token1"
        assert s.dynamic_second_actor_oauth2.token_url == f"{TARGET}/token2"


class TestStateCrawlScope:
    def test_valid_overrides_are_accepted(self):
        s = ScanStart(
            scan_type="dynamic", target_url=TARGET,
            dynamic_state_crawl_max_forms=10, dynamic_state_crawl_max_depth=3,
        )
        assert s.dynamic_state_crawl_max_forms == 10
        assert s.dynamic_state_crawl_max_depth == 3

    def test_max_forms_out_of_range_is_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(scan_type="dynamic", target_url=TARGET, dynamic_state_crawl_max_forms=0)
        with pytest.raises(ValidationError):
            ScanStart(scan_type="dynamic", target_url=TARGET, dynamic_state_crawl_max_forms=31)

    def test_defaults_to_none(self):
        s = ScanStart(code="print(1)", language="python")
        assert s.dynamic_state_crawl_max_forms is None
        assert s.dynamic_state_crawl_max_depth is None


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

    def test_new_assert_fields_accepted(self):
        # V10.4.x/V10.7.1 — a status code alone can't distinguish two
        # outcomes that both come back with the same redirect status.
        s = ScanStart(
            scan_type="dynamic", target_url=TARGET,
            dynamic_scenarios=[{
                "scenario_id": "CONSENT_SHOWN_AGAIN", "asvs_controls": ["V10.7.1"],
                "steps": [{
                    "method": "GET", "url": f"{TARGET}/authorize",
                    "assert_body_contains": "requested_scope",
                    "assert_body_not_contains": "admin:write",
                    "assert_redirect_location_contains": "consent",
                }],
            }],
        )
        step = s.dynamic_scenarios[0].steps[0]
        assert step.assert_body_contains == "requested_scope"
        assert step.assert_body_not_contains == "admin:write"
        assert step.assert_redirect_location_contains == "consent"

    def test_delay_seconds_within_bounds_is_accepted(self):
        s = ScanStart(
            scan_type="dynamic", target_url=TARGET,
            dynamic_scenarios=[{
                "scenario_id": "AUTH_CODE_EXPIRY", "asvs_controls": ["V10.4.3"],
                "steps": [{"method": "POST", "url": f"{TARGET}/token", "delay_seconds": 600}],
            }],
        )
        assert s.dynamic_scenarios[0].steps[0].delay_seconds == 600

    def test_delay_seconds_over_the_cap_is_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET,
                dynamic_scenarios=[{
                    "scenario_id": "X",
                    "steps": [{"method": "GET", "url": f"{TARGET}/x", "delay_seconds": 700}],
                }],
            )

    def test_negative_delay_seconds_is_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET,
                dynamic_scenarios=[{
                    "scenario_id": "X",
                    "steps": [{"method": "GET", "url": f"{TARGET}/x", "delay_seconds": -1}],
                }],
            )


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


class TestDynamicTimingProbes:
    def _variants(self):
        return {
            "variant_a": {"data": {"ciphertext": "valid-padding-wrong-content"}},
            "variant_b": {"data": {"ciphertext": "invalid-padding"}},
        }

    def test_minimal_timing_probe_is_valid(self):
        s = ScanStart(
            scan_type="dynamic", target_url=TARGET,
            dynamic_timing_probes=[{
                "scenario_id": "PADDING_ORACLE_CHECK", "url": f"{TARGET}/decrypt", **self._variants(),
            }],
        )
        probe = s.dynamic_timing_probes[0]
        assert probe.asvs_controls == ["V11.2.5"]
        assert probe.samples == 7
        assert probe.requires_active_mode is True
        assert probe.variant_a.data == {"ciphertext": "valid-padding-wrong-content"}
        assert probe.variant_b.data == {"ciphertext": "invalid-padding"}

    def test_missing_variant_b_is_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET,
                dynamic_timing_probes=[{
                    "scenario_id": "X", "url": f"{TARGET}/decrypt",
                    "variant_a": self._variants()["variant_a"],
                }],
            )

    def test_samples_below_minimum_is_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET,
                dynamic_timing_probes=[{
                    "scenario_id": "X", "url": f"{TARGET}/decrypt", "samples": 2, **self._variants(),
                }],
            )

    def test_samples_above_maximum_is_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET,
                dynamic_timing_probes=[{
                    "scenario_id": "X", "url": f"{TARGET}/decrypt", "samples": 31, **self._variants(),
                }],
            )

    def test_url_must_be_http_or_https(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET,
                dynamic_timing_probes=[{
                    "scenario_id": "X", "url": "ftp://target.example/decrypt", **self._variants(),
                }],
            )

    def test_defaults_to_none(self):
        s = ScanStart(code="print(1)", language="python")
        assert s.dynamic_timing_probes is None


class TestDynamicSignalingFuzzProbes:
    def test_minimal_probe_is_valid(self):
        s = ScanStart(
            scan_type="dynamic", target_url=TARGET,
            dynamic_signaling_fuzz_probes=[{
                "scenario_id": "SIGNALING_FUZZ", "url": "wss://target.example/signaling",
            }],
        )
        probe = s.dynamic_signaling_fuzz_probes[0]
        assert probe.asvs_controls == ["V17.3.2"]
        assert probe.payloads is None  # means "use the built-in default corpus"
        assert probe.requires_active_mode is True

    def test_custom_payloads_are_accepted(self):
        s = ScanStart(
            scan_type="dynamic", target_url=TARGET,
            dynamic_signaling_fuzz_probes=[{
                "scenario_id": "X", "url": "ws://target.example/signaling",
                "payloads": ["not json", '{"type": null}'],
            }],
        )
        assert s.dynamic_signaling_fuzz_probes[0].payloads == ["not json", '{"type": null}']

    def test_url_must_be_ws_or_wss(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET,
                dynamic_signaling_fuzz_probes=[{"scenario_id": "X", "url": "https://target.example/signaling"}],
            )

    def test_defaults_to_none(self):
        s = ScanStart(code="print(1)", language="python")
        assert s.dynamic_signaling_fuzz_probes is None


class TestDynamicWebRtcConnectionValidation:
    """DynamicWebRtcConnectionRequest — shared by all three V17.2.x probe
    request types below. Testing it once via the simplest of the three
    (malformed-packet) rather than duplicating these cases three times."""

    def test_signaling_url_alone_is_valid(self):
        s = ScanStart(
            scan_type="dynamic", target_url=TARGET,
            dynamic_malformed_packet_probes=[{
                "scenario_id": "X",
                "connection": {"signaling_url": "https://target.example/whip"},
            }],
        )
        assert s.dynamic_malformed_packet_probes[0].connection.signaling_url == "https://target.example/whip"

    def test_remote_answer_sdp_alone_is_valid(self):
        s = ScanStart(
            scan_type="dynamic", target_url=TARGET,
            dynamic_malformed_packet_probes=[{
                "scenario_id": "X",
                "connection": {"remote_answer_sdp": "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\n"},
            }],
        )
        assert s.dynamic_malformed_packet_probes[0].connection.remote_answer_sdp is not None

    def test_neither_signaling_method_is_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET,
                dynamic_malformed_packet_probes=[{"scenario_id": "X", "connection": {}}],
            )

    def test_both_signaling_methods_is_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET,
                dynamic_malformed_packet_probes=[{
                    "scenario_id": "X",
                    "connection": {
                        "signaling_url": "https://target.example/whip",
                        "remote_answer_sdp": "v=0\r\n",
                    },
                }],
            )

    def test_signaling_url_must_be_http_or_https(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET,
                dynamic_malformed_packet_probes=[{
                    "scenario_id": "X",
                    "connection": {"signaling_url": "ws://target.example/whip"},
                }],
            )


class TestDynamicMediaFloodProbes:
    def test_minimal_probe_is_valid(self):
        s = ScanStart(
            scan_type="dynamic", target_url=TARGET,
            dynamic_media_flood_probes=[{
                "scenario_id": "MEDIA_FLOOD",
                "control_connection": {"signaling_url": "https://target.example/whip/control"},
                "flood_connections": [{"signaling_url": "https://target.example/whip/flood"}],
            }],
        )
        probe = s.dynamic_media_flood_probes[0]
        assert probe.asvs_controls == ["V17.2.5"]
        assert probe.hold_seconds == 5.0
        assert probe.requires_active_mode is True

    def test_empty_flood_connections_is_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET,
                dynamic_media_flood_probes=[{
                    "scenario_id": "X",
                    "control_connection": {"signaling_url": "https://target.example/whip"},
                    "flood_connections": [],
                }],
            )

    def test_hold_seconds_out_of_range_is_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET,
                dynamic_media_flood_probes=[{
                    "scenario_id": "X",
                    "control_connection": {"signaling_url": "https://target.example/whip"},
                    "flood_connections": [{"signaling_url": "https://target.example/whip"}],
                    "hold_seconds": 120,
                }],
            )

    def test_defaults_to_none(self):
        s = ScanStart(code="print(1)", language="python")
        assert s.dynamic_media_flood_probes is None


class TestDynamicMalformedPacketProbes:
    def test_minimal_probe_is_valid(self):
        s = ScanStart(
            scan_type="dynamic", target_url=TARGET,
            dynamic_malformed_packet_probes=[{
                "scenario_id": "RTP_FUZZ",
                "connection": {"signaling_url": "https://target.example/whip"},
            }],
        )
        probe = s.dynamic_malformed_packet_probes[0]
        assert probe.asvs_controls == ["V17.2.4"]
        assert probe.payloads is None  # means "use the built-in default corpus"

    def test_custom_hex_payloads_are_accepted(self):
        s = ScanStart(
            scan_type="dynamic", target_url=TARGET,
            dynamic_malformed_packet_probes=[{
                "scenario_id": "X",
                "connection": {"signaling_url": "https://target.example/whip"},
                "payloads": ["ff00", "deadbeef"],
            }],
        )
        assert s.dynamic_malformed_packet_probes[0].payloads == ["ff00", "deadbeef"]

    def test_non_hex_payload_is_rejected(self):
        with pytest.raises(ValidationError):
            ScanStart(
                scan_type="dynamic", target_url=TARGET,
                dynamic_malformed_packet_probes=[{
                    "scenario_id": "X",
                    "connection": {"signaling_url": "https://target.example/whip"},
                    "payloads": ["not-hex-zz"],
                }],
            )

    def test_defaults_to_none(self):
        s = ScanStart(code="print(1)", language="python")
        assert s.dynamic_malformed_packet_probes is None


class TestDynamicSrtpAuthProbes:
    def test_minimal_probe_is_valid(self):
        s = ScanStart(
            scan_type="dynamic", target_url=TARGET,
            dynamic_srtp_auth_probes=[{
                "scenario_id": "SRTP_AUTH_CHECK",
                "attacker_connection": {"signaling_url": "https://target.example/whip/a"},
                "observer_connection": {"signaling_url": "https://target.example/whip/b"},
            }],
        )
        probe = s.dynamic_srtp_auth_probes[0]
        assert probe.asvs_controls == ["V17.2.3"]
        assert probe.requires_active_mode is True

    def test_defaults_to_none(self):
        s = ScanStart(code="print(1)", language="python")
        assert s.dynamic_srtp_auth_probes is None


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


class TestEnableLlm:
    def test_defaults_to_true(self):
        s = ScanStart(code="print(1)", language="python")
        assert s.enable_llm is True

    def test_can_be_disabled(self):
        s = ScanStart(code="print(1)", language="python", enable_llm=False)
        assert s.enable_llm is False


class TestUseHeadlessBrowser:
    def test_defaults_to_false(self):
        s = ScanStart(code="print(1)", language="python")
        assert s.dynamic_use_headless_browser is False

    def test_can_be_enabled(self):
        s = ScanStart(scan_type="dynamic", target_url=TARGET, dynamic_use_headless_browser=True)
        assert s.dynamic_use_headless_browser is True
