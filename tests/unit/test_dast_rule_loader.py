"""app/domain/analysis/dast/rule_loader.py — loads queries/dynamic_queries.json
into DynamicQueryRule models. Zero prior dedicated coverage; only exercised
indirectly wherever checks.py/scan_service.py call load_dynamic_queries().
"""
import json

import pytest
from pydantic import ValidationError

from app.domain.analysis.dast.rule_loader import DynamicQueryRule, load_dynamic_queries


class TestLoadDynamicQueries:
    def test_default_path_loads_the_real_queries_file(self):
        rules = load_dynamic_queries()
        assert len(rules) > 0
        assert all(isinstance(r, DynamicQueryRule) for r in rules.values())

    def test_rule_id_is_populated_from_the_json_key_not_a_field(self):
        rules = load_dynamic_queries()
        for rule_id, rule in rules.items():
            assert rule.rule_id == rule_id

    def test_every_real_rule_has_asvs_controls_and_a_severity(self):
        rules = load_dynamic_queries()
        for rule_id, rule in rules.items():
            assert rule.asvs_controls, f"{rule_id} has no asvs_controls"
            assert rule.severity

    def test_loads_from_an_explicit_path(self, tmp_path):
        path = tmp_path / "custom_queries.json"
        path.write_text(json.dumps({
            "MY_RULE": {"check_type": "payload", "asvs_controls": ["V1.2.3"], "severity": "high"},
        }), encoding="utf-8")

        rules = load_dynamic_queries(path)

        assert set(rules) == {"MY_RULE"}
        assert rules["MY_RULE"].check_type == "payload"
        assert rules["MY_RULE"].severity == "high"

    def test_defaults_applied_when_optional_fields_omitted(self, tmp_path):
        path = tmp_path / "minimal.json"
        path.write_text(json.dumps({"BARE_RULE": {"check_type": "scenario"}}), encoding="utf-8")

        rules = load_dynamic_queries(path)
        rule = rules["BARE_RULE"]

        assert rule.asvs_controls == []
        assert rule.owasp == ""
        assert rule.cwe is None
        assert rule.severity == "medium"
        assert rule.description == ""
        assert rule.requires_active_mode is False

    def test_extra_check_specific_fields_are_preserved(self, tmp_path):
        """extra='allow' — checks.py reads check-specific parameters (payload
        templates, candidate param names, ...) straight off the model via
        getattr, so unknown keys must not be silently dropped or rejected."""
        path = tmp_path / "extra.json"
        path.write_text(json.dumps({
            "PAYLOAD_RULE": {
                "check_type": "payload",
                "payload_template": "' OR 1=1--",
                "candidate_params": ["id", "user_id"],
            },
        }), encoding="utf-8")

        rules = load_dynamic_queries(path)
        rule = rules["PAYLOAD_RULE"]

        assert rule.payload_template == "' OR 1=1--"
        assert rule.candidate_params == ["id", "user_id"]

    def test_missing_required_check_type_raises(self, tmp_path):
        path = tmp_path / "invalid.json"
        path.write_text(json.dumps({"BAD_RULE": {"severity": "low"}}), encoding="utf-8")

        with pytest.raises(ValidationError):
            load_dynamic_queries(path)

    def test_missing_file_raises_file_not_found(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_dynamic_queries(tmp_path / "does_not_exist.json")

    def test_requires_active_mode_gates_side_effecting_rules(self, tmp_path):
        path = tmp_path / "active.json"
        path.write_text(json.dumps({
            "SMUGGLING_RULE": {"check_type": "scenario", "requires_active_mode": True},
        }), encoding="utf-8")

        rules = load_dynamic_queries(path)
        assert rules["SMUGGLING_RULE"].requires_active_mode is True
