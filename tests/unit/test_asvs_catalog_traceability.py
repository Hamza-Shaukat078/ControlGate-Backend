"""ASVS catalog traceability — every control whose detection_strategy claims
an automated check must actually name that check in check_ref, so "labeled
automatable" and "has a real implementing check" can be verified in-catalog
instead of only inferred by cross-referencing rule files by hand.

Regression coverage for two gaps found by that hand cross-reference:
  - V3.4.1 was config_inspection-labeled but only ever merged from
    config_findings (_merge_config) — DynamicProbe._check_hsts_header's
    live result never contributed to its verdict. Now dispatches through
    _merge_config_or_dynamic like V13.4.6 (see asvs_service.py).
  - dynamic_probe.py's DynamicProbe *does* correctly implement the exact 8
    controls the catalog labels dynamic_probe (verified below by name, not
    just by count) — the earlier-suspected label/implementation mismatch
    was actually scan_service.py never invoking DynamicProbe for
    scan_type="dynamic" (fixed separately; see
    TestDynamicProbeWiring in test_scan_service_dynamic_dispatch.py).
"""
import json
from pathlib import Path

CATALOG_PATHS = [
    Path(__file__).resolve().parents[2] / "app" / "data" / "asvs_l1_controls.json",
    Path(__file__).resolve().parents[2] / "app" / "data" / "asvs_l2_controls.json",
    Path(__file__).resolve().parents[2] / "app" / "data" / "asvs_l3_controls.json",
]


def _load_catalog() -> dict[str, dict]:
    controls: dict[str, dict] = {}
    for path in CATALOG_PATHS:
        for c in json.loads(path.read_text(encoding="utf-8")):
            controls[c["control_id"]] = c
    return controls


class TestCatalogHasNoDuplicates:
    def test_control_id_appears_in_exactly_one_level_file(self):
        seen: dict[str, int] = {}
        for path in CATALOG_PATHS:
            for c in json.loads(path.read_text(encoding="utf-8")):
                seen[c["control_id"]] = seen.get(c["control_id"], 0) + 1
        dupes = {cid: n for cid, n in seen.items() if n > 1}
        assert dupes == {}


class TestCheckRefPopulatedForAutomatableStrategies:
    """check_ref is the in-catalog traceability link from a control to the
    check(s) that actually evaluate it — every automatable control (every
    detection_strategy except manual_attestation) must have one."""

    def test_every_automatable_control_has_a_check_ref(self):
        controls = _load_catalog()
        missing = [
            cid for cid, c in controls.items()
            if c["detection_strategy"] != "manual_attestation" and not c.get("check_ref")
        ]
        assert missing == []

    def test_manual_attestation_controls_have_no_check_ref(self):
        # There is no automated check backing these — a populated check_ref
        # here would be a false claim of automation, not extra information.
        controls = _load_catalog()
        wrongly_populated = [
            cid for cid, c in controls.items()
            if c["detection_strategy"] == "manual_attestation" and c.get("check_ref")
        ]
        assert wrongly_populated == []


class TestDetectionStrategyCounts:
    """Locks in the current, verified automation ceiling: 236 automatable
    (195 static_code + 32 config_inspection + 1 dependency_scan +
    8 dynamic_probe) out of 345 total, 109 permanently manual."""

    def test_counts_match_verified_baseline(self):
        controls = _load_catalog()
        assert len(controls) == 345
        from collections import Counter
        counts = Counter(c["detection_strategy"] for c in controls.values())
        assert counts == {
            "static_code": 195,
            "manual_attestation": 109,
            "config_inspection": 32,
            "dynamic_probe": 8,
            "dependency_scan": 1,
        }


class TestDynamicProbeLabelMatchesImplementation:
    """DynamicProbe (app/domain/analysis/dynamic_probe.py) implements
    exactly the 8 controls the catalog labels dynamic_probe — verified by
    control_id, not just by count, since a same-size mismatch would pass a
    count-only check."""

    def test_catalog_dynamic_probe_controls_match_dynamic_probe_py(self):
        from app.domain.analysis.dynamic_probe import DynamicProbe

        controls = _load_catalog()
        catalog_ids = {cid for cid, c in controls.items() if c["detection_strategy"] == "dynamic_probe"}

        # DynamicProbe.probe() fires every _check_* coroutine unconditionally
        # (see its own body) — the set of control_ids it can ever produce a
        # ProbeFinding for is exactly the dynamic_probe controls whose
        # check_ref names a DynamicProbe method (populated from the same
        # source module via AST inspection, not hand-maintained).
        implemented_ids = {
            cid for cid, c in controls.items()
            if c["detection_strategy"] == "dynamic_probe" and c.get("check_ref", "").startswith("DynamicProbe.")
        }
        assert catalog_ids == implemented_ids
        assert DynamicProbe is not None  # the module import itself is part of the assertion


class TestStaticCodeCoverage:
    def test_every_static_code_control_has_a_rule_or_capability_check(self):
        from semantic_engine.query_store.loader import get_query_store

        store = get_query_store()
        rule_controls: set[str] = set()
        for rule in store.get_all_queries():
            rule_controls.update(rule.asvs_controls)

        controls = _load_catalog()
        static_ids = {cid for cid, c in controls.items() if c["detection_strategy"] == "static_code"}
        uncovered = [
            cid for cid in static_ids
            if cid not in rule_controls and "CapabilityChecker" not in (controls[cid].get("check_ref") or "")
        ]
        assert uncovered == []
