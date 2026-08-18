"""
ASVSService merge-logic tests — the verdict computation across all four
detection strategies plus manual attestation (Section F).

Uses a hand-rolled async-compatible fake Mongo layer rather than the
project's `mongo_db` conftest fixture: that fixture wraps a plain
`mongomock.MongoClient()`, whose collection methods return plain dicts, not
awaitables — `await db.x.find_one(...)` raises `TypeError: object dict can't
be used in await expression` with the mongomock version pinned in this repo.
That's a pre-existing environment issue (visible across this whole test
suite as the standing ~86 unrelated integration-test failures/errors — it
predates every section of this work), not something to route around
silently — but it does mean this suite needs its own minimal async-aware
fake rather than inheriting a broken fixture.
"""
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from app.services.asvs_service import (
    ASVSService,
    HYBRID_ATTESTATION_CAPABILITY_ELIGIBLE_CONTROLS,
    HYBRID_ATTESTATION_DEPENDENCY_ELIGIBLE_CONTROLS,
    HYBRID_ATTESTATION_DYNAMIC_ELIGIBLE_CONTROLS,
    HYBRID_ATTESTATION_ELIGIBLE_CONTROLS,
    _level_includes,
    _not_tested,
)

CATALOG = json.loads(
    (Path(__file__).resolve().parents[2] / "app" / "data" / "asvs_l1_controls.json").read_text(encoding="utf-8")
)


class FakeCursor:
    def __init__(self, docs):
        self.docs = docs

    def sort(self, *a, **kw):
        return self

    async def to_list(self, length=None):
        return self.docs

    def __aiter__(self):
        async def gen():
            for d in self.docs:
                yield d
        return gen()


class FakeCollection:
    def __init__(self, docs=None):
        self.docs = docs or []

    def find(self, *a, **kw):
        return FakeCursor(self.docs)

    async def find_one(self, query, sort=None):
        for d in self.docs:
            if all(d.get(k) == v for k, v in query.items()):
                return d
        return None

    async def update_one(self, *a, **kw):
        return MagicMock()


class FakeDB:
    def __init__(self, scan_summary=None, attestations=None):
        self.asvs_controls = FakeCollection(CATALOG)
        self.attestations = FakeCollection(attestations or [])
        self.asvs_results = FakeCollection([])
        scans = [{"scan_id": "scan-1", "summary": scan_summary}] if scan_summary is not None else []
        self.scans = FakeCollection(scans)


def _summary(**overrides):
    base = {
        "scan_id": "scan-1", "vulnerabilities": [], "config_findings": [],
        "dependency_findings": [], "dependency_control_result": None,
        "dynamic_probe_findings": [],
        # _merge_static_code's "pass by absence" branch requires total_files
        # to distinguish "static analysis ran across N files and found
        # nothing" (a real pass) from "no static analysis ran at all"
        # (dynamic-only scan, correctly not_tested) — every real scan
        # summary always carries this, so the fixture needs it too.
        "total_files": 1, "files_scanned": 1,
    }
    base.update(overrides)
    return base


class TestLevelIncludes:
    def test_l1_control_counts_toward_all_levels(self):
        assert _level_includes("L1", "L1") is True
        assert _level_includes("L1", "L2") is True
        assert _level_includes("L1", "L3") is True

    def test_l2_control_does_not_count_toward_l1(self):
        assert _level_includes("L2", "L1") is False
        assert _level_includes("L2", "L2") is True


class TestStaticCodeMerge:
    @pytest.mark.asyncio
    async def test_vulnerable_finding_fails(self):
        summary = _summary(vulnerabilities=[{
            "type": "JWT issue", "asvs_controls": ["V9.2.1"], "confidence": 0.9,
            "location": {"file": "auth.py", "start_line": 5},
            "analysis": {"llm_classification": {"explanation": "verify_exp disabled"}},
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        results = await svc.build_results_for_scan("scan-1")
        r = results["V9.2.1"]
        assert r["verdict"] == "fail"
        assert r["evidence"][0]["file"] == "auth.py"
        assert r["llm_explanation"] == "verify_exp disabled"

    @pytest.mark.asyncio
    async def test_unconfirmed_fallback_only_hit_becomes_manual_review(self):
        # Regression: when the LLM was rate-limited/unavailable for every matching
        # slice, the classifier's static-only fallback used to be trusted as a
        # confident "fail" — a guess with no real confirmation. It should now
        # surface as manual_review instead of silently asserting a failure.
        summary = _summary(vulnerabilities=[{
            "type": "SQL Injection", "asvs_controls": ["V1.2.4"], "confidence": 0.65,
            "location": {"file": "database.js", "start_line": 17},
            "analysis": {"llm_classification": {"explanation": "LLM unavailable — pattern-based detection only"}},
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        results = await svc.build_results_for_scan("scan-1")
        r = results["V1.2.4"]
        assert r["verdict"] == "manual_review"
        assert "could not confirm" in r["llm_explanation"]

    @pytest.mark.asyncio
    async def test_confirmed_hit_still_fails_even_alongside_unconfirmed_ones(self):
        # A real LLM-confirmed finding must still fail the control, regardless of
        # whether other unconfirmed static-only matches also exist for it.
        summary = _summary(vulnerabilities=[
            {
                "type": "SQL Injection", "asvs_controls": ["V1.2.4"], "confidence": 0.65,
                "location": {"file": "database.js", "start_line": 17},
                "analysis": {"llm_classification": {"explanation": "LLM cap reached — static analysis only"}},
            },
            {
                "type": "SQL Injection", "asvs_controls": ["V1.2.4"], "confidence": 0.9,
                "location": {"file": "app.py", "start_line": 30},
                "analysis": {"llm_classification": {"explanation": "Untrusted input concatenated into SQL string"}},
            },
        ])
        svc = ASVSService(FakeDB(scan_summary=summary))
        results = await svc.build_results_for_scan("scan-1")
        r = results["V1.2.4"]
        assert r["verdict"] == "fail"
        assert r["evidence"][0]["file"] == "app.py"

    @pytest.mark.asyncio
    async def test_bridge_confirmed_upgrades_unconfirmed_llm_hit_to_fail(self):
        # A live DAST bridge reproduction (scan_service.py's hybrid-scan
        # correlation, exact same route) is direct, independent evidence —
        # it must be able to turn an LLM-unconfirmed static pattern match
        # into a real fail, not leave it stuck at manual_review just because
        # the LLM itself was rate-limited/unavailable during this scan.
        summary = _summary(vulnerabilities=[{
            "type": "SQL Injection", "asvs_controls": ["V1.2.4"], "confidence": 0.65,
            "location": {"file": "database.js", "start_line": 17},
            "analysis": {"llm_classification": {"explanation": "LLM unavailable — pattern-based detection only"}},
            "bridge_confirmed": True, "bridge_verdict": "confirmed",
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        results = await svc.build_results_for_scan("scan-1")
        r = results["V1.2.4"]
        assert r["verdict"] == "fail"
        assert r["fail_basis"] == "confirmed"
        assert "dynamic scan independently reproduced" in r["llm_explanation"]

    @pytest.mark.asyncio
    async def test_plain_dynamic_confirmed_without_bridge_does_not_upgrade(self):
        # Coarse dynamic_confirmed (some dynamic finding merely shares this
        # control, not proven to be the same route) is NOT enough on its
        # own — only the precise bridge_confirmed tier counts as decisive
        # evidence. Anything weaker must stay manual_review, same as before.
        summary = _summary(vulnerabilities=[{
            "type": "SQL Injection", "asvs_controls": ["V1.2.4"], "confidence": 0.65,
            "location": {"file": "database.js", "start_line": 17},
            "analysis": {"llm_classification": {"explanation": "LLM unavailable — pattern-based detection only"}},
            "dynamic_confirmed": True,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        results = await svc.build_results_for_scan("scan-1")
        r = results["V1.2.4"]
        assert r["verdict"] == "manual_review"

    @pytest.mark.asyncio
    async def test_llm_confirmed_hit_unaffected_by_bridge_explanation_branch(self):
        # An LLM-confirmed hit that also happens to be bridge_confirmed must
        # still show the LLM's own explanation, not the bridge fallback
        # text — the fallback text is only for the LLM-never-reviewed case.
        summary = _summary(vulnerabilities=[{
            "type": "SQL Injection", "asvs_controls": ["V1.2.4"], "confidence": 0.9,
            "location": {"file": "database.js", "start_line": 17},
            "analysis": {"llm_classification": {"explanation": "Untrusted input concatenated into SQL string"}},
            "bridge_confirmed": True, "bridge_verdict": "confirmed",
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        results = await svc.build_results_for_scan("scan-1")
        r = results["V1.2.4"]
        assert r["verdict"] == "fail"
        assert r["llm_explanation"] == "Untrusted input concatenated into SQL string"

    @pytest.mark.asyncio
    async def test_no_finding_on_vulnerable_polarity_rule_passes(self):
        # V1.2.4 (SQL injection) is a vulnerable-polarity rule with full coverage;
        # no matching finding means the rule ran across the repo and found nothing.
        svc = ASVSService(FakeDB(scan_summary=_summary()))
        results = await svc.build_results_for_scan("scan-1")
        assert results["V1.2.4"]["verdict"] == "pass"

    @pytest.mark.asyncio
    async def test_pass_by_absence_has_a_reason_not_just_llm_explanation(self):
        # Regression: a "pass by absence" verdict used to leave `reason`
        # None (only `llm_explanation` carried the explanation) — the
        # frontend's evidence panel only checked `reason` for not_tested,
        # so a genuinely-evaluated pass looked identical to "never
        # evaluated". `reason` must be populated (and name the rule that
        # actually ran) regardless of verdict whenever evidence is empty.
        svc = ASVSService(FakeDB(scan_summary=_summary()))
        results = await svc.build_results_for_scan("scan-1")
        r = results["V1.2.4"]
        assert r["evidence"] == []
        assert r["reason"]
        assert "SQL Injection" in r["reason"] or "SQL_INJECTION" in r["reason"]

    @pytest.mark.asyncio
    async def test_pass_by_absence_reason_mentions_files_scanned(self):
        summary = _summary()
        summary["files_scanned"] = 12
        svc = ASVSService(FakeDB(scan_summary=summary))
        results = await svc.build_results_for_scan("scan-1")
        assert "12" in results["V1.2.4"]["reason"]

    @pytest.mark.asyncio
    async def test_no_finding_on_marker_polarity_rule_is_not_tested(self):
        # V6.2.2 is covered only by a "compliant"-polarity marker rule
        # (PASSWORD_CHANGE_ENDPOINT) — absence isn't proof of absence.
        svc = ASVSService(FakeDB(scan_summary=_summary()))
        results = await svc.build_results_for_scan("scan-1")
        assert results["V6.2.2"]["verdict"] == "not_tested"

    @pytest.mark.asyncio
    async def test_marker_polarity_finding_present_passes(self):
        summary = _summary(vulnerabilities=[{
            "type": "Password Change Capability Marker", "asvs_controls": ["V6.2.2"],
            "asvs_finding_polarity": "compliant", "confidence": 0.5,
            "location": {"file": "auth.py", "start_line": 40},
            "analysis": {"llm_classification": {}},
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        results = await svc.build_results_for_scan("scan-1")
        assert results["V6.2.2"]["verdict"] == "pass"

    @pytest.mark.asyncio
    async def test_no_scan_at_all_is_not_tested(self):
        svc = ASVSService(FakeDB(scan_summary=None))
        results = await svc.build_results_for_scan("scan-does-not-exist")
        assert results["V1.2.4"]["verdict"] == "not_tested"


class TestConfigInspectionMerge:
    @pytest.mark.asyncio
    async def test_fail_finding_wins(self):
        summary = _summary(config_findings=[
            {"control_id": "V3.4.1", "verdict": "pass", "file": "a.conf", "line": 1, "note": "ok", "confidence": 0.6},
            {"control_id": "V3.4.1", "verdict": "fail", "file": "b.conf", "line": 2, "note": "bad", "confidence": 0.8},
        ])
        svc = ASVSService(FakeDB(scan_summary=summary))
        results = await svc.build_results_for_scan("scan-1")
        assert results["V3.4.1"]["verdict"] == "fail"

    @pytest.mark.asyncio
    async def test_pass_finding_alone_passes(self):
        summary = _summary(config_findings=[
            {"control_id": "V5.2.1", "verdict": "pass", "file": "nginx.conf", "line": 3, "note": "ok", "confidence": 0.85},
        ])
        svc = ASVSService(FakeDB(scan_summary=summary))
        results = await svc.build_results_for_scan("scan-1")
        assert results["V5.2.1"]["verdict"] == "pass"

    @pytest.mark.asyncio
    async def test_no_findings_not_tested(self):
        svc = ASVSService(FakeDB(scan_summary=_summary()))
        results = await svc.build_results_for_scan("scan-1")
        assert results["V4.1.1"]["verdict"] == "not_tested"


class TestConfigOrCompliantStaticMerge:
    """
    V3.5.8 is the one control wired to _merge_config_or_compliant_static instead
    of the plain _merge_config path: the requirement is satisfied by EITHER a
    restrictive Cross-Origin-Resource-Policy header (config_inspection) OR a
    Sec-Fetch-* validation marker in application code (a compliant-polarity
    static finding) — so evaluating it needs both signal sources merged with OR
    semantics, not treated as conflicting evidence.

    Called directly (not via build_results_for_scan) since the fake catalog
    above only loads the L1 file and V3.5.8 is an L2-file/L3-level control.
    """

    def test_failing_config_with_compliant_static_marker_still_passes(self):
        # The important precedence case: a missing/failing CORP header must NOT
        # override a compliant Sec-Fetch-* marker found in code, because the
        # control is genuinely satisfied by either one. If this ever starts
        # failing, someone changed the branch order so "any fail wins" beats
        # the OR semantics the control actually requires.
        summary = _summary(
            config_findings=[
                {"control_id": "V3.5.8", "verdict": "fail", "file": "nginx.conf", "line": 4,
                 "note": "no CORP header", "confidence": 0.5},
            ],
            vulnerabilities=[{
                "type": "Sec-Fetch Resource Guard Marker", "asvs_controls": ["V3.5.8"],
                "asvs_finding_polarity": "compliant", "confidence": 0.6,
                "location": {"file": "middleware.js", "start_line": 12},
                "analysis": {"llm_classification": {}},
            }],
        )
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_config_or_compliant_static("V3.5.8", summary, "scan-1")
        assert r["verdict"] == "pass"

    def test_passing_config_alone_passes(self):
        summary = _summary(config_findings=[
            {"control_id": "V3.5.8", "verdict": "pass", "file": "nginx.conf", "line": 4,
             "note": "Cross-Origin-Resource-Policy: same-origin", "confidence": 0.75},
        ])
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_config_or_compliant_static("V3.5.8", summary, "scan-1")
        assert r["verdict"] == "pass"
        assert r["evidence"][0]["file"] == "nginx.conf"

    def test_compliant_static_marker_alone_passes_with_no_config_findings(self):
        # No nginx.conf in the repo at all — config_findings is empty, not failing.
        # A code-level Sec-Fetch-* marker should still be sufficient on its own.
        summary = _summary(vulnerabilities=[{
            "type": "Sec-Fetch Resource Guard Marker", "asvs_controls": ["V3.5.8"],
            "asvs_finding_polarity": "compliant", "confidence": 0.6,
            "location": {"file": "middleware.js", "start_line": 12},
            "analysis": {"llm_classification": {}},
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_config_or_compliant_static("V3.5.8", summary, "scan-1")
        assert r["verdict"] == "pass"
        assert r["evidence"][0]["file"] == "middleware.js"

    def test_no_evidence_at_all_is_not_tested(self):
        summary = _summary()
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_config_or_compliant_static("V3.5.8", summary, "scan-1")
        assert r["verdict"] == "not_tested"

    def test_failing_config_with_no_static_marker_fails(self):
        summary = _summary(config_findings=[
            {"control_id": "V3.5.8", "verdict": "fail", "file": "nginx.conf", "line": 4,
             "note": "no CORP header", "confidence": 0.5},
        ])
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_config_or_compliant_static("V3.5.8", summary, "scan-1")
        assert r["verdict"] == "fail"


class TestAttestationOrVulnerableStaticMerge:
    """
    V1.1.1 is the one manual_attestation control also wired to
    _merge_attestation_or_vulnerable_static: a confirmed
    DOUBLE_DECODE_CANONICALIZATION hit (LLM-reviewed, or DAST-bridge
    reproduced) is real independent evidence and fails the control outright
    — but unlike the HYBRID_STATIC_ELIGIBLE_CONTROLS controls above, there
    is no corresponding "pass" side: no hit (confirmed or not) ever passes
    V1.1.1 on its own, only a human attestation does.
    """

    def test_confirmed_llm_hit_fails_with_no_attestation(self):
        summary = _summary(vulnerabilities=[{
            "type": "Untrusted Input Decoded/Canonicalized More Than Once",
            "asvs_controls": ["V1.1.1"], "confidence": 0.7,
            "location": {"file": "views.py", "start_line": 40},
            "analysis": {"llm_classification": {"explanation": "Double-decoding allows a %252e%252e%252f bypass."}},
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_vulnerable_static("V1.1.1", summary, {}, "scan-1")
        assert r["verdict"] == "fail"
        assert r["fail_basis"] == "confirmed"

    def test_confirmed_hit_fails_even_with_a_passing_attestation(self):
        # The important precedence case: a stale/incorrect "pass" attestation
        # must not mask a confirmed, independently-detected violation —
        # same fail-always-wins policy as every other hybrid control here.
        summary = _summary(vulnerabilities=[{
            "type": "Untrusted Input Decoded/Canonicalized More Than Once",
            "asvs_controls": ["V1.1.1"], "confidence": 0.7,
            "location": {"file": "views.py", "start_line": 40},
            "analysis": {"llm_classification": {"explanation": "Double-decoding allows a bypass."}},
        }])
        attestations = {"V1.1.1": {"answer": "pass", "attested_by": "alice@example.com"}}
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_vulnerable_static("V1.1.1", summary, attestations, "scan-1")
        assert r["verdict"] == "fail"

    def test_bridge_confirmed_hit_fails_without_llm_review(self):
        summary = _summary(vulnerabilities=[{
            "type": "Untrusted Input Decoded/Canonicalized More Than Once",
            "asvs_controls": ["V1.1.1"], "confidence": 0.65, "bridge_confirmed": True,
            "location": {"file": "views.py", "start_line": 40},
            "analysis": {"llm_classification": {"explanation": "LLM unavailable — pattern-based detection only"}},
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_vulnerable_static("V1.1.1", summary, {}, "scan-1")
        assert r["verdict"] == "fail"

    def test_unconfirmed_hit_falls_through_to_attestation_not_tested(self):
        # LLM rate-limited/unavailable, no bridge reproduction — same as
        # _merge_static, this isn't decisive enough to assert a fail. With
        # no attestation submitted either, the control stays not_tested.
        summary = _summary(vulnerabilities=[{
            "type": "Untrusted Input Decoded/Canonicalized More Than Once",
            "asvs_controls": ["V1.1.1"], "confidence": 0.5,
            "location": {"file": "views.py", "start_line": 40},
            "analysis": {"llm_classification": {"explanation": "LLM unavailable — pattern-based detection only"}},
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_vulnerable_static("V1.1.1", summary, {}, "scan-1")
        assert r["verdict"] == "not_tested"

    def test_unconfirmed_hit_still_allows_a_passing_attestation_through(self):
        summary = _summary(vulnerabilities=[{
            "type": "Untrusted Input Decoded/Canonicalized More Than Once",
            "asvs_controls": ["V1.1.1"], "confidence": 0.5,
            "location": {"file": "views.py", "start_line": 40},
            "analysis": {"llm_classification": {"explanation": "LLM unavailable — pattern-based detection only"}},
        }])
        attestations = {"V1.1.1": {"answer": "pass", "attested_by": "alice@example.com", "evidence_url": "https://example.com/review"}}
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_vulnerable_static("V1.1.1", summary, attestations, "scan-1")
        assert r["verdict"] == "pass"

    def test_no_static_hit_delegates_to_plain_attestation(self):
        summary = _summary()
        attestations = {"V1.1.1": {"answer": "pass", "attested_by": "alice@example.com", "evidence_url": "https://example.com/review"}}
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_vulnerable_static("V1.1.1", summary, attestations, "scan-1")
        assert r["verdict"] == "pass"

    def test_no_static_hit_and_no_attestation_is_not_tested(self):
        summary = _summary()
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_vulnerable_static("V1.1.1", summary, {}, "scan-1")
        assert r["verdict"] == "not_tested"

    def test_compute_result_dispatches_v1_1_1_through_hybrid_path(self):
        # _compute_result's dispatch (not just the merge method called
        # directly) — confirms HYBRID_ATTESTATION_ELIGIBLE_CONTROLS routing
        # actually wires up, without going through build_results_for_scan's
        # full catalog load (the fake catalog here is L1-only and V1.1.1 is
        # an L2-file control — same caveat TestConfigOrCompliantStaticMerge
        # documents for V3.5.8 above).
        summary = _summary(vulnerabilities=[{
            "type": "Untrusted Input Decoded/Canonicalized More Than Once",
            "asvs_controls": ["V1.1.1"], "confidence": 0.7,
            "location": {"file": "views.py", "start_line": 40},
            "analysis": {"llm_classification": {"explanation": "Double-decoding allows a bypass."}},
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        control = {"control_id": "V1.1.1", "detection_strategy": "manual_attestation"}
        r = svc._compute_result(control, summary, {}, "scan-1")
        assert r["verdict"] == "fail"

    def test_v1_5_3_confirmed_hit_fails_via_the_same_generic_merge_path(self):
        # V1.5.3 shares _merge_attestation_or_vulnerable_static with V1.1.1 —
        # nothing control-specific in the method itself, just the
        # HYBRID_ATTESTATION_ELIGIBLE_CONTROLS membership and which rule
        # tags asvs_controls with this control_id.
        summary = _summary(vulnerabilities=[{
            "type": "URL Host Extracted Via Manual String Splitting Instead Of A URL Parser",
            "asvs_controls": ["V1.5.3"], "confidence": 0.6,
            "location": {"file": "ssrf_guard.py", "start_line": 12},
            "analysis": {"llm_classification": {"explanation": "Hand-rolled host extraction bypasses the allowlist parser."}},
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        control = {"control_id": "V1.5.3", "detection_strategy": "manual_attestation"}
        r = svc._compute_result(control, summary, {}, "scan-1")
        assert r["verdict"] == "fail"

    def test_v1_5_3_no_hit_delegates_to_plain_attestation(self):
        summary = _summary()
        attestations = {"V1.5.3": {"answer": "pass", "attested_by": "alice@example.com", "evidence_url": "https://example.com/review"}}
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_vulnerable_static("V1.5.3", summary, attestations, "scan-1")
        assert r["verdict"] == "pass"

    def test_v2_3_3_confirmed_hit_fails_via_the_same_generic_merge_path(self):
        summary = _summary(vulnerabilities=[{
            "type": "Multiple Database Writes With No Transaction Boundary",
            "asvs_controls": ["V2.3.3"], "confidence": 0.6,
            "location": {"file": "checkout.py", "start_line": 88},
            "analysis": {"llm_classification": {"explanation": "Order and inventory writes have no shared transaction boundary."}},
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        control = {"control_id": "V2.3.3", "detection_strategy": "manual_attestation"}
        r = svc._compute_result(control, summary, {}, "scan-1")
        assert r["verdict"] == "fail"

    def test_v2_3_3_no_hit_delegates_to_plain_attestation(self):
        summary = _summary()
        attestations = {"V2.3.3": {"answer": "pass", "attested_by": "alice@example.com", "evidence_url": "https://example.com/review"}}
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_vulnerable_static("V2.3.3", summary, attestations, "scan-1")
        assert r["verdict"] == "pass"

    def test_v6_3_4_confirmed_backdoor_hit_fails_via_the_same_generic_merge_path(self):
        summary = _summary(vulnerabilities=[{
            "type": "Undocumented or Backdoor Authentication Pathway",
            "asvs_controls": ["V6.3.4"], "confidence": 0.6,
            "location": {"file": "auth.py", "start_line": 21},
            "analysis": {"llm_classification": {"explanation": "A hardcoded X-Debug-Auth header grants a session, bypassing login."}},
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        control = {"control_id": "V6.3.4", "detection_strategy": "manual_attestation"}
        r = svc._compute_result(control, summary, {}, "scan-1")
        assert r["verdict"] == "fail"

    def test_v6_3_4_no_hit_delegates_to_plain_attestation(self):
        # AUTH_BACKDOOR_BYPASS firing zero times is not proof no backdoor
        # pathway exists (the control's own description says as much) — a
        # clean scan still needs a human's full authentication-flow audit.
        summary = _summary()
        attestations = {"V6.3.4": {"answer": "pass", "attested_by": "alice@example.com", "evidence_url": "https://example.com/review"}}
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_vulnerable_static("V6.3.4", summary, attestations, "scan-1")
        assert r["verdict"] == "pass"

    def test_v10_3_2_confirmed_missing_audience_check_fails_the_control(self):
        # JWT_MISSING_AUDIENCE_CHECK now also tags V10.3.2 (queries.json) —
        # no new rule needed, reuses the existing V9.2.3/V10.3.1 evidence.
        summary = _summary(vulnerabilities=[{
            "type": "JWT Decoded Without Audience Validation",
            "asvs_controls": ["V9.2.3", "V10.3.1", "V10.3.2"], "confidence": 0.6,
            "location": {"file": "auth.py", "start_line": 30},
            "analysis": {"llm_classification": {"explanation": "jwt.decode() never passes audience=, accepting tokens issued for any service."}},
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        control = {"control_id": "V10.3.2", "detection_strategy": "manual_attestation"}
        r = svc._compute_result(control, summary, {}, "scan-1")
        assert r["verdict"] == "fail"

    def test_v10_3_2_no_hit_delegates_to_plain_attestation(self):
        summary = _summary()
        attestations = {"V10.3.2": {"answer": "pass", "attested_by": "alice@example.com", "evidence_url": "https://example.com/review"}}
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_vulnerable_static("V10.3.2", summary, attestations, "scan-1")
        assert r["verdict"] == "pass"


class TestAttestationOrDynamicFindingMerge:
    """
    V3.7.3 is wired to _merge_attestation_or_dynamic_finding — the DAST
    counterpart of _merge_attestation_or_vulnerable_static above: the second
    evidence source is a live REDIRECT_WARNING_LIVE probe result
    (summary["dynamic_findings"]) instead of a static rule-catalog match.
    Unlike the static hybrid method, there's no separate LLM-confirmation
    gate — a FAIL/CONFIRMED verdict from the probe is decisive on its own,
    since the live interaction already is the confirmation.
    """

    def test_fail_verdict_from_probe_fails_the_control(self):
        summary = _summary(dynamic_findings=[{
            "control_id": "V3.7.3", "verdict": "fail", "rule_id": "REDIRECT_WARNING_LIVE",
            "note": "silent redirect observed", "severity": "medium", "confidence": 0.75,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_dynamic_finding("V3.7.3", summary, {}, "scan-1")
        assert r["verdict"] == "fail"
        assert r["fail_basis"] == "confirmed"

    def test_confirmed_verdict_from_probe_fails_the_control(self):
        summary = _summary(dynamic_findings=[{
            "control_id": "V3.7.3", "verdict": "confirmed", "rule_id": "REDIRECT_WARNING_LIVE",
            "note": "silent redirect observed", "severity": "medium", "confidence": 0.8,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_dynamic_finding("V3.7.3", summary, {}, "scan-1")
        assert r["verdict"] == "fail"

    def test_fail_verdict_fails_even_with_a_passing_attestation(self):
        # Same precedence case as the static hybrid method: a stale/incorrect
        # "pass" attestation must not mask a live, confirmed violation.
        summary = _summary(dynamic_findings=[{
            "control_id": "V3.7.3", "verdict": "fail", "rule_id": "REDIRECT_WARNING_LIVE",
            "note": "silent redirect observed", "severity": "medium", "confidence": 0.75,
        }])
        attestations = {"V3.7.3": {"answer": "pass", "attested_by": "alice@example.com"}}
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_dynamic_finding("V3.7.3", summary, attestations, "scan-1")
        assert r["verdict"] == "fail"

    def test_pass_verdict_from_probe_never_passes_on_its_own(self):
        # The whole epistemic point of this probe: a clean result doesn't
        # confirm a real, working interstitial — falls through to attestation.
        summary = _summary(dynamic_findings=[{
            "control_id": "V3.7.3", "verdict": "pass", "rule_id": "REDIRECT_WARNING_LIVE",
            "note": "no immediate navigation observed", "severity": "medium", "confidence": 0.45,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_dynamic_finding("V3.7.3", summary, {}, "scan-1")
        assert r["verdict"] == "not_tested"

    def test_pass_verdict_from_probe_still_allows_a_passing_attestation_through(self):
        summary = _summary(dynamic_findings=[{
            "control_id": "V3.7.3", "verdict": "pass", "rule_id": "REDIRECT_WARNING_LIVE",
            "note": "no immediate navigation observed", "severity": "medium", "confidence": 0.45,
        }])
        attestations = {"V3.7.3": {"answer": "pass", "attested_by": "alice@example.com", "evidence_url": "https://example.com/review"}}
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_dynamic_finding("V3.7.3", summary, attestations, "scan-1")
        assert r["verdict"] == "pass"

    def test_no_dynamic_finding_delegates_to_plain_attestation(self):
        summary = _summary()
        attestations = {"V3.7.3": {"answer": "pass", "attested_by": "alice@example.com", "evidence_url": "https://example.com/review"}}
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_dynamic_finding("V3.7.3", summary, attestations, "scan-1")
        assert r["verdict"] == "pass"

    def test_no_dynamic_finding_and_no_attestation_is_not_tested(self):
        summary = _summary()
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_dynamic_finding("V3.7.3", summary, {}, "scan-1")
        assert r["verdict"] == "not_tested"

    def test_compute_result_dispatches_v3_7_3_through_dynamic_hybrid_path(self):
        summary = _summary(dynamic_findings=[{
            "control_id": "V3.7.3", "verdict": "fail", "rule_id": "REDIRECT_WARNING_LIVE",
            "note": "silent redirect observed", "severity": "medium", "confidence": 0.75,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        control = {"control_id": "V3.7.3", "detection_strategy": "manual_attestation"}
        r = svc._compute_result(control, summary, {}, "scan-1")
        assert r["verdict"] == "fail"

    def test_inconclusive_verdict_does_not_count_as_a_fail(self):
        # Only "fail"/"confirmed" are decisive — every other DAST verdict
        # (inconclusive, not_tested, not_configured, skipped) falls through
        # to attestation, same as a clean pass does.
        summary = _summary(dynamic_findings=[{
            "control_id": "V3.7.3", "verdict": "inconclusive", "rule_id": "REDIRECT_WARNING_LIVE",
            "note": "ambiguous result", "severity": "medium", "confidence": 0.3,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_dynamic_finding("V3.7.3", summary, {}, "scan-1")
        assert r["verdict"] == "not_tested"


class TestHybridDynamicControlsWiredToRealChecks:
    """V4.2.2 (REQUEST_SMUGGLING) and V4.2.4 (CRLF_HEADER_REFLECTION) were
    already tagged with these control_ids in dynamic_queries.json and
    already landing in summary["dynamic_findings"] — before both control_ids
    were added to HYBRID_ATTESTATION_DYNAMIC_ELIGIBLE_CONTROLS, that live
    evidence had no merge path reading it and was silently dropped
    regardless of what the DAST engine found. V4.4.3/V4.4.4 are the same
    hybrid wiring for the two new WebSocket-token checks."""

    def test_v4_2_2_smuggling_fail_dispatches_through_dynamic_hybrid_path(self):
        summary = _summary(dynamic_findings=[{
            "control_id": "V4.2.2", "verdict": "fail", "rule_id": "REQUEST_SMUGGLING",
            "note": "smuggled marker observed", "severity": "critical", "confidence": 0.6,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        control = {"control_id": "V4.2.2", "detection_strategy": "manual_attestation"}
        r = svc._compute_result(control, summary, {}, "scan-1")
        assert r["verdict"] == "fail"
        assert r["fail_basis"] == "confirmed"

    def test_v4_2_4_crlf_reflection_fail_dispatches_through_dynamic_hybrid_path(self):
        summary = _summary(dynamic_findings=[{
            "control_id": "V4.2.4", "verdict": "fail", "rule_id": "CRLF_HEADER_REFLECTION",
            "note": "marker header reflected", "severity": "high", "confidence": 0.75,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        control = {"control_id": "V4.2.4", "detection_strategy": "manual_attestation"}
        r = svc._compute_result(control, summary, {}, "scan-1")
        assert r["verdict"] == "fail"

    def test_v4_4_4_ws_token_unauth_issuance_fail_dispatches_through_dynamic_hybrid_path(self):
        summary = _summary(dynamic_findings=[{
            "control_id": "V4.4.4", "verdict": "fail", "rule_id": "WEBSOCKET_TOKEN_UNAUTH_ISSUANCE",
            "note": "token issued without auth", "severity": "high", "confidence": 0.6,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        control = {"control_id": "V4.4.4", "detection_strategy": "manual_attestation"}
        r = svc._compute_result(control, summary, {}, "scan-1")
        assert r["verdict"] == "fail"

    def test_v4_4_3_ws_token_reuse_fail_dispatches_through_dynamic_hybrid_path(self):
        summary = _summary(dynamic_findings=[{
            "control_id": "V4.4.3", "verdict": "fail", "rule_id": "WEBSOCKET_TOKEN_DERIVED_FROM_SESSION",
            "note": "token matched HTTP session value", "severity": "medium", "confidence": 0.65,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        control = {"control_id": "V4.4.3", "detection_strategy": "manual_attestation"}
        r = svc._compute_result(control, summary, {}, "scan-1")
        assert r["verdict"] == "fail"

    def test_v4_2_2_clean_result_falls_through_to_attestation(self):
        # Same asymmetric-confidence policy as V3.7.3 — a PASS from the
        # smuggling probe never asserts the control passes on its own.
        summary = _summary(dynamic_findings=[{
            "control_id": "V4.2.2", "verdict": "pass", "rule_id": "REQUEST_SMUGGLING",
            "note": "no smuggled marker observed", "severity": "critical", "confidence": 0.45,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_dynamic_finding("V4.2.2", summary, {}, "scan-1")
        assert r["verdict"] == "not_tested"


class TestV6UserSuppliedScenarioControlsWiredToHybridPath:
    """V6.4.3/V6.6.2/V6.8.3 have no built-in probe — the only way a finding
    for them ever reaches summary["dynamic_findings"] is a tester-authored
    dynamic_scenarios entry (DynamicScenarioRequest) tagged with
    asvs_controls=["V6.4.3"|...]. Before these three joined
    HYBRID_ATTESTATION_DYNAMIC_ELIGIBLE_CONTROLS, run_scenario already
    produced that finding but _compute_result had no read path for it
    (same class of gap TestHybridDynamicControlsWiredToRealChecks documents
    for V4.2.2/V4.2.4) — these tests confirm the read path now exists."""

    def test_v6_4_3_reset_bypasses_mfa_scripted_scenario_fails_the_control(self):
        summary = _summary(dynamic_findings=[{
            "control_id": "V6.4.3", "verdict": "fail", "rule_id": "PASSWORD_RESET_MFA_BYPASS_CHECK",
            "note": "an authenticated session was granted immediately after password reset, "
                    "with no MFA challenge in between", "severity": "high", "confidence": 0.7,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        control = {"control_id": "V6.4.3", "detection_strategy": "manual_attestation"}
        r = svc._compute_result(control, summary, {}, "scan-1")
        assert r["verdict"] == "fail"
        assert r["fail_basis"] == "confirmed"

    def test_v6_6_2_otp_replayed_against_foreign_transaction_fails_the_control(self):
        summary = _summary(dynamic_findings=[{
            "control_id": "V6.6.2", "verdict": "fail", "rule_id": "OTP_TRANSACTION_BINDING_CHECK",
            "note": "a valid OTP code was accepted against an unrelated transaction id",
            "severity": "high", "confidence": 0.7,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        control = {"control_id": "V6.6.2", "detection_strategy": "manual_attestation"}
        r = svc._compute_result(control, summary, {}, "scan-1")
        assert r["verdict"] == "fail"

    def test_v6_8_3_replayed_saml_assertion_fails_the_control(self):
        summary = _summary(dynamic_findings=[{
            "control_id": "V6.8.3", "verdict": "confirmed", "rule_id": "SAML_ASSERTION_REPLAY_CHECK",
            "note": "a captured SAML assertion was accepted a second time", "severity": "critical",
            "confidence": 0.85,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        control = {"control_id": "V6.8.3", "detection_strategy": "manual_attestation"}
        r = svc._compute_result(control, summary, {}, "scan-1")
        assert r["verdict"] == "fail"

    def test_v6_4_3_no_scripted_scenario_delegates_to_plain_attestation(self):
        # No dynamic_scenarios were supplied for this control this scan —
        # falls through exactly like every other member of this hybrid set.
        summary = _summary()
        attestations = {"V6.4.3": {"answer": "pass", "attested_by": "alice@example.com", "evidence_url": "https://example.com/review"}}
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_dynamic_finding("V6.4.3", summary, attestations, "scan-1")
        assert r["verdict"] == "pass"


class TestV7HybridControlsWiredToTheDynamicPath:
    """V7.4.3 is DynamicScenarioRequest's own flagship documented example
    (config.py, scan.py, api_scenario.py, and test_dast_api_scenario.py all
    already reference a CRED_CHANGE_KILLS_SESSIONS scenario_id for it) — yet
    it was never added to HYBRID_ATTESTATION_DYNAMIC_ELIGIBLE_CONTROLS, so a
    tester-scripted finding for the one control this mechanism was built to
    demonstrate was silently dropped exactly like V4.2.2/V4.2.4 were before
    those were fixed. V7.4.4 gets a real built-in probe instead
    (check_logout_visible_on_every_page, logout_discovery.py)."""

    def test_v7_4_3_scripted_cross_session_scenario_fails_the_control(self):
        summary = _summary(dynamic_findings=[{
            "control_id": "V7.4.3", "verdict": "fail", "rule_id": "CRED_CHANGE_KILLS_SESSIONS",
            "note": "the secondary session was still usable after the primary changed its password",
            "severity": "high", "confidence": 0.7,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        control = {"control_id": "V7.4.3", "detection_strategy": "manual_attestation"}
        r = svc._compute_result(control, summary, {}, "scan-1")
        assert r["verdict"] == "fail"
        assert r["fail_basis"] == "confirmed"

    def test_v7_4_3_no_scripted_scenario_delegates_to_plain_attestation(self):
        summary = _summary()
        attestations = {"V7.4.3": {"answer": "pass", "attested_by": "alice@example.com", "evidence_url": "https://example.com/review"}}
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_dynamic_finding("V7.4.3", summary, attestations, "scan-1")
        assert r["verdict"] == "pass"

    def test_v7_4_4_missing_logout_control_fails_the_control(self):
        summary = _summary(dynamic_findings=[{
            "control_id": "V7.4.4", "verdict": "fail", "rule_id": "LOGOUT_VISIBLE_ON_EVERY_PAGE",
            "note": "no logout-shaped link or button found on 1 of 3 checked pages",
            "severity": "medium", "confidence": 0.55,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        control = {"control_id": "V7.4.4", "detection_strategy": "manual_attestation"}
        r = svc._compute_result(control, summary, {}, "scan-1")
        assert r["verdict"] == "fail"

    def test_v7_4_4_clean_probe_result_falls_through_to_attestation(self):
        # Markup presence everywhere still doesn't prove real visibility —
        # same asymmetric-confidence policy as every other member of this set.
        summary = _summary(dynamic_findings=[{
            "control_id": "V7.4.4", "verdict": "pass", "rule_id": "LOGOUT_VISIBLE_ON_EVERY_PAGE",
            "note": "found on every checked page", "severity": "medium", "confidence": 0.35,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_dynamic_finding("V7.4.4", summary, {}, "scan-1")
        assert r["verdict"] == "not_tested"


class TestV2AndV8HybridDynamicControlsWiredToTheDynamicPath:
    """V2.3.1 and V8.3.2 are DynamicScenarioRequest's own documented
    examples (scan.py, api_scenario.py), same silently-dropped-finding bug
    as V7.4.3 — never added to HYBRID_ATTESTATION_DYNAMIC_ELIGIBLE_CONTROLS
    until now. V2.3.4 rides DynamicRaceProbeRequest/race_probe.py instead of
    generic dynamic_scenarios but has the same gap. V8.3.3 is new scope
    (nothing in this codebase names or scripts it yet), included because the
    mechanism already expresses the test trivially and the wiring is
    zero-cost until someone actually scripts it."""

    def test_v2_3_1_scripted_step_skipping_scenario_fails_the_control(self):
        summary = _summary(dynamic_findings=[{
            "control_id": "V2.3.1", "verdict": "fail", "rule_id": "CHECKOUT_STEP_SKIPPED",
            "note": "the payment step was skipped and the order still completed",
            "severity": "high", "confidence": 0.7,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        control = {"control_id": "V2.3.1", "detection_strategy": "manual_attestation"}
        r = svc._compute_result(control, summary, {}, "scan-1")
        assert r["verdict"] == "fail"
        assert r["fail_basis"] == "confirmed"

    def test_v2_3_4_race_probe_fail_dispatches_through_hybrid_path(self):
        summary = _summary(dynamic_findings=[{
            "control_id": "V2.3.4", "verdict": "fail", "rule_id": "RACE_CONDITION_PROBE",
            "note": "4 of 5 concurrent requests succeeded where only 1 should have",
            "severity": "high", "confidence": 0.6,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        control = {"control_id": "V2.3.4", "detection_strategy": "manual_attestation"}
        r = svc._compute_result(control, summary, {}, "scan-1")
        assert r["verdict"] == "fail"

    def test_v8_3_2_permission_revoke_not_immediate_fails_the_control(self):
        summary = _summary(dynamic_findings=[{
            "control_id": "V8.3.2", "verdict": "fail", "rule_id": "PERMISSION_REVOKE_TAKES_EFFECT",
            "note": "the revoked role's session could still perform the privileged action",
            "severity": "high", "confidence": 0.65,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        control = {"control_id": "V8.3.2", "detection_strategy": "manual_attestation"}
        r = svc._compute_result(control, summary, {}, "scan-1")
        assert r["verdict"] == "fail"

    def test_v8_3_2_no_scripted_scenario_delegates_to_plain_attestation(self):
        summary = _summary()
        attestations = {"V8.3.2": {"answer": "pass", "attested_by": "alice@example.com", "evidence_url": "https://example.com/review"}}
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_dynamic_finding("V8.3.2", summary, attestations, "scan-1")
        assert r["verdict"] == "pass"

    def test_v8_3_3_confused_deputy_scripted_scenario_fails_the_control(self):
        summary = _summary(dynamic_findings=[{
            "control_id": "V8.3.3", "verdict": "confirmed", "rule_id": "CONFUSED_DEPUTY_CHECK",
            "note": "a low-privileged actor's request through the intermediary service succeeded",
            "severity": "critical", "confidence": 0.75,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        control = {"control_id": "V8.3.3", "detection_strategy": "manual_attestation"}
        r = svc._compute_result(control, summary, {}, "scan-1")
        assert r["verdict"] == "fail"

    def test_v8_3_3_no_scripted_scenario_delegates_to_plain_attestation(self):
        summary = _summary()
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_dynamic_finding("V8.3.3", summary, {}, "scan-1")
        assert r["verdict"] == "not_tested"


class TestV10OAuthLiveProtocolControlsWiredToTheDynamicPath:
    """V10.4.x/V10.7.1 — new scope, same reasoning as V8.3.3: nothing
    pre-existing names them, but each reduces to a small number of scripted
    requests dynamic_scenarios already expresses (now including the new
    assert_body_contains/assert_body_not_contains/
    assert_redirect_location_contains fields and Step.delay_seconds — see
    api_scenario.py and DynamicScenarioStepRequest). Full coverage sweep
    below rather than one test per control_id — the merge mechanism itself
    is already covered by TestV7HybridControlsWiredToTheDynamicPath etc;
    what's specific to V10 is that every one of these 13 control_ids is
    actually IN the set, which a couple of concrete examples don't prove on
    their own."""

    ALL_V10_DYNAMIC_HYBRID_CONTROLS = {
        "V10.4.1", "V10.4.2", "V10.4.3", "V10.4.4", "V10.4.5", "V10.4.7",
        "V10.4.11", "V10.4.12", "V10.4.13", "V10.4.14", "V10.4.15", "V10.4.16",
        "V10.7.1",
    }

    def test_every_intended_v10_control_is_in_the_hybrid_set(self):
        assert self.ALL_V10_DYNAMIC_HYBRID_CONTROLS <= HYBRID_ATTESTATION_DYNAMIC_ELIGIBLE_CONTROLS

    def test_v10_4_1_redirect_uri_tamper_accepted_fails_the_control(self):
        summary = _summary(dynamic_findings=[{
            "control_id": "V10.4.1", "verdict": "fail", "rule_id": "REDIRECT_URI_ALLOWLIST_CHECK",
            "note": "a trailing-slash-modified redirect_uri was still accepted",
            "severity": "high", "confidence": 0.7,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        control = {"control_id": "V10.4.1", "detection_strategy": "manual_attestation"}
        r = svc._compute_result(control, summary, {}, "scan-1")
        assert r["verdict"] == "fail"
        assert r["fail_basis"] == "confirmed"

    def test_v10_4_2_auth_code_replay_accepted_fails_the_control(self):
        summary = _summary(dynamic_findings=[{
            "control_id": "V10.4.2", "verdict": "confirmed", "rule_id": "AUTH_CODE_SINGLE_USE_CHECK",
            "note": "a replayed authorization code issued a second access token",
            "severity": "critical", "confidence": 0.8,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        control = {"control_id": "V10.4.2", "detection_strategy": "manual_attestation"}
        r = svc._compute_result(control, summary, {}, "scan-1")
        assert r["verdict"] == "fail"

    def test_v10_4_3_expired_code_still_accepted_fails_the_control(self):
        summary = _summary(dynamic_findings=[{
            "control_id": "V10.4.3", "verdict": "fail", "rule_id": "AUTH_CODE_LIFETIME_CHECK",
            "note": "an authorization code was exchanged successfully after the 10-minute window",
            "severity": "medium", "confidence": 0.65,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        control = {"control_id": "V10.4.3", "detection_strategy": "manual_attestation"}
        r = svc._compute_result(control, summary, {}, "scan-1")
        assert r["verdict"] == "fail"

    def test_v10_7_1_silent_reconsent_fails_the_control(self):
        summary = _summary(dynamic_findings=[{
            "control_id": "V10.7.1", "verdict": "fail", "rule_id": "PER_REQUEST_CONSENT_CHECK",
            "note": "a scope-expanded authorization request was silently granted without re-showing consent",
            "severity": "medium", "confidence": 0.6,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        control = {"control_id": "V10.7.1", "detection_strategy": "manual_attestation"}
        r = svc._compute_result(control, summary, {}, "scan-1")
        assert r["verdict"] == "fail"

    def test_v10_4_1_no_scripted_scenario_delegates_to_plain_attestation(self):
        summary = _summary()
        attestations = {"V10.4.1": {"answer": "pass", "attested_by": "alice@example.com", "evidence_url": "https://example.com/review"}}
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_dynamic_finding("V10.4.1", summary, attestations, "scan-1")
        assert r["verdict"] == "pass"


class TestV11TimingSideChannelControlWiredToTheDynamicPath:
    """V11.2.5 has a real built-in probe (padding_oracle_probe.py, fed by
    the dedicated dynamic_timing_probes request shape) rather than riding
    generic dynamic_scenarios — but the hybrid merge path is the same
    mechanism as every other member of HYBRID_ATTESTATION_DYNAMIC_
    ELIGIBLE_CONTROLS."""

    def test_v11_2_5_distinguishable_timing_fails_the_control(self):
        summary = _summary(dynamic_findings=[{
            "control_id": "V11.2.5", "verdict": "fail", "rule_id": "PADDING_ORACLE_CHECK",
            "note": "the two payload variants are distinguishable by response timing",
            "severity": "medium", "confidence": 0.55,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        control = {"control_id": "V11.2.5", "detection_strategy": "manual_attestation"}
        r = svc._compute_result(control, summary, {}, "scan-1")
        assert r["verdict"] == "fail"
        assert r["fail_basis"] == "confirmed"

    def test_v11_2_5_clean_comparison_falls_through_to_attestation(self):
        # A clean timing comparison only proves those two payloads aren't
        # distinguishable this way — never decisive on its own, same as
        # every other member of this set.
        summary = _summary(dynamic_findings=[{
            "control_id": "V11.2.5", "verdict": "pass", "rule_id": "PADDING_ORACLE_CHECK",
            "note": "no statistically significant timing difference observed",
            "severity": "medium", "confidence": 0.35,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_dynamic_finding("V11.2.5", summary, {}, "scan-1")
        assert r["verdict"] == "not_tested"

    def test_v11_2_5_no_scripted_probe_delegates_to_plain_attestation(self):
        summary = _summary()
        attestations = {"V11.2.5": {"answer": "pass", "attested_by": "alice@example.com", "evidence_url": "https://example.com/review"}}
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_dynamic_finding("V11.2.5", summary, attestations, "scan-1")
        assert r["verdict"] == "pass"


class TestV17SignalingFuzzControlWiredToTheDynamicPath:
    """V17.3.2 — the WebSocket signaling fuzz probe (websocket_fuzz_probe.py),
    fed by the dedicated dynamic_signaling_fuzz_probes request shape."""

    def test_crashed_listener_fails_the_control(self):
        summary = _summary(dynamic_findings=[{
            "control_id": "V17.3.2", "verdict": "fail", "rule_id": "SIGNALING_FUZZ",
            "note": "a fresh handshake failed immediately after fuzz payload #4",
            "severity": "high", "confidence": 0.6,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        control = {"control_id": "V17.3.2", "detection_strategy": "manual_attestation"}
        r = svc._compute_result(control, summary, {}, "scan-1")
        assert r["verdict"] == "fail"
        assert r["fail_basis"] == "confirmed"

    def test_clean_run_falls_through_to_attestation(self):
        summary = _summary(dynamic_findings=[{
            "control_id": "V17.3.2", "verdict": "pass", "rule_id": "SIGNALING_FUZZ",
            "note": "handshake succeeded after every payload in the corpus",
            "severity": "high", "confidence": 0.4,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_dynamic_finding("V17.3.2", summary, {}, "scan-1")
        assert r["verdict"] == "not_tested"

    def test_no_scripted_probe_delegates_to_plain_attestation(self):
        summary = _summary()
        attestations = {"V17.3.2": {"answer": "pass", "attested_by": "alice@example.com", "evidence_url": "https://example.com/review"}}
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_dynamic_finding("V17.3.2", summary, attestations, "scan-1")
        assert r["verdict"] == "pass"


class TestV17WebRtcMediaLayerControlsWiredToTheDynamicPath:
    """V17.2.3/V17.2.4/V17.2.5/V17.2.7 — webrtc_probe.py's aiortc-dependent
    probes. All four ride the same generic merge mechanism as every other
    dynamic-hybrid member; what's specific to them is covered in
    test_dast_webrtc_probe.py (the probes themselves) — these tests only
    confirm the ASVS-verdict wiring."""

    @pytest.mark.parametrize("control_id,rule_id", [
        ("V17.2.3", "SRTP_AUTH_CHECK"),
        ("V17.2.4", "RTP_FUZZ"),
        ("V17.2.5", "MEDIA_FLOOD"),
        ("V17.2.7", "MEDIA_FLOOD"),
    ])
    def test_fail_dispatches_through_the_dynamic_hybrid_path(self, control_id, rule_id):
        summary = _summary(dynamic_findings=[{
            "control_id": control_id, "verdict": "fail", "rule_id": rule_id,
            "note": "degradation observed", "severity": "high", "confidence": 0.5,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        control = {"control_id": control_id, "detection_strategy": "manual_attestation"}
        r = svc._compute_result(control, summary, {}, "scan-1")
        assert r["verdict"] == "fail"
        assert r["fail_basis"] == "confirmed"

    @pytest.mark.parametrize("control_id", ["V17.2.3", "V17.2.4", "V17.2.5", "V17.2.7"])
    def test_pass_never_decisive_on_its_own(self, control_id):
        summary = _summary(dynamic_findings=[{
            "control_id": control_id, "verdict": "pass", "rule_id": "X",
            "note": "clean run", "severity": "high", "confidence": 0.4,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_dynamic_finding(control_id, summary, {}, "scan-1")
        assert r["verdict"] == "not_tested"

    @pytest.mark.parametrize("control_id", ["V17.2.3", "V17.2.4", "V17.2.5", "V17.2.7"])
    def test_no_scripted_probe_delegates_to_plain_attestation(self, control_id):
        summary = _summary()
        attestations = {control_id: {"answer": "pass", "attested_by": "alice@example.com", "evidence_url": "https://example.com/review"}}
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_dynamic_finding(control_id, summary, attestations, "scan-1")
        assert r["verdict"] == "pass"


class TestAttestationOrCapabilityFindingMerge:
    """V6.6.1 (SMS/telephony OTP validated phone + genuine alternate method)
    and V6.8.1 (cross-IdP account linking requires proof of ownership) are
    wired to _merge_attestation_or_capability_finding — the CapabilityChecker
    counterpart of the static/dynamic hybrid methods above. CapabilityChecker
    never emits a finding for a capability it found no trace of at all (see
    its own implemented=False handling), so a "fail" read here always means
    the LLM found the relevant code and judged it incorrect — real, specific
    evidence, same as a confirmed static/dynamic hit. A "pass" is never
    decisive on its own."""

    def test_v6_6_1_fail_verdict_fails_the_control(self):
        summary = _summary(capability_findings=[{
            "control_id": "V6.6.1", "verdict": "fail", "file": "sms_otp.py", "line": 14,
            "note": "sends an SMS OTP with no phone-number validation and no alternate method offered",
            "confidence": 0.7,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_capability_finding("V6.6.1", summary, {}, "scan-1")
        assert r["verdict"] == "fail"
        assert r["fail_basis"] == "confirmed"

    def test_v6_6_1_fail_verdict_fails_even_with_a_passing_attestation(self):
        summary = _summary(capability_findings=[{
            "control_id": "V6.6.1", "verdict": "fail", "file": "sms_otp.py", "line": 14,
            "note": "no phone validation before trusting the SMS OTP factor", "confidence": 0.7,
        }])
        attestations = {"V6.6.1": {"answer": "pass", "attested_by": "alice@example.com"}}
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_capability_finding("V6.6.1", summary, attestations, "scan-1")
        assert r["verdict"] == "fail"

    def test_v6_6_1_pass_verdict_never_passes_on_its_own(self):
        summary = _summary(capability_findings=[{
            "control_id": "V6.6.1", "verdict": "pass", "file": "sms_otp.py", "line": 14,
            "note": "phone validated before use, WebAuthn offered as an alternate factor",
            "confidence": 0.7,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_capability_finding("V6.6.1", summary, {}, "scan-1")
        assert r["verdict"] == "not_tested"

    def test_v6_8_1_fail_verdict_fails_the_control(self):
        summary = _summary(capability_findings=[{
            "control_id": "V6.8.1", "verdict": "fail", "file": "sso.py", "line": 40,
            "note": "accounts from different IdPs are linked purely on matching email string, "
                    "no proof-of-ownership step", "confidence": 0.65,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        control = {"control_id": "V6.8.1", "detection_strategy": "manual_attestation"}
        r = svc._compute_result(control, summary, {}, "scan-1")
        assert r["verdict"] == "fail"

    def test_no_capability_finding_delegates_to_plain_attestation(self):
        summary = _summary()
        attestations = {"V6.8.1": {"answer": "pass", "attested_by": "alice@example.com", "evidence_url": "https://example.com/review"}}
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_capability_finding("V6.8.1", summary, attestations, "scan-1")
        assert r["verdict"] == "pass"

    def test_no_capability_finding_and_no_attestation_is_not_tested(self):
        summary = _summary()
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_capability_finding("V6.6.1", summary, {}, "scan-1")
        assert r["verdict"] == "not_tested"

    def test_v7_6_2_silent_auto_login_fail_dispatches_through_hybrid_path(self):
        summary = _summary(capability_findings=[{
            "control_id": "V7.6.2", "verdict": "fail", "file": "oauth_callback.py", "line": 22,
            "note": "the OAuth callback creates a session immediately on IdP redirect, no "
                    "consent-confirmation step in between", "confidence": 0.65,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        control = {"control_id": "V7.6.2", "detection_strategy": "manual_attestation"}
        r = svc._compute_result(control, summary, {}, "scan-1")
        assert r["verdict"] == "fail"
        assert r["fail_basis"] == "confirmed"

    def test_v7_6_2_pass_verdict_never_passes_on_its_own(self):
        summary = _summary(capability_findings=[{
            "control_id": "V7.6.2", "verdict": "pass", "file": "oauth_callback.py", "line": 22,
            "note": "a distinct consent screen is shown before session creation", "confidence": 0.65,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_capability_finding("V7.6.2", summary, {}, "scan-1")
        assert r["verdict"] == "not_tested"

    def test_v10_7_2_generic_consent_screen_fails_the_control(self):
        summary = _summary(capability_findings=[{
            "control_id": "V10.7.2", "verdict": "fail", "file": "consent.html", "line": 5,
            "note": "the consent template shows a static generic message, never the actual requested scopes",
            "confidence": 0.6,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        control = {"control_id": "V10.7.2", "detection_strategy": "manual_attestation"}
        r = svc._compute_result(control, summary, {}, "scan-1")
        assert r["verdict"] == "fail"

    def test_v10_7_2_pass_verdict_never_passes_on_its_own(self):
        summary = _summary(capability_findings=[{
            "control_id": "V10.7.2", "verdict": "pass", "file": "consent.html", "line": 5,
            "note": "renders the actual requested scope list", "confidence": 0.6,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_capability_finding("V10.7.2", summary, {}, "scan-1")
        assert r["verdict"] == "not_tested"

    def test_v11_2_2_hardcoded_algorithm_choices_fails_the_control(self):
        summary = _summary(capability_findings=[{
            "control_id": "V11.2.2", "verdict": "fail", "file": "crypto_utils.py", "line": 18,
            "note": "algorithm names are hardcoded individually at each call site, no central "
                    "crypto abstraction", "confidence": 0.55,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        control = {"control_id": "V11.2.2", "detection_strategy": "manual_attestation"}
        r = svc._compute_result(control, summary, {}, "scan-1")
        assert r["verdict"] == "fail"

    def test_v11_2_2_pass_verdict_never_passes_on_its_own(self):
        summary = _summary(capability_findings=[{
            "control_id": "V11.2.2", "verdict": "pass", "file": "crypto_config.py", "line": 4,
            "note": "algorithm names are read from a single central config module", "confidence": 0.55,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_capability_finding("V11.2.2", summary, {}, "scan-1")
        assert r["verdict"] == "not_tested"

    def test_v15_4_4_unbounded_pool_fails_the_control(self):
        summary = _summary(capability_findings=[{
            "control_id": "V15.4.4", "verdict": "fail", "file": "worker.py", "line": 9,
            "note": "ThreadPoolExecutor() created with no max_workers bound", "confidence": 0.5,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        control = {"control_id": "V15.4.4", "detection_strategy": "manual_attestation"}
        r = svc._compute_result(control, summary, {}, "scan-1")
        assert r["verdict"] == "fail"

    def test_v15_4_4_pass_verdict_never_passes_on_its_own(self):
        # Bounded is necessary but not sufficient — fair scheduling and
        # actual behavior under mixed load still need a human/load test.
        summary = _summary(capability_findings=[{
            "control_id": "V15.4.4", "verdict": "pass", "file": "worker.py", "line": 9,
            "note": "ThreadPoolExecutor(max_workers=10)", "confidence": 0.5,
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_capability_finding("V15.4.4", summary, {}, "scan-1")
        assert r["verdict"] == "not_tested"


class TestAttestationOrDependencyFindingMerge:
    """V17.2.6 — wired to _merge_attestation_or_dependency_finding, the
    fourth and last hybrid evidence source: summary["dependency_findings"],
    the same generic per-dependency OSV.dev results V15.2.1 already reads.
    A match requires BOTH a DTLS/ClientHello handshake-context term and a
    race-condition term in the same finding's text — either alone is a
    guaranteed false-match source across an unrelated CVE catalog."""

    def test_matching_advisory_fails_the_control(self):
        summary = _summary(dependency_findings=[{
            "package": "some-webrtc-stack", "version": "1.2.0", "ecosystem": "PyPI",
            "vuln_id": "GHSA-xxxx-yyyy-zzzz", "severity": "HIGH",
            "summary": "A race condition in DTLS ClientHello handling allows an attacker to "
                       "bypass the handshake state machine.",
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        control = {"control_id": "V17.2.6", "detection_strategy": "manual_attestation"}
        r = svc._compute_result(control, summary, {}, "scan-1")
        assert r["verdict"] == "fail"
        assert r["fail_basis"] == "confirmed"

    def test_race_condition_without_dtls_context_does_not_match(self):
        # A completely unrelated race condition (e.g. a filesystem TOCTOU
        # bug) must not false-positive this control.
        summary = _summary(dependency_findings=[{
            "package": "some-unrelated-lib", "version": "2.0.0", "ecosystem": "PyPI",
            "vuln_id": "CVE-2024-00000", "severity": "MODERATE",
            "summary": "A race condition in temp file creation allows local privilege escalation.",
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_dependency_finding("V17.2.6", summary, {}, "scan-1")
        assert r["verdict"] == "not_tested"

    def test_dtls_finding_without_race_context_does_not_match(self):
        # A DTLS memory-safety bug with nothing to do with a handshake race.
        summary = _summary(dependency_findings=[{
            "package": "some-dtls-lib", "version": "0.9.0", "ecosystem": "PyPI",
            "vuln_id": "CVE-2024-11111", "severity": "HIGH",
            "summary": "A buffer overflow in DTLS record parsing allows remote code execution.",
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_dependency_finding("V17.2.6", summary, {}, "scan-1")
        assert r["verdict"] == "not_tested"

    def test_no_dependency_findings_delegates_to_plain_attestation(self):
        summary = _summary()
        attestations = {"V17.2.6": {"answer": "pass", "attested_by": "alice@example.com", "evidence_url": "https://example.com/review"}}
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_dependency_finding("V17.2.6", summary, attestations, "scan-1")
        assert r["verdict"] == "pass"

    def test_matching_advisory_fails_even_with_a_passing_attestation(self):
        summary = _summary(dependency_findings=[{
            "package": "some-webrtc-stack", "version": "1.2.0", "ecosystem": "PyPI",
            "vuln_id": "GHSA-xxxx-yyyy-zzzz", "severity": "HIGH",
            "summary": "DTLS ClientHello race condition.",
        }])
        attestations = {"V17.2.6": {"answer": "pass", "attested_by": "alice@example.com"}}
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_attestation_or_dependency_finding("V17.2.6", summary, attestations, "scan-1")
        assert r["verdict"] == "fail"


class TestHybridSetMembership:
    """Every control_id this session's work added across V6/V7/V8/V9(none)/
    V10/V11/V15/V17 is actually a member of its intended hybrid set — a
    regression guard against a control being documented in a comment but
    never actually landing in the set literal (exactly the class of bug
    this whole thread of work has been fixing for OTHER modules)."""

    def test_static_hybrid_membership(self):
        assert {"V1.1.1", "V1.5.3", "V2.3.3", "V6.3.4", "V10.3.2"} <= HYBRID_ATTESTATION_ELIGIBLE_CONTROLS

    def test_dynamic_hybrid_membership(self):
        assert {
            "V2.3.1", "V2.3.4", "V6.4.3", "V6.6.2", "V6.8.3",
            "V7.4.3", "V7.4.4", "V8.3.2", "V8.3.3", "V11.2.5",
            "V17.2.3", "V17.2.4", "V17.2.5", "V17.2.7", "V17.3.2",
        } <= HYBRID_ATTESTATION_DYNAMIC_ELIGIBLE_CONTROLS

    def test_capability_hybrid_membership(self):
        assert {
            "V6.6.1", "V6.8.1", "V7.6.2", "V10.7.2", "V11.2.2", "V15.4.4",
        } <= HYBRID_ATTESTATION_CAPABILITY_ELIGIBLE_CONTROLS

    def test_dependency_hybrid_membership(self):
        assert {"V17.2.6"} <= HYBRID_ATTESTATION_DEPENDENCY_ELIGIBLE_CONTROLS


class TestConfigOrDynamicMerge:
    """
    V13.4.6 (backend version info not exposed) and V3.4.1 (HSTS header) are both
    wired to _merge_config_or_dynamic: evidence can come from a static config
    reading (config_inspection — nginx server_tokens / hsts directives) or a
    live probe (dynamic_probe — Server/X-Powered-By header / live HSTS header)
    — a fail from either source wins, consistent with this module's
    conservative-by-default policy.
    """

    def test_passing_config_alone_passes(self):
        summary = _summary(config_findings=[
            {"control_id": "V13.4.6", "verdict": "pass", "file": "nginx.conf", "line": 6,
             "note": "server_tokens off directive found", "confidence": 0.7},
        ])
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_config_or_dynamic("V13.4.6", summary, "scan-1")
        assert r["verdict"] == "pass"

    def test_passing_probe_alone_passes(self):
        summary = _summary(dynamic_probe_findings=[
            {"control_id": "V13.4.6", "verdict": "pass",
             "note": "No version-revealing Server/X-Powered-By header observed", "confidence": 0.6},
        ])
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_config_or_dynamic("V13.4.6", summary, "scan-1")
        assert r["verdict"] == "pass"

    def test_passing_config_with_failing_probe_fails(self):
        # The important precedence case: a live header leak must NOT be masked
        # by a clean static config reading — fail from either source wins.
        summary = _summary(
            config_findings=[
                {"control_id": "V13.4.6", "verdict": "pass", "file": "nginx.conf", "line": 6,
                 "note": "server_tokens off directive found", "confidence": 0.7},
            ],
            dynamic_probe_findings=[
                {"control_id": "V13.4.6", "verdict": "fail",
                 "note": "Live response discloses backend component version info — Server: nginx/1.18.0",
                 "confidence": 0.75},
            ],
        )
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_config_or_dynamic("V13.4.6", summary, "scan-1")
        assert r["verdict"] == "fail"

    def test_no_evidence_at_all_is_not_tested(self):
        summary = _summary()
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_config_or_dynamic("V13.4.6", summary, "scan-1")
        assert r["verdict"] == "not_tested"

    @pytest.mark.asyncio
    async def test_v3_4_1_dispatches_through_compute_result_not_plain_config(self):
        # Regression: V3.4.1 used to go through plain _merge_config, which
        # ignores dynamic_probe_findings entirely — DynamicProbe's
        # _check_hsts_header result for V3.4.1 was silently dead for scans
        # with no config file (e.g. a scan_type="dynamic" run with no repo
        # at all). It must now resolve via _merge_config_or_dynamic, same as
        # V13.4.6, so a live-probe-only result is enough.
        summary = _summary(dynamic_probe_findings=[
            {"control_id": "V3.4.1", "verdict": "pass", "note": "Live HSTS max-age=31536000", "confidence": 0.85},
        ])
        svc = ASVSService(FakeDB(scan_summary=summary))
        results = await svc.build_results_for_scan("scan-1")
        assert results["V3.4.1"]["verdict"] == "pass"

    def test_v3_4_1_passing_config_with_failing_probe_fails(self):
        summary = _summary(
            config_findings=[
                {"control_id": "V3.4.1", "verdict": "pass", "file": "nginx.conf", "line": 2,
                 "note": "add_header Strict-Transport-Security found", "confidence": 0.7},
            ],
            dynamic_probe_findings=[
                {"control_id": "V3.4.1", "verdict": "fail",
                 "note": "No Strict-Transport-Security header on the live response", "confidence": 0.8},
            ],
        )
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_config_or_dynamic("V3.4.1", summary, "scan-1")
        assert r["verdict"] == "fail"


class TestDependencyScanMerge:
    @pytest.mark.asyncio
    async def test_uses_dependency_control_result_directly(self):
        summary = _summary(
            dependency_findings=[{"package": "flask", "version": "0.12", "vuln_id": "GHSA-x", "severity": "HIGH"}],
            dependency_control_result={"control_id": "V15.2.1", "verdict": "fail", "note": "breached SLA"},
        )
        svc = ASVSService(FakeDB(scan_summary=summary))
        results = await svc.build_results_for_scan("scan-1")
        assert results["V15.2.1"]["verdict"] == "fail"
        assert "flask@0.12" in results["V15.2.1"]["evidence"][0]["note"]

    @pytest.mark.asyncio
    async def test_no_result_not_tested(self):
        svc = ASVSService(FakeDB(scan_summary=_summary()))
        results = await svc.build_results_for_scan("scan-1")
        assert results["V15.2.1"]["verdict"] == "not_tested"

    @pytest.mark.asyncio
    async def test_pass_with_no_findings_has_a_reason(self):
        # Regression: a clean dependency scan (verdict=pass, no vulnerable
        # packages -> evidence=[]) used to leave `reason` None — same class
        # of bug as the static "pass by absence" case.
        summary = _summary(
            dependency_findings=[],
            dependency_control_result={
                "control_id": "V15.2.1", "verdict": "pass",
                "note": "No known-vulnerable dependencies found against OSV.dev.",
            },
        )
        svc = ASVSService(FakeDB(scan_summary=summary))
        results = await svc.build_results_for_scan("scan-1")
        r = results["V15.2.1"]
        assert r["verdict"] == "pass"
        assert r["evidence"] == []
        assert r["reason"] == "No known-vulnerable dependencies found against OSV.dev."


class TestDynamicProbeMerge:
    @pytest.mark.asyncio
    async def test_takes_probe_finding_directly(self):
        summary = _summary(dynamic_probe_findings=[
            {"control_id": "V12.1.1", "verdict": "pass", "note": "TLS 1.3", "confidence": 0.85},
        ])
        svc = ASVSService(FakeDB(scan_summary=summary))
        results = await svc.build_results_for_scan("scan-1")
        assert results["V12.1.1"]["verdict"] == "pass"

    @pytest.mark.asyncio
    async def test_no_target_url_not_tested(self):
        svc = ASVSService(FakeDB(scan_summary=_summary()))
        results = await svc.build_results_for_scan("scan-1")
        assert results["V12.1.1"]["verdict"] == "not_tested"


class TestManualAttestationMerge:
    @pytest.mark.asyncio
    async def test_no_attestation_not_tested(self):
        svc = ASVSService(FakeDB(scan_summary=_summary()))
        results = await svc.build_results_for_scan("scan-1")
        assert results["V2.1.1"]["verdict"] == "not_tested"

    @pytest.mark.asyncio
    async def test_attestation_answer_used(self):
        attestations = [{
            "control_id": "V2.1.1", "answer": "pass", "evidence_url": "doc.pdf",
            "attested_by": "alice", "timestamp": "2026-01-01T00:00:00Z",
        }]
        svc = ASVSService(FakeDB(scan_summary=_summary(), attestations=attestations))
        results = await svc.build_results_for_scan("scan-1")
        r = results["V2.1.1"]
        assert r["verdict"] == "pass"
        assert r["reviewed_by"] == "alice"
        assert r["evidence"][0]["note"] == "doc.pdf"

    @pytest.mark.asyncio
    async def test_pass_without_evidence_url_still_has_a_reason(self):
        # Regression: an attester answering "pass" with no evidence_url
        # (a legitimate, common case — not every attestation has a doc to
        # link) used to leave both `evidence` and `reason` empty, looking
        # identical to "nobody ever reviewed this".
        attestations = [{
            "control_id": "V2.1.1", "answer": "pass",
            "attested_by": "bob", "timestamp": "2026-01-01T00:00:00Z",
        }]
        svc = ASVSService(FakeDB(scan_summary=_summary(), attestations=attestations))
        results = await svc.build_results_for_scan("scan-1")
        r = results["V2.1.1"]
        assert r["verdict"] == "pass"
        assert r["evidence"] == []
        assert r["reason"]
        assert "bob" in r["reason"]


class TestComplianceSummaryAggregation:
    @pytest.mark.asyncio
    async def test_all_70_controls_present(self):
        svc = ASVSService(FakeDB(scan_summary=_summary()))
        summary = await svc.get_compliance_summary("scan-1")
        assert len(summary["results"]) == 70

    @pytest.mark.asyncio
    async def test_fifteen_chapters(self):
        svc = ASVSService(FakeDB(scan_summary=_summary()))
        summary = await svc.get_compliance_summary("scan-1")
        assert len(summary["chapters"]) == 15

    @pytest.mark.asyncio
    async def test_level_completion_matches_l1_only_catalog(self):
        # Every control in the current catalog is L1, so L1/L2/L3 totals are identical.
        svc = ASVSService(FakeDB(scan_summary=_summary()))
        summary = await svc.get_compliance_summary("scan-1")
        assert summary["levels"]["L1"]["total"] == 70
        assert summary["levels"]["L1"]["total"] == summary["levels"]["L3"]["total"]

    @pytest.mark.asyncio
    async def test_chapter_counts_sum_to_control_count(self):
        svc = ASVSService(FakeDB(scan_summary=_summary()))
        summary = await svc.get_compliance_summary("scan-1")
        for ch in summary["chapters"]:
            assert sum(ch["counts"].values()) == ch["control_count"]


class TestPassBasis:
    """`pass_basis` distinguishes a *confirmed* pass (real positive
    evidence — a marker match, a passing config/probe check, a human
    attestation) from a `no_findings` pass (a rule actively searched for
    the bad pattern everywhere and matched nothing — real signal, but not
    the same confidence). Non-pass verdicts always carry pass_basis=None.
    Compliance % is unaffected either way — see session discussion: a
    static scanner can never produce positive proof of a vulnerability's
    absence, so requiring "confirmed" evidence for every static_code
    control would make 100% compliance structurally unreachable."""

    @pytest.mark.asyncio
    async def test_static_pass_by_absence_is_no_findings(self):
        svc = ASVSService(FakeDB(scan_summary=_summary()))
        results = await svc.build_results_for_scan("scan-1")
        assert results["V1.2.4"]["verdict"] == "pass"
        assert results["V1.2.4"]["pass_basis"] == "no_findings"

    @pytest.mark.asyncio
    async def test_static_compliant_marker_match_is_confirmed(self):
        summary = _summary(vulnerabilities=[{
            "type": "Password Change Capability Marker", "asvs_controls": ["V6.2.2"],
            "asvs_finding_polarity": "compliant", "confidence": 0.5,
            "location": {"file": "auth.py", "start_line": 40},
            "analysis": {"llm_classification": {}},
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        results = await svc.build_results_for_scan("scan-1")
        assert results["V6.2.2"]["pass_basis"] == "confirmed"

    @pytest.mark.asyncio
    async def test_fail_and_manual_review_have_no_pass_basis(self):
        summary = _summary(vulnerabilities=[{
            "type": "JWT issue", "asvs_controls": ["V9.2.1"], "confidence": 0.9,
            "location": {"file": "auth.py", "start_line": 5},
            "analysis": {"llm_classification": {"explanation": "verify_exp disabled"}},
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        results = await svc.build_results_for_scan("scan-1")
        assert results["V9.2.1"]["verdict"] == "fail"
        assert results["V9.2.1"]["pass_basis"] is None

    @pytest.mark.asyncio
    async def test_not_tested_has_no_pass_basis(self):
        svc = ASVSService(FakeDB(scan_summary=_summary()))
        results = await svc.build_results_for_scan("scan-1")
        assert results["V6.2.2"]["verdict"] == "not_tested"
        assert results["V6.2.2"]["pass_basis"] is None

    @pytest.mark.asyncio
    async def test_config_inspection_pass_is_confirmed(self):
        summary = _summary(config_findings=[
            {"control_id": "V5.2.1", "verdict": "pass", "file": "nginx.conf", "line": 3, "note": "ok", "confidence": 0.85},
        ])
        svc = ASVSService(FakeDB(scan_summary=summary))
        results = await svc.build_results_for_scan("scan-1")
        assert results["V5.2.1"]["pass_basis"] == "confirmed"

    def test_config_or_compliant_static_pass_is_confirmed(self):
        summary = _summary(config_findings=[
            {"control_id": "V3.5.8", "verdict": "pass", "file": "nginx.conf", "line": 4,
             "note": "Cross-Origin-Resource-Policy: same-origin", "confidence": 0.75},
        ])
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_config_or_compliant_static("V3.5.8", summary, "scan-1")
        assert r["pass_basis"] == "confirmed"

    def test_config_or_dynamic_pass_is_confirmed(self):
        summary = _summary(dynamic_probe_findings=[
            {"control_id": "V13.4.6", "verdict": "pass", "note": "server_tokens off", "confidence": 0.8},
        ])
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_config_or_dynamic("V13.4.6", summary, "scan-1")
        assert r["pass_basis"] == "confirmed"

    @pytest.mark.asyncio
    async def test_dependency_pass_with_no_vulnerable_deps_is_no_findings(self):
        summary = _summary(
            dependency_findings=[],
            dependency_control_result={
                "control_id": "V15.2.1", "verdict": "pass",
                "note": "No known-vulnerable dependencies found against OSV.dev.",
            },
        )
        svc = ASVSService(FakeDB(scan_summary=summary))
        results = await svc.build_results_for_scan("scan-1")
        assert results["V15.2.1"]["pass_basis"] == "no_findings"

    @pytest.mark.asyncio
    async def test_dependency_pass_with_findings_within_sla_is_confirmed(self):
        # Vulnerable dependencies WERE found, but all are still within their
        # remediation SLA window — a real, specific finding, not an absence.
        summary = _summary(
            dependency_findings=[{"package": "flask", "version": "0.12", "vuln_id": "GHSA-x", "severity": "LOW"}],
            dependency_control_result={
                "control_id": "V15.2.1", "verdict": "pass",
                "note": "1 vulnerable dependency found, all still within SLA.",
            },
        )
        svc = ASVSService(FakeDB(scan_summary=summary))
        results = await svc.build_results_for_scan("scan-1")
        assert results["V15.2.1"]["evidence"]
        assert results["V15.2.1"]["pass_basis"] == "confirmed"

    @pytest.mark.asyncio
    async def test_dynamic_probe_pass_is_confirmed(self):
        summary = _summary(dynamic_probe_findings=[
            {"control_id": "V12.1.1", "verdict": "pass", "note": "TLS 1.3", "confidence": 0.85},
        ])
        svc = ASVSService(FakeDB(scan_summary=summary))
        results = await svc.build_results_for_scan("scan-1")
        assert results["V12.1.1"]["pass_basis"] == "confirmed"

    @pytest.mark.asyncio
    async def test_attestation_pass_is_confirmed_even_without_evidence_url(self):
        attestations = [{
            "control_id": "V2.1.1", "answer": "pass",
            "attested_by": "bob", "timestamp": "2026-01-01T00:00:00Z",
        }]
        svc = ASVSService(FakeDB(scan_summary=_summary(), attestations=attestations))
        results = await svc.build_results_for_scan("scan-1")
        assert results["V2.1.1"]["pass_basis"] == "confirmed"

    @pytest.mark.asyncio
    async def test_attestation_fail_has_no_pass_basis(self):
        attestations = [{
            "control_id": "V2.1.1", "answer": "fail",
            "attested_by": "bob", "timestamp": "2026-01-01T00:00:00Z",
        }]
        svc = ASVSService(FakeDB(scan_summary=_summary(), attestations=attestations))
        results = await svc.build_results_for_scan("scan-1")
        assert results["V2.1.1"]["pass_basis"] is None


class TestFailBasis:
    """`fail_basis` is the fail-side mirror of `pass_basis`: "confirmed"
    means real, deterministic evidence backs the verdict (a config/dependency/
    probe match, an LLM-reviewed static hit, a human attestation);
    "unconfirmed" is the one genuinely weak case — a static pattern matched
    but the LLM never got to review it (rate-limited/unavailable), so it's
    surfaced as manual_review rather than a confident fail. Pass verdicts
    always carry fail_basis=None."""

    @pytest.mark.asyncio
    async def test_llm_confirmed_static_fail_is_confirmed(self):
        summary = _summary(vulnerabilities=[{
            "type": "JWT issue", "asvs_controls": ["V9.2.1"], "confidence": 0.9,
            "location": {"file": "auth.py", "start_line": 5},
            "analysis": {"llm_classification": {"explanation": "verify_exp disabled"}},
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        results = await svc.build_results_for_scan("scan-1")
        r = results["V9.2.1"]
        assert r["verdict"] == "fail"
        assert r["fail_basis"] == "confirmed"

    @pytest.mark.asyncio
    async def test_llm_unavailable_static_hit_is_unconfirmed(self):
        # The one genuinely weak-evidence case: a static pattern matched but
        # the LLM never confirmed it (rate-limited/unavailable) — surfaces
        # as manual_review, and fail_basis says exactly why.
        summary = _summary(vulnerabilities=[{
            "type": "SQL Injection", "asvs_controls": ["V1.2.4"], "confidence": 0.65,
            "location": {"file": "database.js", "start_line": 17},
            "analysis": {"llm_classification": {"explanation": "LLM unavailable — pattern-based detection only"}},
        }])
        svc = ASVSService(FakeDB(scan_summary=summary))
        results = await svc.build_results_for_scan("scan-1")
        r = results["V1.2.4"]
        assert r["verdict"] == "manual_review"
        assert r["fail_basis"] == "unconfirmed"

    @pytest.mark.asyncio
    async def test_config_fail_is_confirmed(self):
        summary = _summary(config_findings=[
            {"control_id": "V3.4.1", "verdict": "fail", "file": "a.conf", "line": 1, "note": "bad", "confidence": 0.8},
        ])
        svc = ASVSService(FakeDB(scan_summary=summary))
        results = await svc.build_results_for_scan("scan-1")
        assert results["V3.4.1"]["fail_basis"] == "confirmed"

    def test_config_or_compliant_static_fail_is_confirmed(self):
        summary = _summary(config_findings=[
            {"control_id": "V3.5.8", "verdict": "fail", "file": "nginx.conf", "line": 4,
             "note": "no CORP header", "confidence": 0.5},
        ])
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_config_or_compliant_static("V3.5.8", summary, "scan-1")
        assert r["fail_basis"] == "confirmed"

    def test_config_or_dynamic_fail_is_confirmed(self):
        summary = _summary(dynamic_probe_findings=[
            {"control_id": "V13.4.6", "verdict": "fail", "note": "server_tokens on", "confidence": 0.7},
        ])
        svc = ASVSService(FakeDB(scan_summary=summary))
        r = svc._merge_config_or_dynamic("V13.4.6", summary, "scan-1")
        assert r["fail_basis"] == "confirmed"

    @pytest.mark.asyncio
    async def test_dependency_manual_review_within_sla_is_confirmed(self):
        # The finding itself (a real CVE match) is certain — manual_review
        # here is a policy question (is being within SLA acceptable), not
        # an evidence-confidence question, so fail_basis stays "confirmed".
        summary = _summary(
            dependency_findings=[{"package": "flask", "version": "0.12", "vuln_id": "GHSA-x", "severity": "LOW"}],
            dependency_control_result={
                "control_id": "V15.2.1", "verdict": "manual_review",
                "note": "1 vulnerable dependency found, all still within SLA.",
            },
        )
        svc = ASVSService(FakeDB(scan_summary=summary))
        results = await svc.build_results_for_scan("scan-1")
        assert results["V15.2.1"]["fail_basis"] == "confirmed"

    @pytest.mark.asyncio
    async def test_dynamic_probe_fail_is_confirmed(self):
        summary = _summary(dynamic_probe_findings=[
            {"control_id": "V12.1.1", "verdict": "fail", "note": "TLS 1.0 accepted", "confidence": 0.9},
        ])
        svc = ASVSService(FakeDB(scan_summary=summary))
        results = await svc.build_results_for_scan("scan-1")
        assert results["V12.1.1"]["fail_basis"] == "confirmed"

    @pytest.mark.asyncio
    async def test_attestation_fail_is_confirmed(self):
        attestations = [{
            "control_id": "V2.1.1", "answer": "fail",
            "attested_by": "bob", "timestamp": "2026-01-01T00:00:00Z",
        }]
        svc = ASVSService(FakeDB(scan_summary=_summary(), attestations=attestations))
        results = await svc.build_results_for_scan("scan-1")
        assert results["V2.1.1"]["fail_basis"] == "confirmed"

    @pytest.mark.asyncio
    async def test_pass_by_absence_has_no_fail_basis(self):
        svc = ASVSService(FakeDB(scan_summary=_summary()))
        results = await svc.build_results_for_scan("scan-1")
        assert results["V1.2.4"]["verdict"] == "pass"
        assert results["V1.2.4"]["fail_basis"] is None

    @pytest.mark.asyncio
    async def test_not_tested_has_no_fail_basis(self):
        svc = ASVSService(FakeDB(scan_summary=_summary()))
        results = await svc.build_results_for_scan("scan-1")
        assert results["V6.2.2"]["verdict"] == "not_tested"
        assert results["V6.2.2"]["fail_basis"] is None


class TestNotTestedHelper:
    def test_shape(self):
        r = _not_tested("V1.1.1", "scan-1")
        assert r["verdict"] == "not_tested"
        assert r["control_id"] == "V1.1.1"
        assert r["evidence"] == []


class TestPdfTextEscaping:
    """Regression: reportlab's Paragraph() runs its content through a mini
    XML/markup parser (that's how the <b>/<br/>/<font> tags this module
    writes itself get rendered) — any *unescaped* '<' in dynamic text blows
    up the whole PDF export with "parse ended with N unclosed tags", not
    just garbles that one paragraph. Real trigger: V17-something's own
    description literally reads "...such as <script> and
    <foreignObject>...". _pdf_text() is the fix; this locks it in."""

    def test_escapes_angle_brackets_and_ampersand(self):
        from app.services.asvs_service import _pdf_text
        assert _pdf_text("remove <script> and <foreignObject> tags") == (
            "remove &lt;script&gt; and &lt;foreignObject&gt; tags"
        )
        assert _pdf_text("Q&A: <b>bold</b>?") == "Q&amp;A: &lt;b&gt;bold&lt;/b&gt;?"

    def test_none_and_empty_are_safe(self):
        from app.services.asvs_service import _pdf_text
        assert _pdf_text(None) == ""
        assert _pdf_text("") == ""

    def test_plain_text_passes_through_unchanged(self):
        from app.services.asvs_service import _pdf_text
        assert _pdf_text("Verify that TLS is enforced.") == "Verify that TLS is enforced."


class TestExportPdf:
    SCRIPT_CONTROL = {
        "control_id": "V17.9.9", "chapter_id": "V17", "chapter": "V17: WebRTC",
        "section_id": "17.9", "section_name": "Sanitization", "level": "L1",
        "description": "Verify that user-supplied SVG images are sanitized to remove "
                        "scripting elements (such as <script> and <foreignObject>) before "
                        "being stored, rendered, or served.",
        "detection_strategy": "static_code", "check_ref": None,
    }

    @staticmethod
    def _catalog_with_script_control():
        # A single-control catalog is enough to exercise export_pdf end to
        # end without pulling in the full 70-control L1 fixture.
        return [TestExportPdf.SCRIPT_CONTROL]

    @pytest.mark.asyncio
    async def test_export_succeeds_with_unescaped_angle_brackets_in_catalog(self, monkeypatch):
        # Forces the deterministic non-LLM summary path — no network calls,
        # no flakiness tied to whether real LLM credentials are configured
        # in this environment.
        fake_pool = MagicMock()
        fake_pool.is_available = False
        monkeypatch.setattr("app.services.asvs_service._get_report_pool", lambda: fake_pool)

        db = FakeDB(scan_summary=_summary())
        db.asvs_controls = FakeCollection(self._catalog_with_script_control())
        svc = ASVSService(db)

        pdf_bytes = await svc.export_pdf("scan-1", repo_name="demo-repo", branch="main")

        assert pdf_bytes is not None
        assert pdf_bytes.startswith(b"%PDF")

    @pytest.mark.asyncio
    async def test_export_succeeds_with_special_characters_in_finding_evidence(self, monkeypatch):
        # A failing control's evidence note (llm_classification.explanation,
        # surfaced verbatim as the finding's evidence "note") is exactly the
        # kind of attacker-influenced/free-form text (e.g. a captured XSS
        # payload) that must never be trusted as literal reportlab markup.
        fake_pool = MagicMock()
        fake_pool.is_available = False
        monkeypatch.setattr("app.services.asvs_service._get_report_pool", lambda: fake_pool)

        summary = _summary(vulnerabilities=[{
            "type": "XSS", "asvs_controls": ["V17.9.9"], "confidence": 0.9,
            "location": {"file": "app.py", "start_line": 1},
            "analysis": {"llm_classification": {
                "explanation": "reflected payload: <script>alert(1)</script> & more",
            }},
        }])
        db = FakeDB(scan_summary=summary)
        db.asvs_controls = FakeCollection(self._catalog_with_script_control())
        svc = ASVSService(db)

        pdf_bytes = await svc.export_pdf("scan-1")

        assert pdf_bytes is not None
        assert pdf_bytes.startswith(b"%PDF")
