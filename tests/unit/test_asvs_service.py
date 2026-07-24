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

from app.services.asvs_service import ASVSService, _level_includes, _not_tested

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
    async def test_no_finding_on_vulnerable_polarity_rule_passes(self):
        # V1.2.4 (SQL injection) is a vulnerable-polarity rule with full coverage;
        # no matching finding means the rule ran across the repo and found nothing.
        svc = ASVSService(FakeDB(scan_summary=_summary()))
        results = await svc.build_results_for_scan("scan-1")
        assert results["V1.2.4"]["verdict"] == "pass"

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


class TestNotTestedHelper:
    def test_shape(self):
        r = _not_tested("V1.1.1", "scan-1")
        assert r["verdict"] == "not_tested"
        assert r["control_id"] == "V1.1.1"
        assert r["evidence"] == []
