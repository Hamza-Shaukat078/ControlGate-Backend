"""
Section G — full-pipeline integration test against curated sample apps.

Runs the real SemanticPipeline (taint engine + rule catalog + config
inspector + dependency scanner) against two hand-built fixture repos:
tests/fixtures/asvs_sample_apps/{vulnerable,clean}/ — then merges the
result through ASVSService exactly as a real scan would. This is the one
test file that exercises the whole detection stack together on a realistic
multi-file app, rather than isolated rules/snippets — it's what caught three
real false-positive bugs during Section G (INSECURE_COOKIE matching a bare
`def set_cookie():`, JWT_WEAK_SECRET matching the `algorithm="HS256"`
keyword argument, and UNRESTRICTED_FILE_UPLOAD firing on any
`request.files` access regardless of validation) that no isolated unit test
had surfaced.

Two known, accepted (not fixed) false-positive classes remain and are
asserted as "expected noise" below rather than silently ignored:
  - V5.3.2 (SSRF/path-traversal control): the inherited SSRF rule doesn't
    distinguish server-side fetches from client-side browser fetch() calls.
  - V8.2.1 (admin route access control): ADMIN_ROUTE_UNPROTECTED is a pure
    "does the route path contain /admin" regex with no ability to recognize
    an in-function permission guard — a real gap in a pre-existing rule,
    not something introduced here. Flagged, not silently masked.

Uses the same hand-rolled async-compatible FakeDB as test_asvs_service.py
(see that file's docstring for why — this repo's mongomock version doesn't
support `await db.x.find_one(...)`).
"""
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from semantic_engine.pipeline import SemanticPipeline, PipelineConfig
from app.services.asvs_service import ASVSService

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "asvs_sample_apps"
CATALOG = json.loads(
    (Path(__file__).resolve().parents[2] / "app" / "data" / "asvs_l1_controls.json").read_text(encoding="utf-8")
)

# Controls verified (by hand, in Section G) to go fail(vulnerable) -> pass(clean).
# A representative subset, not the full 36 — enough to catch a real regression
# without making this test brittle to every future rule tweak.
EXPECTED_FAIL_TO_PASS = [
    "V1.2.1", "V1.2.4", "V1.2.5", "V1.3.2", "V1.5.1",
    "V11.3.1", "V11.4.1", "V3.3.1", "V3.4.1", "V3.4.2",
    "V4.4.1", "V5.2.1", "V5.2.2", "V6.2.1", "V6.4.2",
    "V7.2.1", "V9.1.1", "V9.1.2", "V9.2.1",
]

# Known, accepted false-positive classes — pre-existing rule limitations
# (client/server fetch ambiguity, no guard-clause awareness) documented
# above rather than fixed in this pass. If either of these starts passing
# cleanly in the clean fixture, that's a genuine improvement — update this
# list rather than treating it as a failure.
KNOWN_FALSE_POSITIVES_IN_CLEAN = {"V5.3.2", "V8.2.1"}


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
    def __init__(self, scan_summary):
        self.asvs_controls = FakeCollection(CATALOG)
        self.attestations = FakeCollection([])
        self.asvs_results = FakeCollection([])
        self.scans = FakeCollection([{"scan_id": "scan-1", "summary": scan_summary}])


async def _scan_and_merge(repo_path: Path) -> dict:
    pipeline = SemanticPipeline(PipelineConfig(enable_llm=False))
    result = await pipeline.analyze_repository(str(repo_path))
    summary = {
        "scan_id": "scan-1",
        "vulnerabilities": result.vulnerabilities,
        "config_findings": result.config_findings,
        "dependency_findings": result.dependency_findings,
        "dependency_control_result": result.dependency_control_result,
        "dynamic_probe_findings": [],
    }
    svc = ASVSService(FakeDB(summary))
    return await svc.get_compliance_summary("scan-1")


@pytest.fixture(scope="module")
def vulnerable_compliance():
    import asyncio
    return asyncio.run(_scan_and_merge(FIXTURES / "vulnerable"))


@pytest.fixture(scope="module")
def clean_compliance():
    import asyncio
    return asyncio.run(_scan_and_merge(FIXTURES / "clean"))


class TestVulnerableFixture:
    def test_produces_findings(self, vulnerable_compliance):
        fails = [c for c, r in vulnerable_compliance["results"].items() if r["verdict"] == "fail"]
        assert len(fails) >= 30, f"expected at least 30 failing controls, got {len(fails)}"

    def test_expected_controls_fail(self, vulnerable_compliance):
        for control_id in EXPECTED_FAIL_TO_PASS:
            assert vulnerable_compliance["results"][control_id]["verdict"] == "fail", (
                f"{control_id} expected to fail on the vulnerable fixture"
            )

    def test_dependency_control_fails(self, vulnerable_compliance):
        assert vulnerable_compliance["results"]["V15.2.1"]["verdict"] == "fail"

    def test_low_overall_compliance(self, vulnerable_compliance):
        assert vulnerable_compliance["levels"]["L1"]["pct"] < 30


class TestCleanFixture:
    def test_expected_controls_pass(self, clean_compliance):
        for control_id in EXPECTED_FAIL_TO_PASS:
            assert clean_compliance["results"][control_id]["verdict"] == "pass", (
                f"{control_id} expected to pass on the clean fixture (regression in rule accuracy)"
            )

    def test_no_new_false_positives_beyond_known_set(self, clean_compliance):
        unexpected_fails = {
            c for c, r in clean_compliance["results"].items()
            if r["verdict"] == "fail" and c not in KNOWN_FALSE_POSITIVES_IN_CLEAN and c != "V15.2.1"
        }
        assert not unexpected_fails, f"New false positive(s) on the clean fixture: {sorted(unexpected_fails)}"

    def test_higher_overall_compliance_than_vulnerable(self, clean_compliance, vulnerable_compliance):
        assert clean_compliance["levels"]["L1"]["pct"] > vulnerable_compliance["levels"]["L1"]["pct"]

    def test_compliance_meaningfully_high(self, clean_compliance):
        assert clean_compliance["levels"]["L1"]["pct"] >= 60
