"""
Dependency Scanner tests — ASVS control V15.2.1.

Manifest parsing and SLA/severity logic are tested directly (no network).
query_osv() is tested against a mocked httpx.AsyncClient so the suite stays
fast and deterministic — Section D's implementation notes include one real,
live run against the actual OSV.dev API (flask==0.12, lodash==4.17.15)
confirming the integration itself works; this suite locks in the logic.
"""
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.dependency_scanner import (
    DependencyFinding,
    DependencyRef,
    DependencyScanner,
    REMEDIATION_SLA_DAYS,
)


# ── Manifest parsing ──────────────────────────────────────────────────────────

class TestRequirementsTxtParsing:
    def test_exact_pins_extracted(self):
        content = "flask==1.0.0\ndjango==3.2.1\n"
        refs = DependencyScanner().parse_manifests({"requirements.txt": content})
        assert {(r.name, r.version, r.ecosystem) for r in refs} == {
            ("flask", "1.0.0", "PyPI"), ("django", "3.2.1", "PyPI"),
        }

    def test_range_specs_skipped(self):
        refs = DependencyScanner().parse_manifests({"requirements.txt": "requests>=2.0\n"})
        assert refs == []

    def test_comments_and_includes_ignored(self):
        content = "# comment\nflask==1.0.0\n-r other.txt\n\n"
        refs = DependencyScanner().parse_manifests({"requirements.txt": content})
        assert len(refs) == 1
        assert refs[0].name == "flask"


class TestPackageJsonParsing:
    def test_range_prefixes_stripped(self):
        content = '{"dependencies": {"lodash": "^4.17.15", "express": "~4.16.0"}}'
        refs = DependencyScanner().parse_manifests({"package.json": content})
        versions = {r.name: r.version for r in refs}
        assert versions == {"lodash": "4.17.15", "express": "4.16.0"}

    def test_non_registry_specs_skipped(self):
        content = '{"dependencies": {"local-pkg": "file:../local"}}'
        refs = DependencyScanner().parse_manifests({"package.json": content})
        assert refs == []

    def test_skipped_when_lockfile_present(self):
        file_map = {
            "package.json": '{"dependencies": {"lodash": "^4.17.15"}}',
            "package-lock.json": '{"packages": {"node_modules/lodash": {"version": "4.17.20"}}}',
        }
        refs = DependencyScanner().parse_manifests(file_map)
        assert len(refs) == 1
        assert refs[0].version == "4.17.20"  # exact resolved version wins over declared range


class TestPackageLockParsing:
    def test_v2_v3_format(self):
        content = '{"packages": {"": {"name": "root"}, "node_modules/lodash": {"version": "4.17.15"}}}'
        refs = DependencyScanner().parse_manifests({"package-lock.json": content})
        assert len(refs) == 1
        assert refs[0].name == "lodash" and refs[0].version == "4.17.15"

    def test_v1_nested_format(self):
        content = '{"dependencies": {"lodash": {"version": "4.17.15", "dependencies": {"nested": {"version": "1.0.0"}}}}}'
        refs = DependencyScanner().parse_manifests({"package-lock.json": content})
        names = {r.name for r in refs}
        assert names == {"lodash", "nested"}


class TestPipfileLockParsing:
    def test_default_and_develop_sections(self):
        content = '{"default": {"flask": {"version": "==1.0.0"}}, "develop": {"pytest": {"version": "==7.0.0"}}}'
        refs = DependencyScanner().parse_manifests({"Pipfile.lock": content})
        versions = {r.name: r.version for r in refs}
        assert versions == {"flask": "1.0.0", "pytest": "7.0.0"}


class TestPyprojectTomlParsing:
    def test_pep621_exact_pins(self):
        content = '[project]\nname = "x"\ndependencies = ["flask==1.0.0", "click>=8.0"]\n'
        refs = DependencyScanner().parse_manifests({"pyproject.toml": content})
        assert len(refs) == 1
        assert refs[0].name == "flask" and refs[0].version == "1.0.0"


class TestManifestDeduplication:
    def test_same_package_across_files_deduped(self):
        file_map = {
            "requirements.txt": "flask==1.0.0\n",
            "requirements-dev.txt": "flask==1.0.0\n",
        }
        refs = DependencyScanner().parse_manifests(file_map)
        assert len(refs) == 1


# ── Severity extraction ───────────────────────────────────────────────────────

class TestSeverityExtraction:
    def test_database_specific_severity_used_first(self):
        vuln = {"database_specific": {"severity": "CRITICAL"}}
        assert DependencyScanner._extract_severity(vuln) == "CRITICAL"

    def test_cvss_numeric_score_mapped_to_band(self):
        assert DependencyScanner._extract_severity({"severity": [{"type": "CVSS_V3", "score": "9.8"}]}) == "CRITICAL"
        assert DependencyScanner._extract_severity({"severity": [{"type": "CVSS_V3", "score": "7.5"}]}) == "HIGH"
        assert DependencyScanner._extract_severity({"severity": [{"type": "CVSS_V3", "score": "5.0"}]}) == "MODERATE"
        assert DependencyScanner._extract_severity({"severity": [{"type": "CVSS_V3", "score": "2.0"}]}) == "LOW"

    def test_default_when_no_severity_data(self):
        assert DependencyScanner._extract_severity({}) == "MODERATE"


# ── SLA / days-since-published ────────────────────────────────────────────────

class TestSlaComputation:
    def test_days_since_published(self):
        published = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
        days = DependencyScanner._days_since(published)
        assert days in (99, 100, 101)  # tolerate timing jitter

    def test_none_when_no_date(self):
        assert DependencyScanner._days_since(None) is None

    def test_malformed_date_returns_none(self):
        assert DependencyScanner._days_since("not-a-date") is None


class TestEvaluateV15_2_1:
    def test_no_findings_passes(self):
        result = DependencyScanner.evaluate_v15_2_1([])
        assert result["verdict"] == "pass"

    def test_findings_within_sla_are_manual_review(self):
        finding = DependencyFinding(
            package="flask", version="1.0.0", ecosystem="PyPI", vuln_id="GHSA-x",
            severity="LOW", summary="test", published=None,
            days_since_published=10, sla_days=REMEDIATION_SLA_DAYS["LOW"], breached_sla=False,
        )
        result = DependencyScanner.evaluate_v15_2_1([finding])
        assert result["verdict"] == "manual_review"

    def test_findings_breaching_sla_fail(self):
        finding = DependencyFinding(
            package="flask", version="0.12", ecosystem="PyPI", vuln_id="GHSA-x",
            severity="CRITICAL", summary="test", published=None,
            days_since_published=100, sla_days=REMEDIATION_SLA_DAYS["CRITICAL"], breached_sla=True,
        )
        result = DependencyScanner.evaluate_v15_2_1([finding])
        assert result["verdict"] == "fail"
        assert "flask@0.12" in result["note"]


# ── query_osv (mocked HTTP) ───────────────────────────────────────────────────

def _mock_osv_response(vulns: list[dict]):
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json = MagicMock(return_value={"vulns": vulns})
    return resp


class TestQueryOsv:
    @pytest.mark.asyncio
    async def test_builds_findings_from_response(self):
        ref = DependencyRef("flask", "0.12", "PyPI", "requirements.txt")
        vuln = {
            "id": "GHSA-test-1234", "summary": "Test vuln",
            "published": "2020-01-01T00:00:00Z",
            "database_specific": {"severity": "HIGH"},
        }
        with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=_mock_osv_response([vuln]))):
            findings = await DependencyScanner().query_osv([ref])
        assert len(findings) == 1
        assert findings[0].vuln_id == "GHSA-test-1234"
        assert findings[0].severity == "HIGH"
        assert findings[0].breached_sla is True  # 2020 publish date, way past a 30-day HIGH SLA

    @pytest.mark.asyncio
    async def test_empty_vulns_produces_no_findings(self):
        ref = DependencyRef("flask", "3.1.1", "PyPI", "requirements.txt")
        with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=_mock_osv_response([]))):
            findings = await DependencyScanner().query_osv([ref])
        assert findings == []

    @pytest.mark.asyncio
    async def test_network_failure_degrades_gracefully(self):
        ref = DependencyRef("flask", "1.0.0", "PyPI", "requirements.txt")
        with patch("httpx.AsyncClient.post", new=AsyncMock(side_effect=Exception("connection refused"))):
            findings = await DependencyScanner().query_osv([ref])
        assert findings == []  # no exception propagates — control just gets no evidence

    @pytest.mark.asyncio
    async def test_no_refs_returns_immediately(self):
        findings = await DependencyScanner().query_osv([])
        assert findings == []
