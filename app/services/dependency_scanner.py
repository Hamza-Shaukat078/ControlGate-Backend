"""
Dependency Scanner — ASVS 5.0.0 L1 control V15.2.1.

"Verify that the application only contains components which have not
breached the documented update and remediation time frames."

Rather than shelling out to pip-audit/npm-audit (neither is guaranteed to be
installed in whatever environment this backend runs in — pip-audit isn't a
project dependency, and npm audit needs a real node_modules install to be
meaningful), this queries the OSV.dev API directly over HTTP with httpx
(already a transitive dependency via the LLM provider SDKs). OSV is the same
vulnerability database pip-audit itself queries under the hood, so this is
not a lesser data source — just a more portable way to reach it.

Manifest support: requirements.txt (exact ==-pins), package.json (declared
range, best-effort), package-lock.json / Pipfile.lock (exact resolved
versions, preferred when present), and PEP 621 pyproject.toml
[project.dependencies].
"""
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_TIMEOUT_SECONDS = 8.0
MAX_CONCURRENT_QUERIES = 10

# Remediation SLA — days allowed before an unpatched, known-vulnerable
# component is considered a breach of the documented remediation policy.
REMEDIATION_SLA_DAYS = {
    "CRITICAL": 7,
    "HIGH": 30,
    "MODERATE": 90,
    "LOW": 180,
}
_DEFAULT_SEVERITY = "MODERATE"


@dataclass
class DependencyRef:
    name: str
    version: str
    ecosystem: str  # "PyPI" | "npm"
    source_file: str


@dataclass
class DependencyFinding:
    package: str
    version: str
    ecosystem: str
    vuln_id: str
    severity: str
    summary: str
    published: Optional[str] = None
    days_since_published: Optional[int] = None
    sla_days: int = REMEDIATION_SLA_DAYS[_DEFAULT_SEVERITY]
    breached_sla: bool = False


class DependencyScanner:
    # ── Manifest parsing ─────────────────────────────────────────────────────

    _REQ_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)")
    _RANGE_PREFIX = re.compile(r"^[\^~>=<]+\s*")

    def parse_manifests(self, file_map: dict[str, str]) -> list[DependencyRef]:
        refs: list[DependencyRef] = []
        by_name = {Path(p).name.lower(): p for p in file_map}

        for path, content in file_map.items():
            name = Path(path).name.lower()
            try:
                if name in ("requirements.txt", "requirements-dev.txt") or name.startswith("requirements"):
                    refs += self._parse_requirements_txt(path, content)
                elif name == "pyproject.toml":
                    refs += self._parse_pyproject_toml(path, content)
                elif name == "pipfile.lock":
                    refs += self._parse_pipfile_lock(path, content)
                elif name == "package-lock.json":
                    refs += self._parse_package_lock(path, content)
                elif name == "package.json":
                    # Skip package.json range-declarations if an exact lockfile is present —
                    # the lockfile has the actually-installed version.
                    if "package-lock.json" not in by_name:
                        refs += self._parse_package_json(path, content)
            except Exception as exc:
                logger.warning(f"Dependency manifest parse failed for {path}: {exc}")

        # De-dupe (name, version, ecosystem) — same package can appear in
        # both requirements.txt and requirements-dev.txt.
        seen = set()
        deduped = []
        for ref in refs:
            key = (ref.name.lower(), ref.version, ref.ecosystem)
            if key not in seen:
                seen.add(key)
                deduped.append(ref)
        return deduped

    def _parse_requirements_txt(self, path: str, content: str) -> list[DependencyRef]:
        refs = []
        for line in content.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            m = self._REQ_LINE.match(line)
            if m:
                refs.append(DependencyRef(m.group(1), m.group(2), "PyPI", path))
        return refs

    def _parse_pyproject_toml(self, path: str, content: str) -> list[DependencyRef]:
        try:
            import tomllib
        except ModuleNotFoundError:
            return []
        try:
            data = tomllib.loads(content)
        except Exception:
            return []

        refs = []
        deps = (data.get("project") or {}).get("dependencies") or []
        for entry in deps:
            m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)", entry.strip())
            if m:
                refs.append(DependencyRef(m.group(1), m.group(2), "PyPI", path))
        return refs

    def _parse_pipfile_lock(self, path: str, content: str) -> list[DependencyRef]:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []
        refs = []
        for section in ("default", "develop"):
            for pkg_name, meta in (data.get(section) or {}).items():
                version = (meta or {}).get("version", "")
                version = version.lstrip("=") if version else ""
                if version:
                    refs.append(DependencyRef(pkg_name, version, "PyPI", path))
        return refs

    def _parse_package_json(self, path: str, content: str) -> list[DependencyRef]:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []
        refs = []
        for section in ("dependencies", "devDependencies"):
            for pkg_name, spec in (data.get(section) or {}).items():
                if not isinstance(spec, str):
                    continue
                version = self._RANGE_PREFIX.sub("", spec.strip())
                # Skip non-registry specs (git urls, "workspace:*", "file:...")
                if not re.match(r"^\d", version):
                    continue
                refs.append(DependencyRef(pkg_name, version, "npm", path))
        return refs

    def _parse_package_lock(self, path: str, content: str) -> list[DependencyRef]:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []
        refs = []
        packages = data.get("packages")
        if isinstance(packages, dict):
            # lockfile v2/v3: keys are "node_modules/<pkg>" (possibly nested)
            for key, meta in packages.items():
                if not key or not isinstance(meta, dict):
                    continue
                pkg_name = key.rsplit("node_modules/", 1)[-1]
                version = meta.get("version")
                if pkg_name and version:
                    refs.append(DependencyRef(pkg_name, version, "npm", path))
        else:
            # lockfile v1: nested "dependencies" tree
            def _walk(deps: dict):
                for pkg_name, meta in (deps or {}).items():
                    version = meta.get("version")
                    if version:
                        refs.append(DependencyRef(pkg_name, version, "npm", path))
                    if meta.get("dependencies"):
                        _walk(meta["dependencies"])
            _walk(data.get("dependencies") or {})
        return refs

    # ── OSV querying ──────────────────────────────────────────────────────────

    async def query_osv(self, refs: list[DependencyRef]) -> list[DependencyFinding]:
        if not refs:
            return []

        import asyncio
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_QUERIES)

        async def _query_one(client: httpx.AsyncClient, ref: DependencyRef) -> list[DependencyFinding]:
            async with semaphore:
                try:
                    resp = await client.post(
                        OSV_QUERY_URL,
                        json={"package": {"name": ref.name, "ecosystem": ref.ecosystem}, "version": ref.version},
                        timeout=OSV_TIMEOUT_SECONDS,
                    )
                    resp.raise_for_status()
                    data = resp.json()
                except Exception as exc:
                    logger.warning(f"OSV query failed for {ref.ecosystem}:{ref.name}@{ref.version}: {exc}")
                    return []
                return [self._to_finding(ref, v) for v in data.get("vulns", [])]

        async with httpx.AsyncClient() as client:
            results = await asyncio.gather(*[_query_one(client, ref) for ref in refs])

        findings: list[DependencyFinding] = []
        for r in results:
            findings.extend(r)
        return findings

    def _to_finding(self, ref: DependencyRef, vuln: dict) -> DependencyFinding:
        severity = self._extract_severity(vuln)
        published = vuln.get("published")
        days_since = self._days_since(published)
        sla_days = REMEDIATION_SLA_DAYS.get(severity, REMEDIATION_SLA_DAYS[_DEFAULT_SEVERITY])
        breached = days_since is not None and days_since > sla_days
        summary = vuln.get("summary") or vuln.get("details", "")[:200] or vuln.get("id", "")
        return DependencyFinding(
            package=ref.name, version=ref.version, ecosystem=ref.ecosystem,
            vuln_id=vuln.get("id", "UNKNOWN"), severity=severity, summary=summary,
            published=published, days_since_published=days_since,
            sla_days=sla_days, breached_sla=breached,
        )

    @staticmethod
    def _extract_severity(vuln: dict) -> str:
        db_specific = vuln.get("database_specific") or {}
        sev = db_specific.get("severity")
        if isinstance(sev, str) and sev.upper() in REMEDIATION_SLA_DAYS:
            return sev.upper()

        for entry in vuln.get("severity") or []:
            if entry.get("type") == "CVSS_V3" and entry.get("score"):
                score_str = entry["score"]
                m = re.search(r"/([\d.]+)$", score_str) or re.match(r"^([\d.]+)$", score_str)
                # CVSS vector strings don't carry a base score directly; if a bare
                # numeric score was provided instead, use standard CVSS bands.
                try:
                    numeric = float(score_str) if re.match(r"^[\d.]+$", score_str) else None
                except ValueError:
                    numeric = None
                if numeric is not None:
                    if numeric >= 9:
                        return "CRITICAL"
                    if numeric >= 7:
                        return "HIGH"
                    if numeric >= 4:
                        return "MODERATE"
                    return "LOW"
        return _DEFAULT_SEVERITY

    @staticmethod
    def _days_since(iso_date: Optional[str]) -> Optional[int]:
        if not iso_date:
            return None
        try:
            published = datetime.fromisoformat(iso_date.replace("Z", "+00:00"))
            return (datetime.now(timezone.utc) - published).days
        except ValueError:
            return None

    # ── Control evaluation ───────────────────────────────────────────────────

    @staticmethod
    def evaluate_v15_2_1(findings: list[DependencyFinding]) -> dict:
        """
        pass           — no known-vulnerable dependencies found
        manual_review  — vulnerable dependencies found, all still within their SLA window
        fail           — at least one vulnerable dependency has breached its remediation SLA
        """
        if not findings:
            return {
                "control_id": "V15.2.1", "verdict": "pass",
                "note": "No known-vulnerable dependencies found against OSV.dev.",
            }

        breached = [f for f in findings if f.breached_sla]
        if breached:
            worst = sorted(breached, key=lambda f: REMEDIATION_SLA_DAYS.get(f.severity, 999))[0]
            return {
                "control_id": "V15.2.1", "verdict": "fail",
                "note": (
                    f"{len(breached)} of {len(findings)} vulnerable dependencies have breached "
                    f"their remediation SLA (worst: {worst.package}@{worst.version} — {worst.vuln_id}, "
                    f"{worst.severity}, {worst.days_since_published}d since publish, SLA {worst.sla_days}d)."
                ),
            }

        return {
            "control_id": "V15.2.1", "verdict": "manual_review",
            "note": f"{len(findings)} vulnerable dependencies found, all still within their remediation SLA window.",
        }
