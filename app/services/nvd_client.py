"""NVD (National Vulnerability Database) CVE enrichment.

Used purely as an enrichment step, not discovery — OSV.dev already tells us
*which* CVE applies to a vulnerable dependency (dependency_scanner.py); this
looks up each CVE *by ID* (fast — no product/version search) to attach the
authoritative CVSS score/severity/description/references NVD provides,
which OSV's own severity field is a much coarser proxy for.

Rate-limited deliberately conservatively: NVD's public limit is 5 requests
per rolling 30s window (50/30s with a free API key — see
https://nvd.nist.gov/developers/request-an-api-key, set NVD_API_KEY). A
failed lookup (timeout/404/rate-limited) degrades that one CVE to
"unenriched" rather than failing the whole scan — same philosophy as every
other network-dependent check in this backend.
"""
import asyncio
import dataclasses
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_TIMEOUT_SECONDS = 10.0

# Paced comfortably under NVD's published limits (5/30s public, 50/30s with a key).
_NO_KEY_DELAY_SECONDS = 6.5
_WITH_KEY_DELAY_SECONDS = 0.7

# D2 — a CVE's core data (score/description) doesn't change scan to scan, so
# repeat lookups of the same CVE across *process restarts*, not just within
# one, are wasted rate-limited calls. A flat JSON file (not Mongo) on purpose:
# every call site down to DependencyScanner.enrich_with_nvd() is currently
# DB-handle-free, and this cache's whole job is surviving a restart, not
# concurrent multi-instance sharing — a file is the smallest change that
# solves that, without threading a Mongo connection through three layers
# that don't have one today.
_CACHE_FILE = Path(__file__).resolve().parents[2] / ".nvd_cache" / "cve_cache.json"
_cache: Dict[str, Optional["CveDetails"]] = {}
_disk_cache_loaded = False


def _load_disk_cache() -> None:
    global _disk_cache_loaded
    if _disk_cache_loaded:
        return
    _disk_cache_loaded = True
    try:
        if not _CACHE_FILE.exists():
            return
        raw = json.loads(_CACHE_FILE.read_text(encoding="utf-8"))
        for cve_id, data in raw.items():
            _cache[cve_id] = CveDetails(**data) if data is not None else None
    except Exception as exc:
        logger.warning(f"Could not load NVD disk cache, starting empty: {exc}")


def _save_disk_cache() -> None:
    try:
        _CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        serializable = {
            cve_id: (dataclasses.asdict(details) if details is not None else None)
            for cve_id, details in _cache.items()
        }
        _CACHE_FILE.write_text(json.dumps(serializable), encoding="utf-8")
    except Exception as exc:
        # Never let a cache-write failure break enrichment itself.
        logger.warning(f"Could not persist NVD disk cache: {exc}")


@dataclass
class CveDetails:
    cve_id: str
    cvss_score: Optional[float] = None
    cvss_severity: Optional[str] = None
    cvss_version: Optional[str] = None
    description: str = ""
    references: List[str] = field(default_factory=list)
    published: Optional[str] = None


def _extract_cvss(cve_data: dict):
    metrics = cve_data.get("metrics", {})
    for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key)
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            severity = entries[0].get("baseSeverity") or cvss_data.get("baseSeverity")
            if score is not None:
                return float(score), severity, version
    return None, None, None


async def fetch_cve_details(cve_id: str, *, api_key: Optional[str] = None) -> Optional[CveDetails]:
    _load_disk_cache()
    if cve_id in _cache:
        return _cache[cve_id]

    headers = {"apiKey": api_key} if api_key else {}
    try:
        async with httpx.AsyncClient(timeout=NVD_TIMEOUT_SECONDS) as client:
            resp = await client.get(NVD_CVE_URL, params={"cveId": cve_id}, headers=headers)
        if resp.status_code == 404:
            _cache[cve_id] = None
            _save_disk_cache()
            return None
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        logger.warning(f"NVD lookup failed for {cve_id}: {exc}")
        return None

    vulns = data.get("vulnerabilities") or []
    if not vulns:
        _cache[cve_id] = None
        _save_disk_cache()
        return None

    cve_data = vulns[0].get("cve", {})
    score, severity, cvss_version = _extract_cvss(cve_data)
    descriptions = cve_data.get("descriptions") or []
    description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
    references = [r["url"] for r in (cve_data.get("references") or []) if r.get("url")]

    details = CveDetails(
        cve_id=cve_id, cvss_score=score, cvss_severity=severity, cvss_version=cvss_version,
        description=description, references=references, published=cve_data.get("published"),
    )
    _cache[cve_id] = details
    _save_disk_cache()
    return details


async def fetch_cve_details_batch(
    cve_ids: List[str], *, api_key: Optional[str] = None, max_lookups: int = 10,
) -> Dict[str, CveDetails]:
    """Looks up up to max_lookups distinct CVE IDs, paced to respect NVD's
    rate limit (sequential, not concurrent — concurrent requests would blow
    through the rate limit immediately). Returns only the ones successfully
    resolved; callers must treat a missing ID as "not enriched this scan",
    never as "no CVE data exists for this ID" — dependency_scanner.py's
    OSV-derived severity remains the fallback for anything NVD didn't reach.
    """
    unique_ids = list(dict.fromkeys(cve_ids))[:max_lookups]
    delay = _WITH_KEY_DELAY_SECONDS if api_key else _NO_KEY_DELAY_SECONDS

    results: Dict[str, CveDetails] = {}
    for i, cve_id in enumerate(unique_ids):
        if i > 0:
            await asyncio.sleep(delay)
        details = await fetch_cve_details(cve_id, api_key=api_key)
        if details is not None:
            results[cve_id] = details
    return results
