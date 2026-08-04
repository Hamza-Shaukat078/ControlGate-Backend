"""NVD CVE-enrichment client — CVSS extraction, graceful degradation on
network failure/404/rate-limit, and batch pacing/dedup/cap logic.
"""
import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.services import nvd_client
from app.services.nvd_client import fetch_cve_details, fetch_cve_details_batch


def _mock_nvd_response(cve_id: str, *, cvss_v31=None, description="A vulnerability", references=None):
    metrics = {}
    if cvss_v31 is not None:
        metrics["cvssMetricV31"] = [{"cvssData": {"baseScore": cvss_v31}, "baseSeverity": "HIGH"}]
    body = {
        "vulnerabilities": [{"cve": {
            "id": cve_id, "published": "2020-01-01T00:00:00.000",
            "descriptions": [{"lang": "en", "value": description}],
            "references": [{"url": u} for u in (references or [])],
            "metrics": metrics,
        }}]
    }
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = 200
    resp.json.return_value = body
    resp.raise_for_status = MagicMock()
    return resp


@pytest.fixture(autouse=True)
def _clear_cache():
    nvd_client._cache.clear()
    # D2's disk-persisted cache is process-lifetime-loaded-once by design —
    # force it "already loaded" here so no test ever reads a real
    # .nvd_cache/cve_cache.json off disk; TestDiskPersistence below resets
    # this explicitly to exercise the load/save path in isolation.
    nvd_client._disk_cache_loaded = True
    yield
    nvd_client._cache.clear()
    nvd_client._disk_cache_loaded = True


class TestFetchCveDetails:
    @pytest.mark.asyncio
    async def test_extracts_cvss_v31_score(self):
        resp = _mock_nvd_response("CVE-2021-12345", cvss_v31=9.8, references=["https://example.com/a"])
        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=resp)):
            details = await fetch_cve_details("CVE-2021-12345")
        assert details.cvss_score == 9.8
        assert details.cvss_severity == "HIGH"
        assert details.cvss_version == "3.1"
        assert details.description == "A vulnerability"
        assert details.references == ["https://example.com/a"]

    @pytest.mark.asyncio
    async def test_no_cvss_metrics_returns_none_score(self):
        resp = _mock_nvd_response("CVE-2021-12345")
        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=resp)):
            details = await fetch_cve_details("CVE-2021-12345")
        assert details.cvss_score is None

    @pytest.mark.asyncio
    async def test_404_returns_none(self):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 404
        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=resp)):
            details = await fetch_cve_details("CVE-9999-99999")
        assert details is None

    @pytest.mark.asyncio
    async def test_network_failure_returns_none(self):
        with patch("httpx.AsyncClient.get", new=AsyncMock(side_effect=Exception("timeout"))):
            details = await fetch_cve_details("CVE-2021-12345")
        assert details is None

    @pytest.mark.asyncio
    async def test_result_is_cached(self):
        resp = _mock_nvd_response("CVE-2021-12345", cvss_v31=9.8)
        mock_get = AsyncMock(return_value=resp)
        with patch("httpx.AsyncClient.get", new=mock_get):
            await fetch_cve_details("CVE-2021-12345")
            await fetch_cve_details("CVE-2021-12345")
        assert mock_get.call_count == 1

    @pytest.mark.asyncio
    async def test_negative_cache_avoids_repeat_404_lookup(self):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 404
        mock_get = AsyncMock(return_value=resp)
        with patch("httpx.AsyncClient.get", new=mock_get):
            await fetch_cve_details("CVE-9999-99999")
            await fetch_cve_details("CVE-9999-99999")
        assert mock_get.call_count == 1


class TestFetchCveDetailsBatch:
    @pytest.mark.asyncio
    async def test_dedupes_and_caps_at_max_lookups(self):
        seen = []

        async def fake_fetch(cve_id, *, api_key=None):
            seen.append(cve_id)
            return nvd_client.CveDetails(cve_id=cve_id, cvss_score=5.0)

        with patch("app.services.nvd_client.fetch_cve_details", side_effect=fake_fetch), \
             patch("asyncio.sleep", new=AsyncMock()):
            results = await fetch_cve_details_batch(
                ["CVE-1", "CVE-1", "CVE-2", "CVE-3"], max_lookups=2,
            )
        assert seen == ["CVE-1", "CVE-2"]  # deduped, capped at 2
        assert set(results.keys()) == {"CVE-1", "CVE-2"}

    @pytest.mark.asyncio
    async def test_unresolved_cve_omitted_from_results(self):
        async def fake_fetch(cve_id, *, api_key=None):
            return None if cve_id == "CVE-1" else nvd_client.CveDetails(cve_id=cve_id, cvss_score=5.0)

        with patch("app.services.nvd_client.fetch_cve_details", side_effect=fake_fetch), \
             patch("asyncio.sleep", new=AsyncMock()):
            results = await fetch_cve_details_batch(["CVE-1", "CVE-2"])
        assert "CVE-1" not in results
        assert "CVE-2" in results

    @pytest.mark.asyncio
    async def test_paces_requests_with_delay_between_calls(self):
        sleep_mock = AsyncMock()
        with patch("app.services.nvd_client.fetch_cve_details",
                   AsyncMock(return_value=nvd_client.CveDetails(cve_id="X", cvss_score=1.0))), \
             patch("asyncio.sleep", sleep_mock):
            await fetch_cve_details_batch(["CVE-1", "CVE-2", "CVE-3"])
        assert sleep_mock.call_count == 2  # delay before 2nd and 3rd, not before the 1st

    @pytest.mark.asyncio
    async def test_empty_list_returns_empty_dict(self):
        results = await fetch_cve_details_batch([])
        assert results == {}


class TestDiskPersistence:
    """D2 — the cache survives a process restart via a flat JSON file
    (see nvd_client.py's module docstring for why not Mongo). Each test
    points _CACHE_FILE at a tmp_path and resets _disk_cache_loaded so
    _load_disk_cache() actually runs, isolated from any real cache file."""

    @pytest.fixture(autouse=True)
    def _isolated_cache_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(nvd_client, "_CACHE_FILE", tmp_path / "cve_cache.json")
        nvd_client._disk_cache_loaded = False
        yield

    @pytest.mark.asyncio
    async def test_successful_lookup_is_persisted_to_disk(self):
        resp = _mock_nvd_response("CVE-2021-12345", cvss_v31=9.8)
        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=resp)):
            await fetch_cve_details("CVE-2021-12345")

        assert nvd_client._CACHE_FILE.exists()
        saved = json.loads(nvd_client._CACHE_FILE.read_text(encoding="utf-8"))
        assert saved["CVE-2021-12345"]["cvss_score"] == 9.8

    @pytest.mark.asyncio
    async def test_negative_result_is_persisted_as_null(self):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 404
        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=resp)):
            await fetch_cve_details("CVE-9999-99999")

        saved = json.loads(nvd_client._CACHE_FILE.read_text(encoding="utf-8"))
        assert saved["CVE-9999-99999"] is None

    @pytest.mark.asyncio
    async def test_cache_survives_a_simulated_restart(self):
        resp = _mock_nvd_response("CVE-2021-12345", cvss_v31=7.5)
        mock_get = AsyncMock(return_value=resp)
        with patch("httpx.AsyncClient.get", new=mock_get):
            await fetch_cve_details("CVE-2021-12345")

        # Simulate a fresh process: in-memory cache and the loaded-flag both
        # reset, only the disk file (still pointed at tmp_path) survives.
        nvd_client._cache.clear()
        nvd_client._disk_cache_loaded = False

        with patch("httpx.AsyncClient.get", new=mock_get):
            details = await fetch_cve_details("CVE-2021-12345")

        assert details.cvss_score == 7.5
        mock_get.assert_called_once()  # second call served from the disk-restored cache

    @pytest.mark.asyncio
    async def test_corrupt_cache_file_is_ignored_not_raised(self):
        nvd_client._CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        nvd_client._CACHE_FILE.write_text("not valid json", encoding="utf-8")

        resp = _mock_nvd_response("CVE-2021-12345", cvss_v31=5.0)
        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=resp)):
            details = await fetch_cve_details("CVE-2021-12345")

        assert details.cvss_score == 5.0

    @pytest.mark.asyncio
    async def test_disk_cache_loaded_only_once_per_process(self):
        resp = _mock_nvd_response("CVE-2021-12345", cvss_v31=5.0)
        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=resp)):
            await fetch_cve_details("CVE-2021-12345")
        assert nvd_client._disk_cache_loaded is True

        # Delete the file after the first load — a second lookup shouldn't
        # try to reload (and thus shouldn't care that it's gone).
        nvd_client._CACHE_FILE.unlink()
        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=resp)) as mock_get:
            await fetch_cve_details("CVE-2021-12345")  # served from in-memory _cache
        mock_get.assert_not_called()
