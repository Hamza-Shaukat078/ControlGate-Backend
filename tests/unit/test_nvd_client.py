"""NVD CVE-enrichment client — CVSS extraction, graceful degradation on
network failure/404/rate-limit, and batch pacing/dedup/cap logic.
"""
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
    yield
    nvd_client._cache.clear()


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
