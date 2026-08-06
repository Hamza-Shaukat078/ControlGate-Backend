"""Track C3 wiring — dynamic_openapi_spec_url/dynamic_openapi_spec on
ScanStart, threaded through _run_dynamic_checks into a second, optional
source of URLs for check_urls, folded in alongside the crawler's own output.

Mocks fetch_openapi_spec/parse_openapi_spec (the discovery logic itself is
covered by test_dast_openapi_discovery.py) and run_payload_checks — this
tests only the glue: that check_urls actually gets widened, capped, and
deduped, and that a broken spec degrades the scan rather than aborting it.
Same pattern as test_scan_service_dynamic_dispatch.py's TestCrawlerWiring.
"""
import socket
from unittest.mock import AsyncMock, patch

import pytest
from mongomock_motor import AsyncMongoMockClient

from app.domain.analysis.dast.crawler import CrawlResult
from app.domain.analysis.dast.openapi_discovery import DiscoveredEndpoint
from app.services.scan_service import ScanService

TARGET = "https://example.com"


@pytest.fixture(autouse=True)
def _mock_dns(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))],
    )


class _FakeSessionPair:
    last_config = None
    last_instance = None

    def __init__(self, config):
        _FakeSessionPair.last_config = config
        _FakeSessionPair.last_instance = self
        self.primary = object()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False


async def _make_service():
    db = AsyncMongoMockClient()["test"]
    return ScanService(db), db


class TestOpenApiSpecUrlWiring:
    @pytest.mark.asyncio
    async def test_discovered_urls_are_folded_into_check_urls(self):
        svc, db = await _make_service()
        endpoints = [DiscoveredEndpoint(method="GET", url=f"{TARGET}/api/users?id=1")]
        run_checks_mock = AsyncMock(return_value=[])
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult(urls=[TARGET]))), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", run_checks_mock), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.openapi_discovery.fetch_openapi_spec",
                   AsyncMock(return_value={"paths": {}})), \
             patch("app.domain.analysis.dast.openapi_discovery.parse_openapi_spec", return_value=endpoints):
            await svc._run_dynamic_scan(
                "scan-oa-1", TARGET, dynamic_openapi_spec_url=f"{TARGET}/openapi.json",
            )

        called_urls = run_checks_mock.call_args.args[1]
        assert f"{TARGET}/api/users?id=1" in called_urls

    @pytest.mark.asyncio
    async def test_spec_fetched_through_the_primary_session(self):
        svc, db = await _make_service()
        fetch_mock = AsyncMock(return_value={"paths": {}})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult(urls=[TARGET]))), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.openapi_discovery.fetch_openapi_spec", fetch_mock), \
             patch("app.domain.analysis.dast.openapi_discovery.parse_openapi_spec", return_value=[]):
            await svc._run_dynamic_scan(
                "scan-oa-2", TARGET, dynamic_openapi_spec_url=f"{TARGET}/openapi.json",
            )

        fetch_mock.assert_awaited_once_with(_FakeSessionPair.last_instance.primary, f"{TARGET}/openapi.json")

    @pytest.mark.asyncio
    async def test_duplicate_url_against_crawler_output_is_not_added_twice(self):
        svc, db = await _make_service()
        # The crawler already found this exact URL — discovery must not add
        # a second copy of it to check_urls.
        endpoints = [DiscoveredEndpoint(method="GET", url=f"{TARGET}/shared")]
        run_checks_mock = AsyncMock(return_value=[])
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl",
                   AsyncMock(return_value=CrawlResult(urls=[TARGET, f"{TARGET}/shared"]))), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", run_checks_mock), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.openapi_discovery.fetch_openapi_spec",
                   AsyncMock(return_value={"paths": {}})), \
             patch("app.domain.analysis.dast.openapi_discovery.parse_openapi_spec", return_value=endpoints):
            await svc._run_dynamic_scan(
                "scan-oa-3", TARGET, dynamic_openapi_spec_url=f"{TARGET}/openapi.json",
            )

        called_urls = run_checks_mock.call_args.args[1]
        assert called_urls.count(f"{TARGET}/shared") == 1

    @pytest.mark.asyncio
    async def test_discovered_urls_capped_at_fifteen(self):
        svc, db = await _make_service()
        endpoints = [DiscoveredEndpoint(method="GET", url=f"{TARGET}/api/{i}") for i in range(30)]
        run_checks_mock = AsyncMock(return_value=[])
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult(urls=[TARGET]))), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", run_checks_mock), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.openapi_discovery.fetch_openapi_spec",
                   AsyncMock(return_value={"paths": {}})), \
             patch("app.domain.analysis.dast.openapi_discovery.parse_openapi_spec", return_value=endpoints):
            await svc._run_dynamic_scan(
                "scan-oa-4", TARGET, dynamic_openapi_spec_url=f"{TARGET}/openapi.json",
            )

        called_urls = run_checks_mock.call_args.args[1]
        openapi_urls_included = [u for u in called_urls if u.startswith(f"{TARGET}/api/")]
        assert len(openapi_urls_included) == 15

    @pytest.mark.asyncio
    async def test_fetch_failure_degrades_scan_instead_of_aborting(self):
        svc, db = await _make_service()
        run_checks_mock = AsyncMock(return_value=[])
        await db.scans.insert_one({"scan_id": "scan-oa-5", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult(urls=[TARGET]))), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", run_checks_mock), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.openapi_discovery.fetch_openapi_spec",
                   AsyncMock(side_effect=RuntimeError("connection refused"))):
            await svc._run_dynamic_scan(
                "scan-oa-5", TARGET, dynamic_openapi_spec_url=f"{TARGET}/openapi.json",
            )

        doc = await db.scans.find_one({"scan_id": "scan-oa-5"})
        assert doc["state"] == "COMPLETED"
        called_urls = run_checks_mock.call_args.args[1]
        assert called_urls == [TARGET]  # crawler-only, unaffected by the failed spec fetch

    @pytest.mark.asyncio
    async def test_no_spec_supplied_never_calls_discovery(self):
        svc, db = await _make_service()
        fetch_mock = AsyncMock()
        parse_mock = AsyncMock()
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult(urls=[TARGET]))), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", AsyncMock(return_value=[])), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.openapi_discovery.fetch_openapi_spec", fetch_mock), \
             patch("app.domain.analysis.dast.openapi_discovery.parse_openapi_spec", parse_mock):
            await svc._run_dynamic_scan("scan-oa-6", TARGET)

        fetch_mock.assert_not_called()
        parse_mock.assert_not_called()


class TestInlineOpenApiSpecWiring:
    @pytest.mark.asyncio
    async def test_inline_spec_text_is_parsed_without_fetching(self):
        svc, db = await _make_service()
        endpoints = [DiscoveredEndpoint(method="GET", url=f"{TARGET}/api/inline?x=1")]
        fetch_mock = AsyncMock()
        run_checks_mock = AsyncMock(return_value=[])
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult(urls=[TARGET]))), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", run_checks_mock), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)), \
             patch("app.domain.analysis.dast.openapi_discovery.fetch_openapi_spec", fetch_mock), \
             patch("app.domain.analysis.dast.openapi_discovery.parse_openapi_spec", return_value=endpoints):
            await svc._run_dynamic_scan(
                "scan-oa-7", TARGET, dynamic_openapi_spec='{"paths": {"/api/inline": {"get": {}}}}',
            )

        fetch_mock.assert_not_called()  # inline text never hits the network
        called_urls = run_checks_mock.call_args.args[1]
        assert f"{TARGET}/api/inline?x=1" in called_urls

    @pytest.mark.asyncio
    async def test_invalid_inline_spec_text_degrades_scan_instead_of_aborting(self):
        svc, db = await _make_service()
        run_checks_mock = AsyncMock(return_value=[])
        await db.scans.insert_one({"scan_id": "scan-oa-8", "state": "PENDING"})
        with patch("app.domain.analysis.dast.session.DastSessionPair", _FakeSessionPair), \
             patch("app.domain.analysis.dast.crawler.crawl", AsyncMock(return_value=CrawlResult(urls=[TARGET]))), \
             patch("app.domain.analysis.dast.checks.run_payload_checks", run_checks_mock), \
             patch("app.domain.analysis.dast.logout_discovery.discover_logout_url", AsyncMock(return_value=None)):
            await svc._run_dynamic_scan(
                "scan-oa-8", TARGET, dynamic_openapi_spec="{[ this is not valid JSON or YAML :::",
            )

        doc = await db.scans.find_one({"scan_id": "scan-oa-8"})
        assert doc["state"] == "COMPLETED"
        called_urls = run_checks_mock.call_args.args[1]
        assert called_urls == [TARGET]
