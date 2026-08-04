"""Race-condition probe (V2.3.4) — concurrent request fan-out, a different
execution shape than the sequential Scenario runner. All against
httpx.MockTransport; the handler uses a shared counter to simulate a server
that (correctly or buggily) allows only some concurrent requests through.
"""
import httpx
import pytest

from app.domain.analysis.dast.config import ActorConfig, AuthMode, DynamicScanConfig
from app.domain.analysis.dast.race_probe import RaceProbeConfig, run_race_probe
from app.domain.analysis.dast.session import DastSessionPair
from app.domain.analysis.dast.verdict import Verdict

TARGET = "https://target.example"


def _pair(handler) -> DastSessionPair:
    config = DynamicScanConfig(target_url=TARGET, actor=ActorConfig(auth_mode=AuthMode.NONE))
    return DastSessionPair(config, resolve=False, transport=httpx.MockTransport(handler))


class TestGating:
    @pytest.mark.asyncio
    async def test_skipped_without_active_mode_by_default(self):
        config = RaceProbeConfig(scenario_id="DOUBLE_REDEEM", url=f"{TARGET}/redeem")
        async with _pair(lambda r: httpx.Response(200)) as pair:
            finding = await run_race_probe(pair, config)  # active_mode defaults False
        assert finding.verdict == Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION
        assert finding.control_id == "V2.3.4"

    @pytest.mark.asyncio
    async def test_missing_secondary_session_is_not_configured(self):
        config = RaceProbeConfig(scenario_id="DOUBLE_REDEEM", url=f"{TARGET}/redeem", session="secondary")
        async with _pair(lambda r: httpx.Response(200)) as pair:
            finding = await run_race_probe(pair, config, active_mode=True)
        assert finding.verdict == Verdict.NOT_CONFIGURED


class TestRaceDetection:
    @pytest.mark.asyncio
    async def test_more_successes_than_expected_fails(self):
        state = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            state["count"] += 1
            # Buggy: allows the first 2 concurrent redemptions through.
            if state["count"] <= 2:
                return httpx.Response(200, text="redeemed")
            return httpx.Response(409, text="already redeemed")

        config = RaceProbeConfig(
            scenario_id="DOUBLE_REDEEM", url=f"{TARGET}/redeem", concurrency=5, max_expected_successes=1,
        )
        async with _pair(handler) as pair:
            finding = await run_race_probe(pair, config, active_mode=True)

        assert finding.verdict == Verdict.FAIL
        assert "2 of 5" in finding.note

    @pytest.mark.asyncio
    async def test_successes_within_expected_max_passes(self):
        state = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            state["count"] += 1
            if state["count"] <= 1:
                return httpx.Response(200, text="redeemed")
            return httpx.Response(409, text="already redeemed")

        config = RaceProbeConfig(
            scenario_id="DOUBLE_REDEEM", url=f"{TARGET}/redeem", concurrency=5, max_expected_successes=1,
        )
        async with _pair(handler) as pair:
            finding = await run_race_probe(pair, config, active_mode=True)

        assert finding.verdict == Verdict.PASS

    @pytest.mark.asyncio
    async def test_all_requests_failing_is_not_tested(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("boom")

        config = RaceProbeConfig(scenario_id="DOUBLE_REDEEM", url=f"{TARGET}/redeem", concurrency=3)
        async with _pair(handler) as pair:
            finding = await run_race_probe(pair, config, active_mode=True)

        assert finding.verdict == Verdict.NOT_TESTED

    @pytest.mark.asyncio
    async def test_fires_exactly_concurrency_requests(self):
        state = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            state["count"] += 1
            return httpx.Response(409)

        config = RaceProbeConfig(scenario_id="DOUBLE_REDEEM", url=f"{TARGET}/redeem", concurrency=7)
        async with _pair(handler) as pair:
            await run_race_probe(pair, config, active_mode=True)

        assert state["count"] == 7
