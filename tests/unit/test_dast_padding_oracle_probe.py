"""Timing-comparison probe (V11.2.5) — sends two fixed payload variants
repeatedly and checks whether response timing distinguishes them. All
against httpx.MockTransport; the handler simulates a timing side channel
by actually sleeping different amounts per variant (real time.sleep would
make this test slow/flaky, so timing is instead driven deterministically
via time.monotonic() patching, same technique test_dast_oracles.py uses).
"""
import httpx
import pytest

from app.domain.analysis.dast.config import ActorConfig, AuthMode, DynamicScanConfig
from app.domain.analysis.dast.padding_oracle_probe import (
    TimingComparisonProbeConfig,
    TimingProbeVariant,
    run_timing_comparison_probe,
)
from app.domain.analysis.dast.session import DastSessionPair
from app.domain.analysis.dast.verdict import Verdict

TARGET = "https://target.example"


def _pair(handler) -> DastSessionPair:
    config = DynamicScanConfig(target_url=TARGET, actor=ActorConfig(auth_mode=AuthMode.NONE))
    return DastSessionPair(config, resolve=False, transport=httpx.MockTransport(handler))


def _config(**overrides) -> TimingComparisonProbeConfig:
    base = dict(
        scenario_id="PADDING_ORACLE_CHECK",
        url=f"{TARGET}/decrypt",
        variant_a=TimingProbeVariant(data={"ciphertext": "aaaa-valid-padding-wrong-content"}),
        variant_b=TimingProbeVariant(data={"ciphertext": "bbbb-invalid-padding"}),
        samples=3,
    )
    base.update(overrides)
    return TimingComparisonProbeConfig(**base)


class TestGating:
    @pytest.mark.asyncio
    async def test_skipped_without_active_mode_by_default(self):
        async with _pair(lambda r: httpx.Response(200)) as pair:
            finding = await run_timing_comparison_probe(pair, _config())  # active_mode defaults False
        assert finding.verdict == Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION
        assert finding.control_id == "V11.2.5"

    @pytest.mark.asyncio
    async def test_missing_secondary_session_is_not_configured(self):
        async with _pair(lambda r: httpx.Response(200)) as pair:
            finding = await run_timing_comparison_probe(
                pair, _config(session="secondary"), active_mode=True,
            )
        assert finding.verdict == Verdict.NOT_CONFIGURED


class TestTimingDistinction:
    @pytest.mark.asyncio
    async def test_distinguishable_timing_fails(self, monkeypatch):
        import itertools
        import time as time_module

        # variant a always takes ~50ms, variant b always takes ~90ms —
        # sent in a/b/a/b order matching comparative_timing_oracle's
        # interleaving, so this clock sequence lines up 1:1 with requests.
        clock = itertools.chain.from_iterable([0.0, 0.050, 0.0, 0.090] for _ in range(10))
        monkeypatch.setattr(time_module, "monotonic", lambda: next(clock))

        async with _pair(lambda r: httpx.Response(200, text="ok")) as pair:
            finding = await run_timing_comparison_probe(pair, _config(), active_mode=True)

        assert finding.verdict == Verdict.FAIL
        assert finding.control_id == "V11.2.5"
        assert finding.proof["delta_ms"] == pytest.approx(40.0, abs=0.5)

    @pytest.mark.asyncio
    async def test_identical_timing_passes(self, monkeypatch):
        import itertools
        import time as time_module

        clock = itertools.chain.from_iterable([0.0, 0.050, 0.0, 0.050] for _ in range(10))
        monkeypatch.setattr(time_module, "monotonic", lambda: next(clock))

        async with _pair(lambda r: httpx.Response(200, text="ok")) as pair:
            finding = await run_timing_comparison_probe(pair, _config(), active_mode=True)

        assert finding.verdict == Verdict.PASS

    @pytest.mark.asyncio
    async def test_request_failure_is_not_tested(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("boom")

        async with _pair(handler) as pair:
            finding = await run_timing_comparison_probe(pair, _config(), active_mode=True)
        assert finding.verdict == Verdict.NOT_TESTED

    @pytest.mark.asyncio
    async def test_both_variants_actually_sent(self):
        seen_bodies = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_bodies.append(request.content)
            return httpx.Response(200)

        async with _pair(handler) as pair:
            await run_timing_comparison_probe(pair, _config(samples=2), active_mode=True)

        # 2 samples * (variant_a + variant_b) = 4 requests total.
        assert len(seen_bodies) == 4
        assert any(b"valid-padding-wrong-content" in b for b in seen_bodies)
        assert any(b"invalid-padding" in b for b in seen_bodies)
