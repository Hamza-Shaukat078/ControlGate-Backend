"""Cross-session IDOR probe (V8.2.1) — two independently authenticated
DastSession actors, own MockTransport handler that branches on which
Authorization header made the request (so the test can tell owner vs.
second-actor requests apart, like a real ownership-checking server would).
"""
import httpx
import pytest

from app.domain.analysis.dast.config import ActorConfig, AuthMode, DynamicScanConfig
from app.domain.analysis.dast.idor_probe import IdorProbeConfig, run_idor_probe
from app.domain.analysis.dast.session import DastSessionPair
from app.domain.analysis.dast.verdict import Verdict

TARGET = "https://target.example"
OWNER_TOKEN = "owner-token"
OTHER_TOKEN = "other-token"


def _pair(handler, *, with_secondary: bool = True) -> DastSessionPair:
    config = DynamicScanConfig(
        target_url=TARGET,
        actor=ActorConfig(auth_mode=AuthMode.BEARER, bearer_token=OWNER_TOKEN),
        second_actor=ActorConfig(auth_mode=AuthMode.BEARER, bearer_token=OTHER_TOKEN) if with_secondary else None,
    )
    return DastSessionPair(config, resolve=False, transport=httpx.MockTransport(handler))


def _ownership_enforced_handler(request: httpx.Request) -> httpx.Response:
    auth = request.headers.get("authorization", "")
    if OWNER_TOKEN in auth:
        return httpx.Response(200, json={"id": 42, "secret": "owner data"})
    return httpx.Response(403, text="forbidden")


def _no_ownership_check_handler(request: httpx.Request) -> httpx.Response:
    # Vulnerable: any authenticated caller gets the resource regardless of token.
    return httpx.Response(200, json={"id": 42, "secret": "owner data"})


class TestGating:
    @pytest.mark.asyncio
    async def test_get_does_not_require_active_mode(self):
        config = IdorProbeConfig(scenario_id="IDOR_ORDER", owner_resource_url=f"{TARGET}/orders/42")
        async with _pair(_ownership_enforced_handler) as pair:
            finding = await run_idor_probe(pair, config)  # active_mode defaults False
        assert finding.verdict != Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION

    @pytest.mark.asyncio
    async def test_mutating_method_requires_active_mode_by_default(self):
        config = IdorProbeConfig(
            scenario_id="IDOR_DELETE_ORDER", owner_resource_url=f"{TARGET}/orders/42", method="DELETE",
        )
        async with _pair(_ownership_enforced_handler) as pair:
            finding = await run_idor_probe(pair, config)  # active_mode defaults False
        assert finding.verdict == Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION

    @pytest.mark.asyncio
    async def test_mutating_method_runs_when_active_mode_enabled(self):
        config = IdorProbeConfig(
            scenario_id="IDOR_DELETE_ORDER", owner_resource_url=f"{TARGET}/orders/42", method="DELETE",
        )
        async with _pair(_ownership_enforced_handler) as pair:
            finding = await run_idor_probe(pair, config, active_mode=True)
        assert finding.verdict != Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION

    @pytest.mark.asyncio
    async def test_explicit_requires_active_mode_overrides_method_inference(self):
        config = IdorProbeConfig(
            scenario_id="IDOR_ORDER", owner_resource_url=f"{TARGET}/orders/42",
            requires_active_mode=True,  # GET, but caller forces the gate on anyway
        )
        async with _pair(_ownership_enforced_handler) as pair:
            finding = await run_idor_probe(pair, config)
        assert finding.verdict == Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION

    @pytest.mark.asyncio
    async def test_missing_second_actor_is_not_configured(self):
        config = IdorProbeConfig(scenario_id="IDOR_ORDER", owner_resource_url=f"{TARGET}/orders/42")
        async with _pair(_ownership_enforced_handler, with_secondary=False) as pair:
            finding = await run_idor_probe(pair, config)
        assert finding.verdict == Verdict.NOT_CONFIGURED
        assert finding.control_id == "V8.2.1"


class TestIdorDetection:
    @pytest.mark.asyncio
    async def test_second_actor_denied_passes(self):
        config = IdorProbeConfig(scenario_id="IDOR_ORDER", owner_resource_url=f"{TARGET}/orders/42")
        async with _pair(_ownership_enforced_handler) as pair:
            finding = await run_idor_probe(pair, config)
        assert finding.verdict == Verdict.PASS

    @pytest.mark.asyncio
    async def test_second_actor_granted_fails(self):
        config = IdorProbeConfig(scenario_id="IDOR_ORDER", owner_resource_url=f"{TARGET}/orders/42")
        async with _pair(_no_ownership_check_handler) as pair:
            finding = await run_idor_probe(pair, config)
        assert finding.verdict == Verdict.FAIL
        assert "42" in finding.note or "no ownership check" in finding.note

    @pytest.mark.asyncio
    async def test_owner_baseline_failure_is_not_tested(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, text="not found")

        config = IdorProbeConfig(scenario_id="IDOR_ORDER", owner_resource_url=f"{TARGET}/orders/42")
        async with _pair(handler) as pair:
            finding = await run_idor_probe(pair, config)
        assert finding.verdict == Verdict.NOT_TESTED

    @pytest.mark.asyncio
    async def test_owner_request_exception_is_not_tested(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("boom")

        config = IdorProbeConfig(scenario_id="IDOR_ORDER", owner_resource_url=f"{TARGET}/orders/42")
        async with _pair(handler) as pair:
            finding = await run_idor_probe(pair, config)
        assert finding.verdict == Verdict.NOT_TESTED

    @pytest.mark.asyncio
    async def test_ambiguous_second_actor_status_is_inconclusive(self):
        def handler(request: httpx.Request) -> httpx.Response:
            auth = request.headers.get("authorization", "")
            if OWNER_TOKEN in auth:
                return httpx.Response(200, json={"id": 42})
            return httpx.Response(500, text="server error")

        config = IdorProbeConfig(scenario_id="IDOR_ORDER", owner_resource_url=f"{TARGET}/orders/42")
        async with _pair(handler) as pair:
            finding = await run_idor_probe(pair, config)
        assert finding.verdict == Verdict.INCONCLUSIVE

    @pytest.mark.asyncio
    async def test_default_control_id_is_v8_2_1(self):
        config = IdorProbeConfig(scenario_id="IDOR_ORDER", owner_resource_url=f"{TARGET}/orders/42")
        async with _pair(_ownership_enforced_handler) as pair:
            finding = await run_idor_probe(pair, config)
        assert finding.control_id == "V8.2.1"
