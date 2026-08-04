"""SSRF probe (Track A2, V5.3.2) — the collaborator itself is real
(collaborator.py's own tests prove the socket plumbing), so these use a
lightweight fake with a controllable hits_for() to test the probe's own
control flow (gating, candidate iteration, wait, hit-checking) in
isolation, same "fake the collaborator, keep the session real (mocked
transport)" split test_scan_service_*.py uses for DastSessionPair.
"""
from dataclasses import dataclass
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from app.domain.analysis.dast.config import ActorConfig
from app.domain.analysis.dast.session import DastSession
from app.domain.analysis.dast.ssrf_probe import run_ssrf_probe
from app.domain.analysis.dast.verdict import Verdict

TARGET = "https://target.example/fetch"


@dataclass
class _FakeHit:
    remote_addr: str = "10.0.0.5"


class _FakeCollaborator:
    """Hands out predictable tokens ("token-1", "token-2", ...) in call
    order, so a test can precompute which candidate_params entry a given
    token belongs to and simulate a hit for exactly that one."""

    def __init__(self, hit_token: str = None):
        self._hit_token = hit_token
        self._counter = 0

    def new_token(self) -> str:
        self._counter += 1
        return f"token-{self._counter}"

    def callback_url(self, token: str) -> str:
        return f"http://collab.example/{token}"

    def hits_for(self, token: str):
        return [_FakeHit()] if token == self._hit_token else []


def _session(handler) -> DastSession:
    return DastSession(ActorConfig(), resolve=False, transport=httpx.MockTransport(handler))


class TestGating:
    @pytest.mark.asyncio
    async def test_skipped_without_active_mode_by_default(self):
        async with _session(lambda r: httpx.Response(200)) as session:
            finding = await run_ssrf_probe(session, TARGET, _FakeCollaborator())
        assert finding.verdict == Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION
        assert finding.control_id == "V5.3.2"


class TestSsrfDetection:
    @pytest.mark.asyncio
    async def test_callback_received_fails(self):
        # First candidate param ("url") gets token-1 — simulate a hit for it.
        collab = _FakeCollaborator(hit_token="token-1")

        async with _session(lambda r: httpx.Response(200)) as session:
            finding = await run_ssrf_probe(
                session, TARGET, collab, active_mode=True,
                callback_wait_seconds=0, candidate_params=["url", "webhook"],
            )

        assert finding.verdict == Verdict.FAIL
        assert "url" in finding.note
        assert "10.0.0.5" in finding.note

    @pytest.mark.asyncio
    async def test_no_callback_received_passes(self):
        collab = _FakeCollaborator(hit_token=None)

        async with _session(lambda r: httpx.Response(200)) as session:
            finding = await run_ssrf_probe(
                session, TARGET, collab, active_mode=True,
                callback_wait_seconds=0, candidate_params=["url", "webhook"],
            )

        assert finding.verdict == Verdict.PASS

    @pytest.mark.asyncio
    async def test_no_candidate_param_recognized_is_not_tested(self):
        collab = _FakeCollaborator()

        async with _session(lambda r: httpx.Response(404)) as session:
            finding = await run_ssrf_probe(
                session, TARGET, collab, active_mode=True,
                callback_wait_seconds=0, candidate_params=["url", "webhook"],
            )

        assert finding.verdict == Verdict.NOT_TESTED

    @pytest.mark.asyncio
    async def test_only_recognized_params_get_checked_for_hits(self):
        # 'url' 404s (unrecognized -> no token stored to check), 'webhook'
        # succeeds and gets token-2 — simulate a hit for token-2 specifically.
        collab = _FakeCollaborator(hit_token="token-2")

        def handler(request: httpx.Request) -> httpx.Response:
            if "url=" in str(request.url):
                return httpx.Response(404)
            return httpx.Response(200)

        async with _session(handler) as session:
            finding = await run_ssrf_probe(
                session, TARGET, collab, active_mode=True,
                callback_wait_seconds=0, candidate_params=["url", "webhook"],
            )

        assert finding.verdict == Verdict.FAIL
        assert "webhook" in finding.note

    @pytest.mark.asyncio
    async def test_request_exception_for_one_param_does_not_abort_others(self):
        collab = _FakeCollaborator(hit_token="token-2")

        def handler(request: httpx.Request) -> httpx.Response:
            if "url=" in str(request.url):
                raise httpx.ConnectError("boom")
            return httpx.Response(200)

        async with _session(handler) as session:
            finding = await run_ssrf_probe(
                session, TARGET, collab, active_mode=True,
                callback_wait_seconds=0, candidate_params=["url", "webhook"],
            )

        assert finding.verdict == Verdict.FAIL

    @pytest.mark.asyncio
    async def test_waits_before_checking_for_callbacks(self):
        collab = _FakeCollaborator(hit_token=None)
        with patch("app.domain.analysis.dast.ssrf_probe.asyncio.sleep", new=AsyncMock()) as sleep_mock:
            async with _session(lambda r: httpx.Response(200)) as session:
                await run_ssrf_probe(
                    session, TARGET, collab, active_mode=True,
                    callback_wait_seconds=1.5, candidate_params=["url"],
                )
        sleep_mock.assert_called_once_with(1.5)

    @pytest.mark.asyncio
    async def test_zero_wait_skips_sleep_call(self):
        collab = _FakeCollaborator(hit_token=None)
        with patch("app.domain.analysis.dast.ssrf_probe.asyncio.sleep", new=AsyncMock()) as sleep_mock:
            async with _session(lambda r: httpx.Response(200)) as session:
                await run_ssrf_probe(
                    session, TARGET, collab, active_mode=True,
                    callback_wait_seconds=0, candidate_params=["url"],
                )
        sleep_mock.assert_not_called()

    @pytest.mark.asyncio
    async def test_default_candidate_params_used_when_not_supplied(self):
        collab = _FakeCollaborator(hit_token=None)
        async with _session(lambda r: httpx.Response(200)) as session:
            finding = await run_ssrf_probe(session, TARGET, collab, active_mode=True, callback_wait_seconds=0)
        # 16 default candidates all recognized (handler always 200) -> PASS, not NOT_TESTED.
        assert finding.verdict == Verdict.PASS
