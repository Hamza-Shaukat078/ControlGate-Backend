"""Mass assignment probe (V15.3.3, Phase 3 item 7) — against a fake
DastSessionPair (real socket plumbing is DastSession's/collaborator.py's
own concern), same "fake the pair, exercise the probe's own control flow"
split test_dast_idor_probe.py/test_dast_race_probe.py use.
"""
from dataclasses import dataclass
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock

import pytest

from app.domain.analysis.dast.mass_assignment_probe import (
    MassAssignmentProbeConfig,
    run_mass_assignment_probe,
)
from app.domain.analysis.dast.verdict import Verdict

TARGET = "https://target.example/profile"


@dataclass
class _FakeResponse:
    status_code: int
    _json: Optional[Dict[str, Any]] = None

    def json(self):
        if self._json is None:
            raise ValueError("not json")
        return self._json


class _FakeSession:
    def __init__(self, responses):
        # responses: list of _FakeResponse or Exception, consumed in order.
        self._responses = list(responses)
        self.requests = []

    def redact(self, text: str) -> str:
        return text

    async def request(self, method, url, **kwargs):
        self.requests.append((method, url, kwargs))
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class _FakePair:
    def __init__(self, primary=None, secondary=None):
        self.primary = primary
        self.secondary = secondary


def _config(**overrides) -> MassAssignmentProbeConfig:
    base = dict(scenario_id="MA1", update_url=TARGET)
    base.update(overrides)
    return MassAssignmentProbeConfig(**base)


class TestGating:
    @pytest.mark.asyncio
    async def test_skipped_without_active_mode_by_default(self):
        pair = _FakePair(primary=_FakeSession([]), secondary=_FakeSession([]))
        finding = await run_mass_assignment_probe(pair, _config())
        assert finding.verdict == Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION

    @pytest.mark.asyncio
    async def test_no_secondary_actor_is_not_configured(self):
        pair = _FakePair(primary=_FakeSession([]), secondary=None)
        finding = await run_mass_assignment_probe(pair, _config(), active_mode=True)
        assert finding.verdict == Verdict.NOT_CONFIGURED


class TestBaselineHandling:
    @pytest.mark.asyncio
    async def test_baseline_404_is_not_tested(self):
        pair = _FakePair(primary=_FakeSession([]), secondary=_FakeSession([_FakeResponse(404)]))
        finding = await run_mass_assignment_probe(pair, _config(), active_mode=True)
        assert finding.verdict == Verdict.NOT_TESTED

    @pytest.mark.asyncio
    async def test_non_json_baseline_is_not_tested(self):
        pair = _FakePair(primary=_FakeSession([]), secondary=_FakeSession([_FakeResponse(200, None)]))
        finding = await run_mass_assignment_probe(pair, _config(), active_mode=True)
        assert finding.verdict == Verdict.NOT_TESTED

    @pytest.mark.asyncio
    async def test_already_privileged_baseline_is_inconclusive(self):
        pair = _FakePair(
            primary=_FakeSession([]),
            secondary=_FakeSession([_FakeResponse(200, {"role": "admin"})]),
        )
        finding = await run_mass_assignment_probe(pair, _config(), active_mode=True)
        assert finding.verdict == Verdict.INCONCLUSIVE


class TestConfirmation:
    @pytest.mark.asyncio
    async def test_privileged_field_took_confirms(self):
        secondary = _FakeSession([
            _FakeResponse(200, {"role": "user"}),   # baseline
            _FakeResponse(200, {"role": "admin"}),  # after re-read
        ])
        primary = _FakeSession([_FakeResponse(200)])  # submit
        pair = _FakePair(primary=primary, secondary=secondary)

        finding = await run_mass_assignment_probe(pair, _config(), active_mode=True)

        assert finding.verdict == Verdict.CONFIRMED
        assert finding.evidence_type == "response_diff"
        assert finding.proof["baseline_value"] == "user"
        assert finding.proof["after_value"] == "admin"
        assert finding.reproduction is not None
        # Submission went through primary, verification through secondary —
        # never trusts the submitter's own view of the change.
        assert primary.requests[0][0] == "PATCH"
        assert secondary.requests[0][0] == "GET"
        assert secondary.requests[1][0] == "GET"

    @pytest.mark.asyncio
    async def test_privileged_field_did_not_take_passes(self):
        secondary = _FakeSession([
            _FakeResponse(200, {"role": "user"}),
            _FakeResponse(200, {"role": "user"}),
        ])
        primary = _FakeSession([_FakeResponse(200)])
        pair = _FakePair(primary=primary, secondary=secondary)

        finding = await run_mass_assignment_probe(pair, _config(), active_mode=True)

        assert finding.verdict == Verdict.PASS

    @pytest.mark.asyncio
    async def test_nested_field_path_supported(self):
        secondary = _FakeSession([
            _FakeResponse(200, {"user": {"role": "user"}}),
            _FakeResponse(200, {"user": {"role": "admin"}}),
        ])
        primary = _FakeSession([_FakeResponse(200)])
        pair = _FakePair(primary=primary, secondary=secondary)

        finding = await run_mass_assignment_probe(
            pair, _config(verify_field_path="user.role"), active_mode=True,
        )

        assert finding.verdict == Verdict.CONFIRMED

    @pytest.mark.asyncio
    async def test_submit_request_uses_baseline_fields_plus_injected_field(self):
        secondary = _FakeSession([
            _FakeResponse(200, {"role": "user"}),
            _FakeResponse(200, {"role": "user"}),
        ])
        primary = _FakeSession([_FakeResponse(200)])
        pair = _FakePair(primary=primary, secondary=secondary)

        await run_mass_assignment_probe(
            pair, _config(baseline_fields={"display_name": "New Name"}), active_mode=True,
        )

        method, url, kwargs = primary.requests[0]
        assert kwargs["json"] == {"display_name": "New Name", "role": "admin"}

    @pytest.mark.asyncio
    async def test_verify_url_defaults_to_update_url(self):
        secondary = _FakeSession([
            _FakeResponse(200, {"role": "user"}),
            _FakeResponse(200, {"role": "user"}),
        ])
        primary = _FakeSession([_FakeResponse(200)])
        pair = _FakePair(primary=primary, secondary=secondary)

        await run_mass_assignment_probe(pair, _config(), active_mode=True)

        assert secondary.requests[0][1] == TARGET

    @pytest.mark.asyncio
    async def test_separate_verify_url_is_used(self):
        secondary = _FakeSession([
            _FakeResponse(200, {"role": "user"}),
            _FakeResponse(200, {"role": "user"}),
        ])
        primary = _FakeSession([_FakeResponse(200)])
        pair = _FakePair(primary=primary, secondary=secondary)
        verify_url = "https://target.example/profile/me"

        await run_mass_assignment_probe(pair, _config(verify_url=verify_url), active_mode=True)

        assert secondary.requests[0][1] == verify_url
        assert secondary.requests[1][1] == verify_url
