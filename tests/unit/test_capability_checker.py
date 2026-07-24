"""
Capability Checker tests — the LLM-judged "is X implemented (correctly)?"
side-channel for V6.2.2/.3/.4, V6.3.1, V6.4.1, V7.2.4, V7.4.1/.2, V14.3.1.
No real LLM calls: RoleAwareLLMPool.call is stubbed so these run offline/fast.
"""
import json
import pytest

from app.domain.analysis.capability_checker import (
    CapabilityChecker,
    _CAPABILITY_CHECKS,
    _select_candidates,
)


class _FakePool:
    """Stand-in for RoleAwareLLMPool — returns a canned response per call."""

    def __init__(self, response: str):
        self.is_available = True
        self._response = response
        self.calls = []

    async def call(self, messages, max_tokens=400, temperature=0.1, severity=""):
        self.calls.append(messages)
        return self._response


def _make_checker(response: str) -> CapabilityChecker:
    checker = CapabilityChecker()
    checker._pool = _FakePool(response)
    return checker


class TestCandidateSelection:
    def test_keyword_match_selects_file(self):
        source_map = {"app/auth.py": "def logout():\n    session.clear()\n"}
        candidates = _select_candidates(source_map, _CAPABILITY_CHECKS["V7.4.1"]["keywords"])
        assert candidates and candidates[0][0] == "app/auth.py"

    def test_topical_filename_selects_file_even_without_keyword(self):
        source_map = {"app/session_utils.py": "def helper():\n    pass\n"}
        candidates = _select_candidates(source_map, _CAPABILITY_CHECKS["V7.4.1"]["keywords"])
        assert candidates  # matched via "session" in the filename, not a keyword hit

    def test_unrelated_file_not_selected(self):
        source_map = {"app/math_utils.py": "def add(a, b):\n    return a + b\n"}
        candidates = _select_candidates(source_map, _CAPABILITY_CHECKS["V7.4.1"]["keywords"])
        assert candidates == []


class TestCheckOneControl:
    @pytest.mark.asyncio
    async def test_implemented_correctly_yields_pass(self):
        # Deliberately neutral filename/content: uniquely trips V7.4.1's keyword
        # ("session.clear") without the topical filename net or another control's
        # keyword list also matching, so this isolates the one control cleanly.
        response = json.dumps({
            "implemented": True, "correct": True,
            "file": "app/cleanup.py", "line": 2,
            "explanation": "end_session() calls session.clear() before returning.",
        })
        checker = _make_checker(response)
        source_map = {"app/cleanup.py": "def end_session():\n    session.clear()\n    return True\n"}
        findings = await checker.check(source_map)
        assert len(findings) == 1
        f = findings[0]
        assert f.control_id == "V7.4.1"
        assert f.verdict == "pass"
        assert f.file == "app/cleanup.py"
        assert f.line == 2

    @pytest.mark.asyncio
    async def test_implemented_incorrectly_yields_fail(self):
        # "old_password" only appears in V6.2.3's keyword list (V6.2.2 uses
        # change_password/update_password/etc.), and the filename avoids every
        # topical hint, so only V6.2.3 is a candidate here.
        response = json.dumps({
            "implemented": True, "correct": False,
            "file": "app/creds.py", "line": 1,
            "explanation": "rotate() accepts a new secret with no old_password check.",
        })
        checker = _make_checker(response)
        source_map = {"app/creds.py": "def rotate(old_password, incoming):\n    pass\n"}
        findings = await checker.check(source_map)
        assert len(findings) == 1
        assert findings[0].verdict == "fail"
        assert findings[0].control_id == "V6.2.3"

    @pytest.mark.asyncio
    async def test_not_implemented_yields_no_finding(self):
        response = json.dumps({"implemented": False, "correct": False, "file": None, "line": None, "explanation": "No evidence found."})
        checker = _make_checker(response)
        source_map = {"app/auth.py": "def old_password_check():\n    pass\n"}
        findings = await checker.check(source_map)
        assert findings == []

    @pytest.mark.asyncio
    async def test_no_candidate_files_means_no_llm_call(self):
        checker = _make_checker(json.dumps({"implemented": True, "correct": True}))
        source_map = {"app/math_utils.py": "def add(a, b):\n    return a + b\n"}
        findings = await checker.check(source_map)
        assert findings == []
        assert checker._pool.calls == []

    @pytest.mark.asyncio
    async def test_malformed_llm_response_is_skipped_not_raised(self):
        checker = _make_checker("not valid json at all")
        source_map = {"app/auth.py": "def logout():\n    session.clear()\n"}
        findings = await checker.check(source_map)
        assert findings == []  # degrades gracefully, doesn't raise
