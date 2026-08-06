"""Track C5 — REQUEST_SMUGGLING's only proof until now was that the raw-socket
code path (_send_raw_smuggling_probe) could complete a round trip against a
real TCP server (test_dast_live.py's test_smuggling_probe_completes_a_real_round_trip)
— never against a genuine front-end/back-end disagreement, because a single
naive http.server can't produce one (a real smuggling bug needs two hops that
parse HTTP framing differently from each other).

tests/fixtures/smuggling_proxy/ is that two-hop stack: one shared Python
backend behind two independently configured nginx front ends —
nginx-vulnerable.conf (pinned to nginx:1.18, predates nginx's own built-in
CL+TE ambiguity rejection, so the ambiguous request reaches the backend and
desyncs) and nginx-safe.conf (identical proxy_pass, plus an explicit
ambiguous-framing rejection — "the actual recommended-safe nginx setting").
See those two files' docstrings for exactly how the desync happens.

This file runs the *actual*, unmodified _check_request_smuggling (via
run_payload_checks, restricted to just that rule) against both front ends
and asserts the verdicts land where they should: FAIL against the vulnerable
one, PASS against the safe one. It found no bug in the existing probe —
manually verified end to end against this same stack before writing this
test (see session notes) — so unlike the track's contingency plan, no
checks.py change was needed here.
"""
from __future__ import annotations

import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

from app.domain.analysis.dast import session as session_module
from app.domain.analysis.dast.checks import run_payload_checks
from app.domain.analysis.dast.config import ActorConfig
from app.domain.analysis.dast.rule_loader import load_dynamic_queries
from app.domain.analysis.dast.session import DastSession
from app.domain.analysis.dast.verdict import Verdict

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "smuggling_proxy"
COMPOSE_FILE = FIXTURE_DIR / "docker-compose.yml"

# Fixed, not ephemeral — this is a docker-only, skip-if-unavailable test
# fixture (not part of the normal fast suite), and fixed ports keep the
# compose file/this test in sync without extra plumbing. A collision with
# something else already bound to these ports on the test host is possible
# but unlikely; if it happens, the fixture's readiness poll below will just
# time out and fail loudly rather than silently testing the wrong service.
VULNERABLE_PORT = 18091
SAFE_PORT = 18092

RULES = load_dynamic_queries(Path(__file__).resolve().parents[2] / "queries" / "dynamic_queries.json")
SMUGGLING_RULE = {"REQUEST_SMUGGLING": RULES["REQUEST_SMUGGLING"]}


def _docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        subprocess.run(["docker", "info"], capture_output=True, timeout=5, check=True)
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _docker_available(), reason="Docker not available in this environment")


def _wait_for_port(host: str, port: int, timeout: float = 60.0) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=2.0):
                return
        except OSError as exc:
            last_error = exc
            time.sleep(0.5)
    raise TimeoutError(f"{host}:{port} did not accept connections within {timeout}s (last error: {last_error})")


@pytest.fixture(scope="module")
def proxy_chain_stack():
    # up -d generously timed out: a cold image pull (nginx:1.18-alpine,
    # python:3.12-slim) can take a while in an environment without them
    # cached yet; readiness polling below has its own, tighter timeout once
    # the containers actually exist.
    subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "up", "-d"],
        cwd=FIXTURE_DIR, check=True, capture_output=True, timeout=300,
    )
    try:
        _wait_for_port("127.0.0.1", VULNERABLE_PORT)
        _wait_for_port("127.0.0.1", SAFE_PORT)
        yield {
            "vulnerable": f"http://127.0.0.1:{VULNERABLE_PORT}/",
            "safe": f"http://127.0.0.1:{SAFE_PORT}/",
        }
    finally:
        subprocess.run(
            ["docker", "compose", "-f", str(COMPOSE_FILE), "down", "-v"],
            cwd=FIXTURE_DIR, capture_output=True, timeout=60,
        )


@pytest.fixture(autouse=True)
def _allow_loopback_targets(monkeypatch):
    # Same rationale as test_dast_live.py: validate_public_http_url() rejects
    # loopback/private hosts by design (SSRF guard), correct for a real scan
    # but incompatible with this fixture's own loopback target.
    monkeypatch.setattr(session_module, "validate_public_http_url", lambda url, **kwargs: url)


class TestRequestSmugglingAgainstRealProxyChain:
    async def test_vulnerable_front_end_fails(self, proxy_chain_stack):
        target = proxy_chain_stack["vulnerable"]
        async with DastSession(ActorConfig()) as session:
            findings = await run_payload_checks(session, target, SMUGGLING_RULE, active_mode=True)

        finding = next(f for f in findings if f.rule_id == "REQUEST_SMUGGLING")
        assert finding.verdict == Verdict.FAIL, finding.note

    async def test_safe_front_end_passes(self, proxy_chain_stack):
        target = proxy_chain_stack["safe"]
        async with DastSession(ActorConfig()) as session:
            findings = await run_payload_checks(session, target, SMUGGLING_RULE, active_mode=True)

        finding = next(f for f in findings if f.rule_id == "REQUEST_SMUGGLING")
        assert finding.verdict == Verdict.PASS, finding.note
