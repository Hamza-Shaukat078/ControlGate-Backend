"""JWT algorithm confusion (Phase 3, item 5) — against httpx.MockTransport,
no real network calls. RSA key generation for the key-confusion variant
uses the real `cryptography` library (already a dependency via
python-jose[cryptography]) but never talks to a real JWKS endpoint; the
mock handler serves a fabricated JWKS response instead.
"""
import base64
import json

import httpx
import pytest

from app.domain.analysis.dast.config import ActorConfig, AuthMode
from app.domain.analysis.dast.jwt_probe import run_jwt_probe
from app.domain.analysis.dast.session import DastSession
from app.domain.analysis.dast.verdict import Verdict

TARGET = "https://target.example/api/profile"


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def _make_jwt(header: dict, payload: dict, sig: str = "realsig") -> str:
    return f"{_b64(header)}.{_b64(payload)}.{sig}"


def _session(handler, bearer_token: str = None) -> DastSession:
    actor = (
        ActorConfig(auth_mode=AuthMode.BEARER, bearer_token=bearer_token)
        if bearer_token else ActorConfig(auth_mode=AuthMode.NONE)
    )
    return DastSession(actor, resolve=False, transport=httpx.MockTransport(handler))


class TestGating:
    @pytest.mark.asyncio
    async def test_skipped_without_active_mode_by_default(self):
        token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "u1"})
        async with _session(lambda r: httpx.Response(200), bearer_token=token) as session:
            finding = await run_jwt_probe(session, TARGET)
        assert finding.verdict == Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION

    @pytest.mark.asyncio
    async def test_no_bearer_session_is_not_configured(self):
        async with _session(lambda r: httpx.Response(200)) as session:
            finding = await run_jwt_probe(session, TARGET, active_mode=True)
        assert finding.verdict == Verdict.NOT_CONFIGURED

    @pytest.mark.asyncio
    async def test_malformed_token_is_not_configured(self):
        async with _session(lambda r: httpx.Response(200), bearer_token="not-a-real-jwt") as session:
            finding = await run_jwt_probe(session, TARGET, active_mode=True)
        assert finding.verdict == Verdict.NOT_CONFIGURED

    @pytest.mark.asyncio
    async def test_baseline_not_2xx_is_not_tested(self):
        token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "u1"})
        async with _session(lambda r: httpx.Response(403), bearer_token=token) as session:
            finding = await run_jwt_probe(session, TARGET, active_mode=True)
        assert finding.verdict == Verdict.NOT_TESTED


class TestAlgNoneForgery:
    @pytest.mark.asyncio
    async def test_accepted_forged_token_confirms(self):
        real_token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "u1"})

        def handler(request: httpx.Request) -> httpx.Response:
            auth = request.headers.get("authorization", "")
            if auth == f"Bearer {real_token}":
                return httpx.Response(200, text="profile data")
            if auth.startswith("Bearer "):
                # Server accepts any bearer-shaped token regardless of alg —
                # the vulnerability this check exists to catch.
                return httpx.Response(200, text="profile data (forged)")
            return httpx.Response(401)

        async with _session(handler, bearer_token=real_token) as session:
            finding = await run_jwt_probe(session, TARGET, active_mode=True)

        assert finding.verdict == Verdict.CONFIRMED
        assert finding.evidence_type == "data_exfil"
        assert finding.proof["variant"] == "alg_none"
        assert finding.reproduction is not None

    @pytest.mark.asyncio
    async def test_rejected_forged_token_passes(self):
        real_token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "u1"})

        def handler(request: httpx.Request) -> httpx.Response:
            auth = request.headers.get("authorization", "")
            if auth == f"Bearer {real_token}":
                return httpx.Response(200, text="profile data")
            return httpx.Response(401)

        async with _session(handler, bearer_token=real_token) as session:
            finding = await run_jwt_probe(session, TARGET, active_mode=True)

        assert finding.verdict == Verdict.PASS

    @pytest.mark.asyncio
    async def test_hs256_token_never_attempts_key_confusion(self):
        # No RSA/EC alg -> no JWKS lookup at all; the mock handler 500s any
        # request to a JWKS-shaped path so this test fails loudly if the
        # check tries one anyway.
        real_token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "u1"})

        def handler(request: httpx.Request) -> httpx.Response:
            if "jwks" in request.url.path or "openid-configuration" in request.url.path:
                return httpx.Response(500)
            auth = request.headers.get("authorization", "")
            if auth == f"Bearer {real_token}":
                return httpx.Response(200, text="profile data")
            return httpx.Response(401)

        async with _session(handler, bearer_token=real_token) as session:
            finding = await run_jwt_probe(session, TARGET, active_mode=True)

        assert finding.verdict == Verdict.PASS


class TestHs256KeyConfusion:
    @pytest.mark.asyncio
    async def test_rs256_token_with_discoverable_jwks_confirms_via_key_confusion(self):
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = private_key.public_key().public_numbers()

        def _b64_int(value: int) -> str:
            length = (value.bit_length() + 7) // 8
            return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode()

        jwk = {"kty": "RSA", "n": _b64_int(numbers.n), "e": _b64_int(numbers.e)}
        real_token = _make_jwt({"alg": "RS256", "typ": "JWT"}, {"sub": "u1"})

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/.well-known/jwks.json":
                return httpx.Response(200, json={"keys": [jwk]})
            auth = request.headers.get("authorization", "")
            if auth == f"Bearer {real_token}":
                return httpx.Response(200, text="profile data")
            if auth.startswith("Bearer "):
                forged = auth.split(" ", 1)[1]
                header_b64 = forged.split(".")[0]
                padded = header_b64 + "=" * (-len(header_b64) % 4)
                header = json.loads(base64.urlsafe_b64decode(padded))
                if header.get("alg") == "HS256":
                    # Server naively honors the client-supplied alg and
                    # verifies with whatever key it looks up for this
                    # kid/issuer — treating the RSA public key's own bytes
                    # as a valid HMAC secret is exactly the confusion bug.
                    return httpx.Response(200, text="profile data (key confusion)")
                return httpx.Response(403)
            return httpx.Response(401)

        async with _session(handler, bearer_token=real_token) as session:
            finding = await run_jwt_probe(session, TARGET, active_mode=True)

        assert finding.verdict == Verdict.CONFIRMED
        assert finding.proof["variant"] == "hs256_key_confusion"

    @pytest.mark.asyncio
    async def test_rs256_token_without_discoverable_jwks_passes(self):
        real_token = _make_jwt({"alg": "RS256", "typ": "JWT"}, {"sub": "u1"})

        def handler(request: httpx.Request) -> httpx.Response:
            if "jwks" in request.url.path or "openid-configuration" in request.url.path:
                return httpx.Response(404)
            auth = request.headers.get("authorization", "")
            if auth == f"Bearer {real_token}":
                return httpx.Response(200, text="profile data")
            return httpx.Response(401)

        async with _session(handler, bearer_token=real_token) as session:
            finding = await run_jwt_probe(session, TARGET, active_mode=True)

        assert finding.verdict == Verdict.PASS
