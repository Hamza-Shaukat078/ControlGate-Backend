"""
Dynamic Probe — ASVS 5.0.0 L1 live-deployment checks.

Unlike every other detection module in this backend, these controls can't be
answered from source code or repo config at all — they're properties of the
*running* deployment (negotiated TLS version, whether HTTPS is enforced, the
certificate actually served, response headers, whether debug artifacts are
reachable). This module only runs when the user supplies a live target URL
for the scan; it is opt-in, not part of the default source-only scan.

All probes are read-only (TLS handshakes and plain GET requests) against a
target the user owns and is submitting for their own compliance scan — no
exploitation, no fuzzing, no write requests.

Controls covered:
  V12.1.1  Only TLS 1.2/1.3 enabled (bonus: legacy protocols actively rejected)
  V12.2.1  HTTPS enforced, no plaintext fallback
  V12.2.2  Publicly trusted TLS certificate
  V3.4.1   HSTS header on the live response (cross-checks ConfigInspector's static reading)
  V13.4.1  .git / .svn metadata not exposed
"""
import asyncio
import logging
import re
import socket
import ssl
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit

import httpx

logger = logging.getLogger(__name__)

_ONE_YEAR_SECONDS = 31_536_000
CONNECT_TIMEOUT_SECONDS = 6.0
HTTP_TIMEOUT_SECONDS = 8.0


@dataclass
class ProbeFinding:
    control_id: str
    verdict: str  # "pass" | "fail" | "not_tested"
    note: str
    confidence: float = 0.8


def _parse_target(target_url: str) -> tuple[str, int, str]:
    parts = urlsplit(target_url if "://" in target_url else f"https://{target_url}")
    host = parts.hostname or target_url
    scheme = parts.scheme or "https"
    port = parts.port or (443 if scheme == "https" else 80)
    return host, port, scheme


class DynamicProbe:
    async def probe(self, target_url: str) -> list[ProbeFinding]:
        host, port, scheme = _parse_target(target_url)
        base_url = f"{scheme}://{host}" + (f":{port}" if port not in (80, 443) else "")

        checks = [
            self._check_tls_version(host, port),
            self._check_cert_trust(host, port),
            self._check_https_enforcement(host),
            self._check_hsts_header(base_url),
            self._check_git_exposure(base_url),
        ]
        results = await asyncio.gather(*checks, return_exceptions=True)

        findings: list[ProbeFinding] = []
        for r in results:
            if isinstance(r, ProbeFinding):
                findings.append(r)
            elif isinstance(r, Exception):
                logger.warning(f"Dynamic probe check raised unexpectedly: {r}")
        return findings

    # ── V12.1.1 — TLS protocol version ───────────────────────────────────────

    async def _check_tls_version(self, host: str, port: int) -> ProbeFinding:
        try:
            negotiated = await asyncio.wait_for(
                asyncio.to_thread(self._negotiate_tls_version, host, port, None),
                timeout=CONNECT_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            return ProbeFinding("V12.1.1", "not_tested", f"Could not establish a TLS connection to {host}:{port}: {exc}", confidence=0.3)

        if negotiated not in ("TLSv1.3", "TLSv1.2"):
            return ProbeFinding("V12.1.1", "fail", f"Negotiated protocol was {negotiated}, not TLS 1.2/1.3", confidence=0.85)

        # Bonus: confirm the server actually rejects a legacy protocol offer,
        # not just that it *supports* a modern one alongside old ones.
        legacy_accepted = None
        try:
            legacy_accepted = await asyncio.wait_for(
                asyncio.to_thread(self._negotiate_tls_version, host, port, ssl.TLSVersion.TLSv1),
                timeout=CONNECT_TIMEOUT_SECONDS,
            )
        except Exception:
            legacy_accepted = None  # handshake failure = legacy rejected, which is what we want

        if legacy_accepted:
            return ProbeFinding(
                "V12.1.1", "fail",
                f"Server negotiated {negotiated} by default but also accepted a legacy protocol offer ({legacy_accepted})",
                confidence=0.8,
            )
        return ProbeFinding("V12.1.1", "pass", f"Negotiated {negotiated}; legacy protocol offers were rejected", confidence=0.85)

    @staticmethod
    def _negotiate_tls_version(host: str, port: int, max_version: Optional["ssl.TLSVersion"]) -> Optional[str]:
        context = ssl.create_default_context()
        if max_version is not None:
            context.maximum_version = max_version
            context.minimum_version = max_version
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT_SECONDS) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                return tls_sock.version()

    # ── V12.2.2 — certificate trust ──────────────────────────────────────────

    async def _check_cert_trust(self, host: str, port: int) -> ProbeFinding:
        try:
            await asyncio.wait_for(
                asyncio.to_thread(self._verify_trusted_cert, host, port),
                timeout=CONNECT_TIMEOUT_SECONDS,
            )
        except ssl.SSLCertVerificationError as exc:
            return ProbeFinding("V12.2.2", "fail", f"Certificate is not publicly trusted: {exc}", confidence=0.9)
        except Exception as exc:
            return ProbeFinding("V12.2.2", "not_tested", f"Could not verify certificate for {host}:{port}: {exc}", confidence=0.3)
        return ProbeFinding("V12.2.2", "pass", "Certificate validated against the system trust store", confidence=0.85)

    @staticmethod
    def _verify_trusted_cert(host: str, port: int) -> None:
        context = ssl.create_default_context()  # validates against the system CA trust store
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT_SECONDS) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                pass  # handshake succeeding without SSLCertVerificationError is the assertion

    # ── V12.2.1 — HTTPS enforcement ───────────────────────────────────────────

    async def _check_https_enforcement(self, host: str) -> ProbeFinding:
        # Standard convention: a plaintext listener alongside HTTPS lives on port 80
        # regardless of what non-standard HTTPS port was originally targeted.
        http_url = f"http://{host}"
        try:
            async with httpx.AsyncClient(follow_redirects=False, timeout=HTTP_TIMEOUT_SECONDS) as client:
                resp = await client.get(http_url)
        except (httpx.ConnectError, httpx.ConnectTimeout):
            return ProbeFinding("V12.2.1", "pass", "Plaintext HTTP port did not accept connections", confidence=0.75)
        except Exception as exc:
            return ProbeFinding("V12.2.1", "not_tested", f"Could not probe {http_url}: {exc}", confidence=0.3)

        if resp.status_code in (301, 302, 307, 308):
            location = resp.headers.get("location", "")
            if location.startswith("https://"):
                return ProbeFinding("V12.2.1", "pass", f"HTTP redirects to HTTPS ({location})", confidence=0.85)
            return ProbeFinding("V12.2.1", "fail", f"HTTP redirect target is not HTTPS: {location}", confidence=0.7)

        return ProbeFinding("V12.2.1", "fail", f"Plaintext HTTP served content directly (status {resp.status_code}) instead of redirecting to HTTPS", confidence=0.8)

    # ── V3.4.1 — live HSTS header ─────────────────────────────────────────────

    async def _check_hsts_header(self, base_url: str) -> ProbeFinding:
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS, verify=True) as client:
                resp = await client.get(base_url)
        except Exception as exc:
            return ProbeFinding("V3.4.1", "not_tested", f"Could not fetch {base_url}: {exc}", confidence=0.3)

        hsts = resp.headers.get("strict-transport-security")
        if not hsts:
            return ProbeFinding("V3.4.1", "fail", "No Strict-Transport-Security header on the live response", confidence=0.8)

        m = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
        if not m:
            return ProbeFinding("V3.4.1", "fail", f"Strict-Transport-Security header present but no max-age found: {hsts}", confidence=0.6)

        seconds = int(m.group(1))
        verdict = "pass" if seconds >= _ONE_YEAR_SECONDS else "fail"
        return ProbeFinding("V3.4.1", verdict, f"Live HSTS max-age={seconds} ({'meets' if verdict == 'pass' else 'below'} the 1-year minimum)", confidence=0.85)

    # ── V13.4.1 — .git / .svn exposure ────────────────────────────────────────

    async def _check_git_exposure(self, base_url: str) -> ProbeFinding:
        probes = [
            (f"{base_url}/.git/HEAD", "ref: refs/"),
            (f"{base_url}/.svn/entries", None),
            (f"{base_url}/.svn/wc.db", None),
        ]
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
                for url, signature in probes:
                    try:
                        resp = await client.get(url)
                    except Exception:
                        continue
                    if resp.status_code == 200 and (signature is None or signature in resp.text[:200]):
                        return ProbeFinding("V13.4.1", "fail", f"Source-control metadata reachable at {url}", confidence=0.9)
        except Exception as exc:
            return ProbeFinding("V13.4.1", "not_tested", f"Could not probe {base_url}: {exc}", confidence=0.3)

        return ProbeFinding("V13.4.1", "pass", "No .git/.svn metadata reachable at common paths", confidence=0.7)
