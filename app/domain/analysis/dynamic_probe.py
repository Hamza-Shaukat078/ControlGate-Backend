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
  V12.1.3  mTLS client-certificate trust — best-effort (see note below)
  V12.2.1  HTTPS enforced, no plaintext fallback
  V12.2.2  Publicly trusted TLS certificate
  V12.3.4  Internal service-to-service TLS cert trust — best-effort (see note below)
  V3.3.5   Set-Cookie header name+value length does not exceed 4096 bytes
  V3.4.1   HSTS header on the live response (cross-checks ConfigInspector's static reading)
  V3.7.4   Domain is accepted for or already on the HSTS preload list
  V13.4.1  .git / .svn metadata not exposed
  V13.4.6  Backend component version info not exposed (Server/X-Powered-By headers)

V12.1.3 and V12.3.4 are best-effort: a black-box scanner has no legitimate
client certificate or internal CA to test with, so instead of skipping them
outright, each infers what it can from the target's TLS behavior alone and
reports not_tested where the target genuinely doesn't give it enough to go
on (see each check's docstring for the reasoning).

Evidence convention: every pass and fail below states the concrete
measurement or observation that produced the verdict (header values, byte
counts, cert subject/issuer/expiry, protocol names, paths checked) — a
reviewer reading `note` should be able to see *why* without re-running the
probe themselves. not_tested stays a short reason (there is nothing to show
evidence of yet).
"""
import asyncio
import logging
import os
import re
import socket
import ssl
import tempfile
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
    severity: str = "medium"


# Severity when this control's check fails — a property of what the check
# actually verifies, not of which branch inside it returned "fail", so it's
# assigned once in probe() below rather than duplicated across every
# ProbeFinding(...) call site. Reflects real-world impact: TLS/HTTPS/cert
# weaknesses and a leaked .git directory are directly exploitable; HSTS
# max-age is a real but narrower downgrade-attack window; HSTS preload
# status and version disclosure are hardening/reconnaissance gaps, not
# exploits on their own.
_CONTROL_SEVERITY = {
    "V12.1.1": "high",     # weak/legacy TLS protocol negotiated or accepted
    "V12.2.2": "high",     # untrusted/invalid TLS certificate
    "V12.2.1": "high",     # plaintext HTTP served instead of enforcing HTTPS
    "V13.4.1": "critical", # .git/.svn metadata reachable — source code leak
    "V3.4.1": "medium",    # HSTS missing or max-age below the 1-year minimum
    "V12.1.3": "medium",   # mTLS client-certificate trust not enforced
    "V12.3.4": "medium",   # internal service-to-service cert trust
    "V3.3.5": "low",       # oversized Set-Cookie header
    "V3.7.4": "low",       # not on the HSTS preload list (bonus hardening only)
    "V13.4.6": "low",      # Server/X-Powered-By version disclosure (recon aid, not an exploit)
}


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
            self._check_cookie_size(base_url),
            self._check_hsts_header(base_url),
            self._check_hsts_preload(host),
            self._check_git_exposure(base_url),
            self._check_version_disclosure(base_url),
            self._check_mtls_client_cert_trust(host, port),
            self._check_internal_tls_cert_trust(host, port),
        ]
        results = await asyncio.gather(*checks, return_exceptions=True)

        findings: list[ProbeFinding] = []
        for r in results:
            if isinstance(r, ProbeFinding):
                r.severity = _CONTROL_SEVERITY.get(r.control_id, "medium")
                findings.append(r)
            elif isinstance(r, Exception):
                logger.warning(f"Dynamic probe check raised unexpectedly: {r}")
        return findings

    @staticmethod
    def _cert_summary(cert: dict) -> str:
        """subject/issuer common name + expiry, for concrete cert-trust
        evidence — same helper feeds both V12.2.2 and V12.3.4 below."""
        def _cn(field):
            for rdn in field or ():
                for key, value in rdn:
                    if key == "commonName":
                        return value
            return None

        subject_cn = _cn(cert.get("subject")) or "unknown subject"
        issuer_cn = _cn(cert.get("issuer")) or "unknown issuer"
        not_after = cert.get("notAfter") or "unknown expiry"
        return f"subject={subject_cn}, issuer={issuer_cn}, expires={not_after}"

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
            return ProbeFinding(
                "V12.1.1", "fail",
                f"Negotiated protocol was {negotiated}, not TLS 1.2 or 1.3 (default handshake against {host}:{port})",
                confidence=0.85,
            )

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
                f"Server negotiated {negotiated} by default, but a handshake forced to offer only TLS 1.0 "
                f"still succeeded (negotiated {legacy_accepted}) — legacy protocol is not rejected",
                confidence=0.8,
            )
        return ProbeFinding(
            "V12.1.1", "pass",
            f"Negotiated {negotiated} by default; a handshake forced to offer only TLS 1.0 failed, "
            "confirming the legacy protocol is rejected",
            confidence=0.85,
        )

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
            cert = await asyncio.wait_for(
                asyncio.to_thread(self._verify_trusted_cert, host, port),
                timeout=CONNECT_TIMEOUT_SECONDS,
            )
        except ssl.SSLCertVerificationError as exc:
            return ProbeFinding("V12.2.2", "fail", f"Certificate at {host}:{port} is not publicly trusted: {exc}", confidence=0.9)
        except Exception as exc:
            return ProbeFinding("V12.2.2", "not_tested", f"Could not verify certificate for {host}:{port}: {exc}", confidence=0.3)
        return ProbeFinding(
            "V12.2.2", "pass",
            f"Certificate validated against the system trust store — {self._cert_summary(cert)}",
            confidence=0.85,
        )

    @staticmethod
    def _verify_trusted_cert(host: str, port: int) -> dict:
        context = ssl.create_default_context()  # validates against the system CA trust store
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT_SECONDS) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                # A dict form is only returned when verification succeeded
                # (verify_mode is CERT_REQUIRED by default in a default
                # context) — the handshake completing at all is the pass
                # signal; this is extra detail for the evidence text.
                return tls_sock.getpeercert() or {}

    # ── V12.2.1 — HTTPS enforcement ───────────────────────────────────────────

    async def _check_https_enforcement(self, host: str) -> ProbeFinding:
        # Standard convention: a plaintext listener alongside HTTPS lives on port 80
        # regardless of what non-standard HTTPS port was originally targeted.
        http_url = f"http://{host}"
        try:
            async with httpx.AsyncClient(follow_redirects=False, timeout=HTTP_TIMEOUT_SECONDS) as client:
                resp = await client.get(http_url)
        except (httpx.ConnectError, httpx.ConnectTimeout):
            return ProbeFinding("V12.2.1", "pass", f"Plaintext HTTP port did not accept connections at {http_url}", confidence=0.75)
        except Exception as exc:
            return ProbeFinding("V12.2.1", "not_tested", f"Could not probe {http_url}: {exc}", confidence=0.3)

        if resp.status_code in (301, 302, 307, 308):
            location = resp.headers.get("location", "")
            if location.startswith("https://"):
                return ProbeFinding("V12.2.1", "pass", f"HTTP {resp.status_code} redirects {http_url} to HTTPS ({location})", confidence=0.85)
            return ProbeFinding(
                "V12.2.1", "fail",
                f"HTTP {resp.status_code} redirect target is not HTTPS: {location or '(no Location header)'}",
                confidence=0.7,
            )

        return ProbeFinding(
            "V12.2.1", "fail",
            f"Plaintext HTTP served content directly (status {resp.status_code}, "
            f"{len(resp.content)} bytes) instead of redirecting to HTTPS",
            confidence=0.8,
        )

    # ── V3.4.1 — live HSTS header ─────────────────────────────────────────────

    async def _check_hsts_header(self, base_url: str) -> ProbeFinding:
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS, verify=True) as client:
                resp = await client.get(base_url)
        except Exception as exc:
            return ProbeFinding("V3.4.1", "not_tested", f"Could not fetch {base_url}: {exc}", confidence=0.3)

        hsts = resp.headers.get("strict-transport-security")
        if not hsts:
            return ProbeFinding(
                "V3.4.1", "fail",
                f"No Strict-Transport-Security header on the live response from {base_url} "
                f"(required: max-age >= {_ONE_YEAR_SECONDS}, ~1 year)",
                confidence=0.8,
            )

        m = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
        if not m:
            return ProbeFinding(
                "V3.4.1", "fail",
                f"Strict-Transport-Security header present but no max-age directive found: \"{hsts}\"",
                confidence=0.6,
            )

        seconds = int(m.group(1))
        verdict = "pass" if seconds >= _ONE_YEAR_SECONDS else "fail"
        return ProbeFinding(
            "V3.4.1", verdict,
            f"Live HSTS max-age={seconds} seconds ({'meets' if verdict == 'pass' else 'below'} "
            f"the {_ONE_YEAR_SECONDS}-second / 1-year minimum) — full header: \"{hsts}\"",
            confidence=0.85,
        )

    # ── V3.3.5 — Set-Cookie size ────────────────────────────────────────────

    async def _check_cookie_size(self, base_url: str) -> ProbeFinding:
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS, verify=True) as client:
                resp = await client.get(base_url)
        except Exception as exc:
            return ProbeFinding("V3.3.5", "not_tested", f"Could not fetch {base_url}: {exc}", confidence=0.3)

        set_cookie_headers = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        if not set_cookie_headers:
            single = resp.headers.get("set-cookie")
            set_cookie_headers = [single] if single else []
        if not set_cookie_headers:
            return ProbeFinding("V3.3.5", "not_tested", f"No Set-Cookie headers observed on the response from {base_url}", confidence=0.35)

        # Measure every cookie's name+value byte length — real evidence for
        # the pass case too, not just an assertion that nothing was over the
        # limit. Cookie *names* only, never values: a value can be a live
        # session token and evidence text isn't a place to put that.
        measurements = []
        for header in set_cookie_headers:
            name_value = header.split(";", 1)[0]
            name = name_value.split("=", 1)[0]
            measurements.append((name, len(name_value.encode("utf-8"))))

        oversized = [(name, size) for name, size in measurements if size > 4096]
        if oversized:
            detail = ", ".join(f"{name} ({size} bytes)" for name, size in oversized[:5])
            return ProbeFinding(
                "V3.3.5", "fail",
                f"Set-Cookie name+value exceeds the 4096-byte limit for: {detail}",
                confidence=0.85,
            )

        detail = ", ".join(f"{name}: {size} bytes" for name, size in measurements[:8])
        more = f" (+{len(measurements) - 8} more)" if len(measurements) > 8 else ""
        return ProbeFinding(
            "V3.3.5", "pass",
            f"All {len(measurements)} observed Set-Cookie name+value pair(s) are within the 4096-byte "
            f"limit — {detail}{more}",
            confidence=0.75,
        )

    # ── V3.7.4 — HSTS preload list status ────────────────────────────────────

    async def _check_hsts_preload(self, host: str) -> ProbeFinding:
        domain = host.lower().strip(".")
        url = f"https://hstspreload.org/api/v2/status?domain={domain}"
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS, verify=True) as client:
                resp = await client.get(url)
        except Exception as exc:
            return ProbeFinding("V3.7.4", "not_tested", f"Could not query HSTS preload status for {domain}: {exc}", confidence=0.3)

        if resp.status_code != 200:
            return ProbeFinding("V3.7.4", "not_tested", f"HSTS preload API returned HTTP {resp.status_code} for {domain}", confidence=0.35)

        try:
            body = resp.json()
            status = body.get("status")
        except Exception:
            return ProbeFinding("V3.7.4", "not_tested", "HSTS preload API response was not valid JSON", confidence=0.3)

        if status in {"preloaded", "pending"}:
            return ProbeFinding(
                "V3.7.4", "pass",
                f"hstspreload.org reports {domain} status as \"{status}\"",
                confidence=0.85,
            )
        reason = body.get("issues") or body.get("message") if isinstance(body, dict) else None
        detail = f" — {reason}" if reason else ""
        return ProbeFinding(
            "V3.7.4", "fail",
            f"hstspreload.org reports {domain} status as \"{status or 'unknown'}\" (not preloaded or pending){detail}",
            confidence=0.75,
        )

    # ── V13.4.1 — .git / .svn exposure ────────────────────────────────────────

    async def _check_git_exposure(self, base_url: str) -> ProbeFinding:
        probes = [
            (f"{base_url}/.git/HEAD", "ref: refs/"),
            (f"{base_url}/.svn/entries", None),
            (f"{base_url}/.svn/wc.db", None),
        ]
        checked_paths = [url for url, _ in probes]
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
                for url, signature in probes:
                    try:
                        resp = await client.get(url)
                    except Exception:
                        continue
                    if resp.status_code == 200 and (signature is None or signature in resp.text[:200]):
                        snippet = resp.text[:80].replace("\n", " ")
                        return ProbeFinding(
                            "V13.4.1", "fail",
                            f"Source-control metadata reachable at {url} (HTTP 200, body starts: \"{snippet}\")",
                            confidence=0.9,
                        )
        except Exception as exc:
            return ProbeFinding("V13.4.1", "not_tested", f"Could not probe {base_url}: {exc}", confidence=0.3)

        return ProbeFinding(
            "V13.4.1", "pass",
            "Checked " + ", ".join(checked_paths) + " — none returned an HTTP 200 with source-control metadata",
            confidence=0.7,
        )

    # ── V13.4.6 — backend version disclosure ─────────────────────────────────

    async def _check_version_disclosure(self, base_url: str) -> ProbeFinding:
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS, verify=True) as client:
                resp = await client.get(base_url)
        except Exception as exc:
            return ProbeFinding("V13.4.6", "not_tested", f"Could not fetch {base_url}: {exc}", confidence=0.3)

        server = resp.headers.get("server", "")
        x_powered_by = resp.headers.get("x-powered-by")
        has_version_in_server = bool(re.search(r"/\d", server))

        if x_powered_by or has_version_in_server:
            reasons = []
            if x_powered_by:
                reasons.append(f"X-Powered-By: {x_powered_by}")
            if has_version_in_server:
                reasons.append(f"Server: {server}")
            return ProbeFinding(
                "V13.4.6", "fail",
                "Live response discloses backend component version info — " + ", ".join(reasons),
                confidence=0.75,
            )
        # Show what *was* observed, not just the absence — a bare "Server:
        # nginx" with no version is still worth showing as the evidence that
        # was actually checked, same as a header that was never sent at all.
        observed = f"Server: {server or '(not sent)'}, X-Powered-By: {x_powered_by or '(not sent)'}"
        return ProbeFinding(
            "V13.4.6", "pass",
            f"No version-revealing Server/X-Powered-By header observed — {observed}",
            confidence=0.6,
        )

    # ── V12.1.3 — mTLS client-certificate trust (best-effort) ────────────────
    #
    # A black-box scanner has no client certificate the target would actually
    # trust, so this can't directly confirm "trust is validated correctly".
    # What it *can* do: first check whether the server hard-requires a client
    # cert at all (handshake without one), and if so, retry with a throwaway
    # self-signed cert the target has no reason to trust. A server that
    # accepts that cert anyway clearly isn't validating client identity; one
    # that rejects it is at least doing real validation, not just checking
    # "was something presented". If the server never asks for a client cert
    # in the first place, this endpoint isn't doing mTLS and the control
    # can't be exercised — not_tested, not a guessed pass or fail.

    @staticmethod
    def _tls_handshake_ok(host: str, port: int, cert_path: Optional[str], key_path: Optional[str]) -> bool:
        context = ssl.create_default_context()
        # Only the server's willingness to accept *our* identity is under
        # test here; its own certificate's trust is covered separately by
        # V12.2.2/V12.3.4, so skip that verification to avoid conflating the
        # two failure modes.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        if cert_path and key_path:
            context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT_SECONDS) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return True

    @staticmethod
    def _generate_throwaway_client_cert() -> tuple[bytes, bytes]:
        from datetime import datetime, timedelta, timezone as _tz

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "controlgate-probe-throwaway")])
        now = datetime.now(_tz.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(minutes=30))
            .sign(key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return cert_pem, key_pem

    async def _check_mtls_client_cert_trust(self, host: str, port: int) -> ProbeFinding:
        # A plain OSError (refused/timeout/DNS failure) means the target couldn't be
        # reached at all — nothing to conclude. An ssl.SSLError means the socket
        # connected fine but the TLS handshake itself was rejected, which is the
        # signal that a client certificate is actually required — worth continuing
        # to the throwaway-cert test. (ssl.SSLError subclasses OSError, so it must
        # be checked first.)
        try:
            await asyncio.wait_for(
                asyncio.to_thread(self._tls_handshake_ok, host, port, None, None),
                timeout=CONNECT_TIMEOUT_SECONDS,
            )
            return ProbeFinding(
                "V12.1.3", "not_tested",
                f"Server at {host}:{port} completed a TLS handshake without requesting a client "
                "certificate — this endpoint does not appear to enforce mTLS, so client-certificate "
                "trust validation could not be exercised",
                confidence=0.3,
            )
        except ssl.SSLError:
            pass  # handshake reached the TLS layer and was rejected — likely cert required
        except Exception as exc:
            return ProbeFinding(
                "V12.1.3", "not_tested",
                f"Could not establish a baseline TLS connection to {host}:{port}: {exc}",
                confidence=0.3,
            )

        try:
            cert_pem, key_pem = self._generate_throwaway_client_cert()
        except Exception as exc:
            return ProbeFinding(
                "V12.1.3", "not_tested",
                f"Could not generate a throwaway test certificate: {exc}",
                confidence=0.2,
            )

        cert_path = key_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as cf:
                cf.write(cert_pem)
                cert_path = cf.name
            with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as kf:
                kf.write(key_pem)
                key_path = kf.name
        except Exception as exc:
            return ProbeFinding(
                "V12.1.3", "not_tested",
                f"Could not write a throwaway test certificate to disk: {exc}",
                confidence=0.2,
            )

        try:
            try:
                await asyncio.wait_for(
                    asyncio.to_thread(self._tls_handshake_ok, host, port, cert_path, key_path),
                    timeout=CONNECT_TIMEOUT_SECONDS,
                )
            except ssl.SSLError as exc:
                return ProbeFinding(
                    "V12.1.3", "pass",
                    f"Server at {host}:{port} required a client certificate and rejected a throwaway "
                    f"self-signed one ({exc.__class__.__name__}: {exc}), consistent with validating "
                    "client-certificate trust",
                    confidence=0.55,
                )
            except Exception as exc:
                return ProbeFinding(
                    "V12.1.3", "not_tested",
                    f"Connection to {host}:{port} failed while testing the throwaway certificate: {exc}",
                    confidence=0.3,
                )
        finally:
            for p in (cert_path, key_path):
                try:
                    os.remove(p)
                except OSError:
                    pass

        return ProbeFinding(
            "V12.1.3", "fail",
            f"Server at {host}:{port} required a client certificate but accepted an untrusted "
            "throwaway self-signed one — client-certificate identity does not appear to be validated",
            confidence=0.6,
        )

    # ── V12.3.4 — internal service-to-service TLS cert trust (best-effort) ───
    #
    # This control is fundamentally about *internal* connections; a probe
    # from outside the network only has something to say when the user has
    # pointed target_url directly at an internal endpoint. Reuses the same
    # system-trust-store check as V12.2.2, but a validation failure here
    # can't be treated as a hard fail: a deliberately pinned internal CA is
    # expected to fail default system trust too, and this probe has no way
    # to tell that apart from a real misconfiguration — so it stays
    # not_tested rather than guessing.
    async def _check_internal_tls_cert_trust(self, host: str, port: int) -> ProbeFinding:
        try:
            cert = await asyncio.wait_for(
                asyncio.to_thread(self._verify_trusted_cert, host, port),
                timeout=CONNECT_TIMEOUT_SECONDS,
            )
        except ssl.SSLCertVerificationError as exc:
            return ProbeFinding(
                "V12.3.4", "not_tested",
                f"TLS certificate at {host}:{port} does not validate against the system trust "
                f"store ({exc}); expected for a deliberately pinned internal CA and can't be "
                "distinguished from misconfiguration without that CA",
                confidence=0.3,
            )
        except Exception as exc:
            return ProbeFinding(
                "V12.3.4", "not_tested",
                f"Could not verify certificate for {host}:{port}: {exc}",
                confidence=0.3,
            )
        return ProbeFinding(
            "V12.3.4", "pass",
            f"TLS certificate validates against a trusted CA recognized by the system trust store "
            f"— {self._cert_summary(cert)}",
            confidence=0.4,
        )
