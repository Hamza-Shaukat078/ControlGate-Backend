"""
Dynamic Probe tests — ASVS controls V12.1.1, V12.2.1, V12.2.2, V3.4.1, V13.4.1.

TLS/socket-level checks are unit-tested by patching the module's own sync
helper methods (they're plain blocking calls run via asyncio.to_thread, so
patching them directly is the correct seam — no real sockets in this suite).
HTTP-level checks are tested by patching httpx.AsyncClient.get.

Section E's implementation notes include two real, live checks that aren't
re-run here: a full probe() against https://github.com (all 5 controls came
back "pass"), and a local http.server exposing a fake .git/HEAD (correctly
flagged "fail") — this suite locks in the logic deterministically.
"""
import ssl
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.domain.analysis.dynamic_probe import DynamicProbe, _parse_target


class TestParseTarget:
    def test_bare_domain_defaults_to_https_443(self):
        host, port, scheme = _parse_target("example.com")
        assert (host, port, scheme) == ("example.com", 443, "https")

    def test_explicit_scheme_and_port(self):
        host, port, scheme = _parse_target("https://example.com:8443")
        assert (host, port, scheme) == ("example.com", 8443, "https")

    def test_http_scheme_defaults_to_port_80(self):
        host, port, scheme = _parse_target("http://example.com")
        assert (host, port, scheme) == ("example.com", 80, "http")


class TestTlsVersionCheck:
    @pytest.mark.asyncio
    async def test_modern_tls_with_legacy_rejected_passes(self):
        def fake_negotiate(host, port, max_version):
            if max_version is None:
                return "TLSv1.3"
            raise ssl.SSLError("handshake failure")  # legacy offer rejected

        with patch.object(DynamicProbe, "_negotiate_tls_version", side_effect=fake_negotiate):
            finding = await DynamicProbe()._check_tls_version("example.com", 443)
        assert finding.control_id == "V12.1.1"
        assert finding.verdict == "pass"

    @pytest.mark.asyncio
    async def test_weak_default_protocol_fails(self):
        with patch.object(DynamicProbe, "_negotiate_tls_version", return_value="TLSv1.0"):
            finding = await DynamicProbe()._check_tls_version("example.com", 443)
        assert finding.verdict == "fail"
        assert "TLSv1.0" in finding.note

    @pytest.mark.asyncio
    async def test_legacy_protocol_accepted_fails(self):
        def fake_negotiate(host, port, max_version):
            return "TLSv1.3" if max_version is None else "TLSv1.0"

        with patch.object(DynamicProbe, "_negotiate_tls_version", side_effect=fake_negotiate):
            finding = await DynamicProbe()._check_tls_version("example.com", 443)
        assert finding.verdict == "fail"
        assert "also accepted" in finding.note

    @pytest.mark.asyncio
    async def test_connection_failure_is_not_tested(self):
        with patch.object(DynamicProbe, "_negotiate_tls_version", side_effect=OSError("unreachable")):
            finding = await DynamicProbe()._check_tls_version("unreachable.invalid", 443)
        assert finding.verdict == "not_tested"


class TestCertTrustCheck:
    @pytest.mark.asyncio
    async def test_trusted_cert_passes(self):
        with patch.object(DynamicProbe, "_verify_trusted_cert", return_value=None):
            finding = await DynamicProbe()._check_cert_trust("example.com", 443)
        assert finding.control_id == "V12.2.2"
        assert finding.verdict == "pass"

    @pytest.mark.asyncio
    async def test_untrusted_cert_fails(self):
        with patch.object(
            DynamicProbe, "_verify_trusted_cert",
            side_effect=ssl.SSLCertVerificationError("self-signed certificate"),
        ):
            finding = await DynamicProbe()._check_cert_trust("example.com", 443)
        assert finding.verdict == "fail"

    @pytest.mark.asyncio
    async def test_unreachable_host_not_tested(self):
        with patch.object(DynamicProbe, "_verify_trusted_cert", side_effect=OSError("timed out")):
            finding = await DynamicProbe()._check_cert_trust("example.com", 443)
        assert finding.verdict == "not_tested"


def _mock_response(status_code=200, headers=None, text=""):
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.text = text
    return resp


class TestHttpsEnforcementCheck:
    @pytest.mark.asyncio
    async def test_connection_refused_on_plaintext_port_passes(self):
        with patch("httpx.AsyncClient.get", new=AsyncMock(side_effect=httpx.ConnectError("refused"))):
            finding = await DynamicProbe()._check_https_enforcement("example.com")
        assert finding.control_id == "V12.2.1"
        assert finding.verdict == "pass"

    @pytest.mark.asyncio
    async def test_redirect_to_https_passes(self):
        resp = _mock_response(301, {"location": "https://example.com/"})
        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=resp)):
            finding = await DynamicProbe()._check_https_enforcement("example.com")
        assert finding.verdict == "pass"

    @pytest.mark.asyncio
    async def test_redirect_to_http_fails(self):
        resp = _mock_response(301, {"location": "http://example.com/"})
        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=resp)):
            finding = await DynamicProbe()._check_https_enforcement("example.com")
        assert finding.verdict == "fail"

    @pytest.mark.asyncio
    async def test_plaintext_content_served_fails(self):
        resp = _mock_response(200, {})
        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=resp)):
            finding = await DynamicProbe()._check_https_enforcement("example.com")
        assert finding.verdict == "fail"


class TestHstsHeaderCheck:
    @pytest.mark.asyncio
    async def test_valid_hsts_passes(self):
        resp = _mock_response(200, {"strict-transport-security": "max-age=63072000; includeSubDomains"})
        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=resp)):
            finding = await DynamicProbe()._check_hsts_header("https://example.com")
        assert finding.control_id == "V3.4.1"
        assert finding.verdict == "pass"

    @pytest.mark.asyncio
    async def test_missing_header_fails(self):
        resp = _mock_response(200, {})
        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=resp)):
            finding = await DynamicProbe()._check_hsts_header("https://example.com")
        assert finding.verdict == "fail"

    @pytest.mark.asyncio
    async def test_short_max_age_fails(self):
        resp = _mock_response(200, {"strict-transport-security": "max-age=3600"})
        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=resp)):
            finding = await DynamicProbe()._check_hsts_header("https://example.com")
        assert finding.verdict == "fail"

    @pytest.mark.asyncio
    async def test_request_failure_not_tested(self):
        with patch("httpx.AsyncClient.get", new=AsyncMock(side_effect=Exception("dns error"))):
            finding = await DynamicProbe()._check_hsts_header("https://example.com")
        assert finding.verdict == "not_tested"


class TestCookieSizeCheck:
    @pytest.mark.asyncio
    async def test_cookie_under_4096_passes(self):
        resp = _mock_response(200, {"set-cookie": "session=abc; Path=/; Secure"})
        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=resp)):
            finding = await DynamicProbe()._check_cookie_size("https://example.com")
        assert finding.control_id == "V3.3.5"
        assert finding.verdict == "pass"

    @pytest.mark.asyncio
    async def test_cookie_over_4096_fails(self):
        resp = _mock_response(200, {"set-cookie": "session=" + ("a" * 4097) + "; Path=/"})
        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=resp)):
            finding = await DynamicProbe()._check_cookie_size("https://example.com")
        assert finding.verdict == "fail"

    @pytest.mark.asyncio
    async def test_no_set_cookie_not_tested(self):
        resp = _mock_response(200, {})
        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=resp)):
            finding = await DynamicProbe()._check_cookie_size("https://example.com")
        assert finding.verdict == "not_tested"


class TestHstsPreloadCheck:
    @pytest.mark.asyncio
    async def test_preloaded_domain_passes(self):
        resp = _mock_response(200, {}, "")
        resp.json.return_value = {"status": "preloaded"}
        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=resp)):
            finding = await DynamicProbe()._check_hsts_preload("example.com")
        assert finding.control_id == "V3.7.4"
        assert finding.verdict == "pass"

    @pytest.mark.asyncio
    async def test_unknown_domain_fails(self):
        resp = _mock_response(200, {}, "")
        resp.json.return_value = {"status": "unknown"}
        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=resp)):
            finding = await DynamicProbe()._check_hsts_preload("example.com")
        assert finding.verdict == "fail"

    @pytest.mark.asyncio
    async def test_preload_api_error_not_tested(self):
        with patch("httpx.AsyncClient.get", new=AsyncMock(side_effect=Exception("dns error"))):
            finding = await DynamicProbe()._check_hsts_preload("example.com")
        assert finding.verdict == "not_tested"


class TestGitExposureCheck:
    @pytest.mark.asyncio
    async def test_exposed_git_head_fails(self):
        async def fake_get(self, url, *a, **kw):
            if url.endswith("/.git/HEAD"):
                return _mock_response(200, {}, "ref: refs/heads/main\n")
            return _mock_response(404)

        with patch("httpx.AsyncClient.get", new=fake_get):
            finding = await DynamicProbe()._check_git_exposure("https://example.com")
        assert finding.control_id == "V13.4.1"
        assert finding.verdict == "fail"

    @pytest.mark.asyncio
    async def test_all_404_passes(self):
        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=_mock_response(404))):
            finding = await DynamicProbe()._check_git_exposure("https://example.com")
        assert finding.verdict == "pass"

    @pytest.mark.asyncio
    async def test_200_without_signature_does_not_count_as_git(self):
        # A generic 200 (e.g. a catch-all SPA route) without the git ref signature shouldn't count.
        async def fake_get(self, url, *a, **kw):
            if url.endswith("/.git/HEAD"):
                return _mock_response(200, {}, "<html>not actually git</html>")
            return _mock_response(404)

        with patch("httpx.AsyncClient.get", new=fake_get):
            finding = await DynamicProbe()._check_git_exposure("https://example.com")
        assert finding.verdict == "pass"


class TestVersionDisclosureCheck:
    @pytest.mark.asyncio
    async def test_versioned_server_header_fails(self):
        resp = _mock_response(200, {"server": "nginx/1.18.0"})
        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=resp)):
            finding = await DynamicProbe()._check_version_disclosure("https://example.com")
        assert finding.control_id == "V13.4.6"
        assert finding.verdict == "fail"

    @pytest.mark.asyncio
    async def test_x_powered_by_header_fails(self):
        resp = _mock_response(200, {"server": "nginx", "x-powered-by": "Express"})
        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=resp)):
            finding = await DynamicProbe()._check_version_disclosure("https://example.com")
        assert finding.verdict == "fail"

    @pytest.mark.asyncio
    async def test_generic_server_header_passes(self):
        resp = _mock_response(200, {"server": "nginx"})
        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=resp)):
            finding = await DynamicProbe()._check_version_disclosure("https://example.com")
        assert finding.verdict == "pass"

    @pytest.mark.asyncio
    async def test_no_headers_passes(self):
        resp = _mock_response(200, {})
        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=resp)):
            finding = await DynamicProbe()._check_version_disclosure("https://example.com")
        assert finding.verdict == "pass"

    @pytest.mark.asyncio
    async def test_request_failure_not_tested(self):
        with patch("httpx.AsyncClient.get", new=AsyncMock(side_effect=Exception("dns error"))):
            finding = await DynamicProbe()._check_version_disclosure("https://example.com")
        assert finding.verdict == "not_tested"


class TestMtlsClientCertTrustCheck:
    @pytest.mark.asyncio
    async def test_no_cert_required_not_tested(self):
        with patch.object(DynamicProbe, "_tls_handshake_ok", return_value=True):
            finding = await DynamicProbe()._check_mtls_client_cert_trust("example.com", 443)
        assert finding.control_id == "V12.1.3"
        assert finding.verdict == "not_tested"

    @pytest.mark.asyncio
    async def test_baseline_unreachable_not_tested(self):
        with patch.object(DynamicProbe, "_tls_handshake_ok", side_effect=OSError("timed out")):
            finding = await DynamicProbe()._check_mtls_client_cert_trust("example.com", 443)
        assert finding.verdict == "not_tested"

    @pytest.mark.asyncio
    async def test_cert_required_and_bogus_cert_rejected_passes(self):
        def fake(host, port, cert_path, key_path):
            if cert_path is None:
                raise ssl.SSLError("certificate required")
            raise ssl.SSLError("bad certificate")

        with patch.object(DynamicProbe, "_tls_handshake_ok", side_effect=fake), \
             patch.object(DynamicProbe, "_generate_throwaway_client_cert", return_value=(b"cert", b"key")):
            finding = await DynamicProbe()._check_mtls_client_cert_trust("example.com", 443)
        assert finding.verdict == "pass"

    @pytest.mark.asyncio
    async def test_cert_required_but_bogus_cert_accepted_fails(self):
        def fake(host, port, cert_path, key_path):
            if cert_path is None:
                raise ssl.SSLError("certificate required")
            return True

        with patch.object(DynamicProbe, "_tls_handshake_ok", side_effect=fake), \
             patch.object(DynamicProbe, "_generate_throwaway_client_cert", return_value=(b"cert", b"key")):
            finding = await DynamicProbe()._check_mtls_client_cert_trust("example.com", 443)
        assert finding.verdict == "fail"

    @pytest.mark.asyncio
    async def test_cert_generation_failure_not_tested(self):
        def fake(host, port, cert_path, key_path):
            if cert_path is None:
                raise ssl.SSLError("certificate required")
            return True

        with patch.object(DynamicProbe, "_tls_handshake_ok", side_effect=fake), \
             patch.object(DynamicProbe, "_generate_throwaway_client_cert", side_effect=RuntimeError("no crypto backend")):
            finding = await DynamicProbe()._check_mtls_client_cert_trust("example.com", 443)
        assert finding.verdict == "not_tested"


class TestInternalTlsCertTrustCheck:
    @pytest.mark.asyncio
    async def test_trusted_cert_passes(self):
        with patch.object(DynamicProbe, "_verify_trusted_cert", return_value=None):
            finding = await DynamicProbe()._check_internal_tls_cert_trust("internal-svc.local", 8443)
        assert finding.control_id == "V12.3.4"
        assert finding.verdict == "pass"

    @pytest.mark.asyncio
    async def test_untrusted_cert_not_tested(self):
        with patch.object(
            DynamicProbe, "_verify_trusted_cert",
            side_effect=ssl.SSLCertVerificationError("self-signed certificate"),
        ):
            finding = await DynamicProbe()._check_internal_tls_cert_trust("internal-svc.local", 8443)
        assert finding.verdict == "not_tested"

    @pytest.mark.asyncio
    async def test_unreachable_host_not_tested(self):
        with patch.object(DynamicProbe, "_verify_trusted_cert", side_effect=OSError("timed out")):
            finding = await DynamicProbe()._check_internal_tls_cert_trust("internal-svc.local", 8443)
        assert finding.verdict == "not_tested"


class TestProbeOrchestration:
    @pytest.mark.asyncio
    async def test_probe_aggregates_all_controls(self):
        probe = DynamicProbe()
        with patch.object(probe, "_check_tls_version", new=AsyncMock(return_value=_finding("V12.1.1"))), \
             patch.object(probe, "_check_cert_trust", new=AsyncMock(return_value=_finding("V12.2.2"))), \
             patch.object(probe, "_check_https_enforcement", new=AsyncMock(return_value=_finding("V12.2.1"))), \
             patch.object(probe, "_check_cookie_size", new=AsyncMock(return_value=_finding("V3.3.5"))), \
             patch.object(probe, "_check_hsts_header", new=AsyncMock(return_value=_finding("V3.4.1"))), \
             patch.object(probe, "_check_hsts_preload", new=AsyncMock(return_value=_finding("V3.7.4"))), \
             patch.object(probe, "_check_git_exposure", new=AsyncMock(return_value=_finding("V13.4.1"))), \
             patch.object(probe, "_check_version_disclosure", new=AsyncMock(return_value=_finding("V13.4.6"))), \
             patch.object(probe, "_check_mtls_client_cert_trust", new=AsyncMock(return_value=_finding("V12.1.3"))), \
             patch.object(probe, "_check_internal_tls_cert_trust", new=AsyncMock(return_value=_finding("V12.3.4"))):
            findings = await probe.probe("https://example.com")
        assert {f.control_id for f in findings} == {
            "V12.1.1", "V12.2.2", "V12.2.1", "V3.3.5", "V3.4.1", "V3.7.4", "V13.4.1", "V13.4.6",
            "V12.1.3", "V12.3.4",
        }

    @pytest.mark.asyncio
    async def test_one_check_raising_does_not_break_the_others(self):
        probe = DynamicProbe()
        with patch.object(probe, "_check_tls_version", new=AsyncMock(side_effect=RuntimeError("boom"))), \
             patch.object(probe, "_check_cert_trust", new=AsyncMock(return_value=_finding("V12.2.2"))), \
             patch.object(probe, "_check_https_enforcement", new=AsyncMock(return_value=_finding("V12.2.1"))), \
             patch.object(probe, "_check_cookie_size", new=AsyncMock(return_value=_finding("V3.3.5"))), \
             patch.object(probe, "_check_hsts_header", new=AsyncMock(return_value=_finding("V3.4.1"))), \
             patch.object(probe, "_check_hsts_preload", new=AsyncMock(return_value=_finding("V3.7.4"))), \
             patch.object(probe, "_check_git_exposure", new=AsyncMock(return_value=_finding("V13.4.1"))), \
             patch.object(probe, "_check_version_disclosure", new=AsyncMock(return_value=_finding("V13.4.6"))), \
             patch.object(probe, "_check_mtls_client_cert_trust", new=AsyncMock(return_value=_finding("V12.1.3"))), \
             patch.object(probe, "_check_internal_tls_cert_trust", new=AsyncMock(return_value=_finding("V12.3.4"))):
            findings = await probe.probe("https://example.com")
        assert {f.control_id for f in findings} == {
            "V12.2.2", "V12.2.1", "V3.3.5", "V3.4.1", "V3.7.4", "V13.4.1", "V13.4.6",
            "V12.1.3", "V12.3.4",
        }


def _finding(control_id):
    from app.domain.analysis.dynamic_probe import ProbeFinding
    return ProbeFinding(control_id, "pass", "stub")
