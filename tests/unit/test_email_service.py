"""app/services/email_service.py — zero prior coverage. Two send paths
(SendGrid HTTP API vs. plain SMTP) selected purely by whether
settings.SENDGRID_API_KEY is set; nothing here talks to a real network.
"""
import json
from urllib.error import HTTPError, URLError
from unittest.mock import MagicMock, patch

import pytest

from app.core.config import settings
from app.services.email_service import EmailService


@pytest.fixture(autouse=True)
def _clear_email_settings(monkeypatch):
    """Every test starts from a clean slate regardless of .env/.env.template
    values loaded into the real settings singleton at import time."""
    for attr, value in [
        ("SENDGRID_API_KEY", ""), ("SMTP_HOST", ""), ("SMTP_FROM_EMAIL", ""),
        ("SMTP_FROM_NAME", "Vulcan Security"), ("SMTP_USER", ""),
        ("SMTP_PASSWORD", ""), ("SMTP_PORT", 587), ("SMTP_USE_TLS", True),
    ]:
        monkeypatch.setattr(settings, attr, value)


class TestSendSyncRouting:
    def test_neither_sendgrid_nor_smtp_configured_raises(self):
        with pytest.raises(ValueError, match="SMTP_HOST is not configured"):
            EmailService()._send_sync("to@example.com", "subj", "body")

    def test_smtp_host_set_without_from_email_raises(self, monkeypatch):
        monkeypatch.setattr(settings, "SMTP_HOST", "smtp.example.com")
        with pytest.raises(ValueError, match="SMTP_FROM_EMAIL is not configured"):
            EmailService()._send_sync("to@example.com", "subj", "body")

    def test_sendgrid_key_present_takes_priority_over_smtp(self, monkeypatch):
        """Even with a fully-valid SMTP config also present, SendGrid wins —
        proves the routing check, not just that one path works in isolation."""
        monkeypatch.setattr(settings, "SENDGRID_API_KEY", "sg-key")
        monkeypatch.setattr(settings, "SMTP_FROM_EMAIL", "noreply@example.com")
        monkeypatch.setattr(settings, "SMTP_HOST", "smtp.example.com")

        with patch.object(EmailService, "_send_sendgrid_api") as mock_sendgrid, \
             patch("smtplib.SMTP") as mock_smtp:
            EmailService()._send_sync("to@example.com", "subj", "body")

        mock_sendgrid.assert_called_once()
        mock_smtp.assert_not_called()


class TestSendGridApi:
    def test_missing_api_key_raises(self):
        with pytest.raises(ValueError, match="SENDGRID_API_KEY is not configured"):
            EmailService()._send_sendgrid_api("to@example.com", "subj", "body")

    def test_missing_from_email_raises(self, monkeypatch):
        monkeypatch.setattr(settings, "SENDGRID_API_KEY", "sg-key")
        with pytest.raises(ValueError, match="SMTP_FROM_EMAIL is not configured"):
            EmailService()._send_sendgrid_api("to@example.com", "subj", "body")

    def test_successful_send_builds_expected_payload(self, monkeypatch):
        monkeypatch.setattr(settings, "SENDGRID_API_KEY", "sg-key")
        monkeypatch.setattr(settings, "SMTP_FROM_EMAIL", "noreply@example.com")
        monkeypatch.setattr(settings, "SMTP_FROM_NAME", "Vulcan Security")

        captured_request = {}

        def fake_urlopen(req, timeout=10):
            captured_request["req"] = req
            cm = MagicMock()
            cm.__enter__.return_value = MagicMock(status=202)
            cm.__exit__.return_value = False
            return cm

        with patch("app.services.email_service.urlopen", side_effect=fake_urlopen):
            EmailService()._send_sendgrid_api(
                "to@example.com", "Hello", "plain body", "<p>html body</p>",
            )

        payload = json.loads(captured_request["req"].data.decode("utf-8"))
        assert payload["personalizations"] == [{"to": [{"email": "to@example.com"}]}]
        assert payload["from"] == {"email": "noreply@example.com", "name": "Vulcan Security"}
        assert payload["subject"] == "Hello"
        assert payload["content"] == [
            {"type": "text/plain", "value": "plain body"},
            {"type": "text/html", "value": "<p>html body</p>"},
        ]
        assert captured_request["req"].headers["Authorization"] == "Bearer sg-key"

    def test_html_body_omitted_when_not_provided(self, monkeypatch):
        monkeypatch.setattr(settings, "SENDGRID_API_KEY", "sg-key")
        monkeypatch.setattr(settings, "SMTP_FROM_EMAIL", "noreply@example.com")

        captured = {}

        def fake_urlopen(req, timeout=10):
            captured["req"] = req
            cm = MagicMock()
            cm.__enter__.return_value = MagicMock(status=200)
            cm.__exit__.return_value = False
            return cm

        with patch("app.services.email_service.urlopen", side_effect=fake_urlopen):
            EmailService()._send_sendgrid_api("to@example.com", "Hello", "plain only")

        payload = json.loads(captured["req"].data.decode("utf-8"))
        assert payload["content"] == [{"type": "text/plain", "value": "plain only"}]

    def test_non_success_status_raises(self, monkeypatch):
        monkeypatch.setattr(settings, "SENDGRID_API_KEY", "sg-key")
        monkeypatch.setattr(settings, "SMTP_FROM_EMAIL", "noreply@example.com")

        def fake_urlopen(req, timeout=10):
            cm = MagicMock()
            cm.__enter__.return_value = MagicMock(status=201)
            cm.__exit__.return_value = False
            return cm

        with patch("app.services.email_service.urlopen", side_effect=fake_urlopen):
            with pytest.raises(ValueError, match="SendGrid API failed with status 201"):
                EmailService()._send_sendgrid_api("to@example.com", "subj", "body")

    def test_http_error_wraps_response_body_into_value_error(self, monkeypatch):
        monkeypatch.setattr(settings, "SENDGRID_API_KEY", "sg-key")
        monkeypatch.setattr(settings, "SMTP_FROM_EMAIL", "noreply@example.com")

        error = HTTPError(url="https://api.sendgrid.com/v3/mail/send", code=401,
                           msg="Unauthorized", hdrs=None, fp=MagicMock(read=lambda: b"bad api key"))

        with patch("app.services.email_service.urlopen", side_effect=error):
            with pytest.raises(ValueError, match="SendGrid API error: 401 bad api key"):
                EmailService()._send_sendgrid_api("to@example.com", "subj", "body")

    def test_url_error_wraps_reason_into_value_error(self, monkeypatch):
        monkeypatch.setattr(settings, "SENDGRID_API_KEY", "sg-key")
        monkeypatch.setattr(settings, "SMTP_FROM_EMAIL", "noreply@example.com")

        with patch("app.services.email_service.urlopen", side_effect=URLError("timed out")):
            with pytest.raises(ValueError, match="SendGrid API connection error"):
                EmailService()._send_sendgrid_api("to@example.com", "subj", "body")


class TestSmtpSend:
    def test_tls_and_login_used_when_configured(self, monkeypatch):
        monkeypatch.setattr(settings, "SMTP_HOST", "smtp.example.com")
        monkeypatch.setattr(settings, "SMTP_FROM_EMAIL", "noreply@example.com")
        monkeypatch.setattr(settings, "SMTP_USER", "user@example.com")
        monkeypatch.setattr(settings, "SMTP_PASSWORD", "pw")
        monkeypatch.setattr(settings, "SMTP_USE_TLS", True)

        mock_server = MagicMock()
        mock_smtp_cm = MagicMock()
        mock_smtp_cm.__enter__.return_value = mock_server
        mock_smtp_cm.__exit__.return_value = False

        with patch("smtplib.SMTP", return_value=mock_smtp_cm) as mock_smtp_cls:
            EmailService()._send_sync("to@example.com", "subj", "body text")

        mock_smtp_cls.assert_called_once_with("smtp.example.com", 587)
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with("user@example.com", "pw")
        mock_server.send_message.assert_called_once()

    def test_no_tls_no_login_when_not_configured(self, monkeypatch):
        monkeypatch.setattr(settings, "SMTP_HOST", "smtp.example.com")
        monkeypatch.setattr(settings, "SMTP_FROM_EMAIL", "noreply@example.com")
        monkeypatch.setattr(settings, "SMTP_USE_TLS", False)
        monkeypatch.setattr(settings, "SMTP_USER", "")

        mock_server = MagicMock()
        mock_smtp_cm = MagicMock()
        mock_smtp_cm.__enter__.return_value = mock_server
        mock_smtp_cm.__exit__.return_value = False

        with patch("smtplib.SMTP", return_value=mock_smtp_cm):
            EmailService()._send_sync("to@example.com", "subj", "body text")

        mock_server.starttls.assert_not_called()
        mock_server.login.assert_not_called()

    def test_html_alternative_added_when_provided(self, monkeypatch):
        monkeypatch.setattr(settings, "SMTP_HOST", "smtp.example.com")
        monkeypatch.setattr(settings, "SMTP_FROM_EMAIL", "noreply@example.com")

        sent_messages = []
        mock_server = MagicMock()
        mock_server.send_message.side_effect = lambda msg: sent_messages.append(msg)
        mock_smtp_cm = MagicMock()
        mock_smtp_cm.__enter__.return_value = mock_server
        mock_smtp_cm.__exit__.return_value = False

        with patch("smtplib.SMTP", return_value=mock_smtp_cm):
            EmailService()._send_sync("to@example.com", "subj", "plain", "<b>html</b>")

        assert sent_messages[0].is_multipart()


class TestSendEmailAsync:
    @pytest.mark.asyncio
    async def test_send_email_delegates_to_sync_implementation_off_thread(self, monkeypatch):
        monkeypatch.setattr(settings, "SMTP_HOST", "smtp.example.com")
        monkeypatch.setattr(settings, "SMTP_FROM_EMAIL", "noreply@example.com")

        with patch.object(EmailService, "_send_sync") as mock_sync:
            await EmailService().send_email("to@example.com", "subj", "body", "<p>html</p>")

        mock_sync.assert_called_once_with("to@example.com", "subj", "body", "<p>html</p>")
