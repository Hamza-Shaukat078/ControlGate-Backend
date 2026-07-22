import asyncio
import json
import smtplib
from email.message import EmailMessage
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from app.core.config import settings


class EmailService:
    def _send_sendgrid_api(self, to_email: str, subject: str, body_text: str, body_html: str | None = None) -> None:
        if not settings.SENDGRID_API_KEY:
            raise ValueError("SENDGRID_API_KEY is not configured")
        if not settings.SMTP_FROM_EMAIL:
            raise ValueError("SMTP_FROM_EMAIL is not configured")

        content = [{"type": "text/plain", "value": body_text}]
        if body_html:
            content.append({"type": "text/html", "value": body_html})

        payload = {
            "personalizations": [{"to": [{"email": to_email}]}],
            "from": {"email": settings.SMTP_FROM_EMAIL, "name": settings.SMTP_FROM_NAME},
            "subject": subject,
            "content": content,
        }

        data = json.dumps(payload).encode("utf-8")
        req = Request(
            "https://api.sendgrid.com/v3/mail/send",
            data=data,
            headers={
                "Authorization": f"Bearer {settings.SENDGRID_API_KEY}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urlopen(req, timeout=10) as resp:
                if resp.status not in (200, 202):
                    raise ValueError(f"SendGrid API failed with status {resp.status}")
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="ignore")
            raise ValueError(f"SendGrid API error: {exc.code} {detail}") from exc
        except URLError as exc:
            raise ValueError(f"SendGrid API connection error: {exc.reason}") from exc

    def _send_sync(self, to_email: str, subject: str, body_text: str, body_html: str | None = None) -> None:
        if settings.SENDGRID_API_KEY:
            self._send_sendgrid_api(to_email, subject, body_text, body_html)
            return
        if not settings.SMTP_HOST:
            raise ValueError("SMTP_HOST is not configured")
        if not settings.SMTP_FROM_EMAIL:
            raise ValueError("SMTP_FROM_EMAIL is not configured")

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = f"{settings.SMTP_FROM_NAME} <{settings.SMTP_FROM_EMAIL}>"
        msg["To"] = to_email
        msg.set_content(body_text)
        if body_html:
            msg.add_alternative(body_html, subtype="html")

        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.ehlo()
            if settings.SMTP_USE_TLS:
                server.starttls()
                server.ehlo()
            if settings.SMTP_USER:
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.send_message(msg)

    async def send_email(self, to_email: str, subject: str, body_text: str, body_html: str | None = None) -> None:
        await asyncio.to_thread(self._send_sync, to_email, subject, body_text, body_html)
