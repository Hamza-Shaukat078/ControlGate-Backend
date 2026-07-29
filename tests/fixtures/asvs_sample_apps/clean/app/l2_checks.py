"""Clean L2 checks — SSRF-safe webhook notification.

ASVS V1.3.6 test fixture: demonstrates correct server-side request forgery
mitigation using a strict hostname allowlist before making any outbound request.
The allow_redirects=False alone is not sufficient — host validation is required.
"""
import requests
from urllib.parse import urlparse

ALLOWED_WEBHOOK_HOSTS = {"partner.example.com"}


def is_allowed_webhook(url):
    """Return True only if url's hostname is in the explicit allowlist."""
    return urlparse(url).hostname in ALLOWED_WEBHOOK_HOSTS


def notify_webhook(webhook, payload):
    # V1.3.6 — webhook URL validated against ALLOWED_WEBHOOK_HOSTS before request
    if not is_allowed_webhook(webhook):
        raise ValueError("webhook host not in allowlist")
    return requests.post(webhook, json=payload, allow_redirects=False)  # ALLOWED_WEBHOOK_HOSTS enforced above
