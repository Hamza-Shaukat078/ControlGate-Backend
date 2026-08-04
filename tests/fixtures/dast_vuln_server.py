"""A tiny, deliberately vulnerable HTTP server for live DAST integration tests.

Phase 1 of the "full static+dynamic" plan: every DAST check so far
(tests/unit/test_dast_*.py) is exercised only against httpx.MockTransport —
none of them has ever sent a byte over a real socket. This fixture is a real
ThreadingHTTPServer bound to 127.0.0.1 with intentionally unsafe routes, one
per live check, so tests/integration/test_dast_live.py can prove the crawler,
payload checks, and race probe work against actual TCP/HTTP, not mocks.

Not a general-purpose test app — each route exists to reproduce exactly one
vulnerability class the DAST engine claims to detect. Do not add routes here
that aren't backing a specific live-integration assertion.
"""
from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

# Shared, deliberately unsynchronized state for the race-condition routes.
_redeem_state = {"vulnerable_redeemed": False}
_redeem_lock = threading.Lock()
_redeem_safe_state = {"safe_redeemed": False}

_REDIRECT_PARAMS = ("url", "next", "redirect", "return", "continue", "dest", "target", "redirect_uri")

# Bearer token the /orders/ route treats as "the owner" — any other value
# (including a different, equally-valid-looking bearer token) gets denied.
OWNER_BEARER_TOKEN = "owner-secret-token"


class VulnHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # noqa: A003 - silence default stderr logging
        pass

    def _send(self, status: int, body: bytes = b"", extra_headers=None, content_type="text/html"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (extra_headers or []):
            # Deliberately unsanitized: send_header() does no CRLF validation,
            # which is exactly the vulnerability /redirect below exists to expose.
            self.send_header(name, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        parts = urlsplit(self.path)
        path = parts.path
        qs = parse_qs(parts.query)

        if path == "/":
            body = (
                b"<html><body>"
                b"<a href='/page1'>page1</a> "
                b"<a href='/page2'>page2</a> "
                b"<a href='/redirect?next=/page1'>redirect</a>"
                b"<form method='POST' action='/redeem-vulnerable'>"
                b"<input name='token'/></form>"
                b"</body></html>"
            )
            self._send(200, body)
            return

        if path in ("/page1", "/page2"):
            self._send(200, f"<html><body>{path}</body></html>".encode())
            return

        if path == "/redirect":
            target = None
            for param in _REDIRECT_PARAMS:
                if param in qs:
                    target = qs[param][0]
                    break
            if target is None:
                self._send(400, b"missing redirect param")
                return
            # Vulnerable on purpose: the raw (still-encoded-by-nothing) query
            # value is written straight into the Location header with no
            # allow-list/host check and no CRLF stripping.
            self._send(302, b"", extra_headers=[("Location", target)])
            return

        if path.startswith("/traverse"):
            # Simulates a WAF/framework that decodes the path once to check
            # for ".." before a *different* downstream layer decodes again
            # (fully) before serving the file — the classic double-decode gap.
            once = unquote(self.path)
            if ".." in once:
                self._send(403, b"blocked: traversal sequence detected")
                return
            twice = unquote(once)
            if ".." in twice and twice.rstrip("/").endswith("etc/passwd"):
                self._send(200, b"root:x:0:0:root:/root:/bin/bash\n", content_type="text/plain")
                return
            self._send(404, b"not found")
            return

        if path.startswith("/orders/"):
            # Ownership enforced: only the bearer token that "owns" this
            # resource gets it back, everyone else is denied.
            auth = self.headers.get("Authorization", "")
            if auth == f"Bearer {OWNER_BEARER_TOKEN}":
                self._send(200, b'{"id": 42, "secret": "owner data"}', content_type="application/json")
            else:
                self._send(403, b"forbidden")
            return

        if path.startswith("/profile/"):
            # Vulnerable on purpose: no ownership check at all — any bearer
            # token (or none) gets the same resource back.
            self._send(200, b'{"id": 42, "secret": "owner data"}', content_type="application/json")
            return

        self._send(404, b"not found")

    def do_POST(self):
        path = urlsplit(self.path).path
        length = int(self.headers.get("Content-Length", 0))
        if length:
            self.rfile.read(length)

        if path == "/redeem-vulnerable":
            # Check-then-act with no lock: concurrent requests can all
            # observe "not yet redeemed" before any of them sets the flag.
            if not _redeem_state["vulnerable_redeemed"]:
                time.sleep(0.05)
                _redeem_state["vulnerable_redeemed"] = True
                self._send(200, b"redeemed")
            else:
                self._send(409, b"already redeemed")
            return

        if path == "/redeem-safe":
            with _redeem_lock:
                if not _redeem_safe_state["safe_redeemed"]:
                    time.sleep(0.05)
                    _redeem_safe_state["safe_redeemed"] = True
                    self._send(200, b"redeemed")
                else:
                    self._send(409, b"already redeemed")
            return

        self._send(404, b"not found")


class VulnFixtureServer:
    """Context-manager wrapper: starts the server on an ephemeral 127.0.0.1
    port in a background thread, tears it down on exit."""

    def __init__(self):
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), VulnHandler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}"

    def reset_race_state(self):
        _redeem_state["vulnerable_redeemed"] = False
        _redeem_safe_state["safe_redeemed"] = False

    def __enter__(self) -> "VulnFixtureServer":
        self._thread.start()
        return self

    def __exit__(self, *exc_info) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
