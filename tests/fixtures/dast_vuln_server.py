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

import html
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

# Shared, deliberately unsynchronized state for the race-condition routes.
_redeem_state = {"vulnerable_redeemed": False}
_redeem_lock = threading.Lock()
_redeem_safe_state = {"safe_redeemed": False}

# Shared state for the stored-XSS comment-wall routes.
_comment_state = {"vulnerable": "", "safe": ""}

_REDIRECT_PARAMS = ("url", "next", "redirect", "return", "continue", "dest", "target", "redirect_uri")

# Bearer token the /orders/ and /admin routes treat as "authorized" — any
# other value (including a different, equally-valid-looking bearer token)
# gets denied.
OWNER_BEARER_TOKEN = "owner-secret-token"

# Value /transfer-form(-safe) render into their hidden csrf_token field, and
# what /transfer-safe checks the submitted csrf_token against.
CSRF_TOKEN_VALUE = "server-csrf-value"

# Credentials /login accepts. /protected-data's session expires (goes back to
# 401) after this many successful accesses, to back Track C4's re-auth test —
# a fresh /login call issues a new session that's good for another
# _LOGIN_EXPIRE_AFTER requests.
LOGIN_USERNAME = "alice"
LOGIN_PASSWORD = "hunter2"
_LOGIN_EXPIRE_AFTER = 2
_login_state = {"login_count": 0, "current_session": None, "successes_this_session": 0}

# Fake "table" for the /products SQLi routes.
_PRODUCTS = {"1": "Widget", "2": "Gadget", "3": "Gizmo"}


def _simulate_unescaped_query(raw_value: str) -> list:
    """Simulates SELECT * FROM products WHERE id = '<raw_value>' with no
    escaping at all — a literal single quote in raw_value terminates the
    string early and whatever follows is evaluated as SQL, exactly like a
    real string-concatenated (non-parameterized) query would behave."""
    if "' OR '1'='1" in raw_value:
        return list(_PRODUCTS.values())  # always-true clause -> every row
    if "' OR '1'='2" in raw_value:
        return []  # always-false clause -> no rows
    exact_id = raw_value.split("'")[0]
    return [_PRODUCTS[exact_id]] if exact_id in _PRODUCTS else []


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

        if path == "/redirect-safe":
            target = None
            for param in _REDIRECT_PARAMS:
                if param in qs:
                    target = qs[param][0]
                    break
            if target is None:
                self._send(400, b"missing redirect param")
                return
            # Safe: only same-site relative paths are ever honored — this
            # rejects both a CRLF-bearing payload and an absolute-URL/
            # forged-host redirect target outright.
            if "\r" in target or "\n" in target or "://" in target or not target.startswith("/"):
                self._send(400, b"invalid redirect target")
                return
            self._send(302, b"", extra_headers=[("Location", target)])
            return

        if path.startswith("/traverse-safe"):
            # Safe: decodes fully (both levels) before checking for a
            # traversal sequence, so single- and double-encoded attempts are
            # both blocked identically — no double-decode gap to exploit.
            fully_decoded = unquote(unquote(self.path))
            if ".." in fully_decoded:
                self._send(403, b"blocked: traversal sequence detected")
                return
            self._send(404, b"not found")
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

        if path == "/transfer-form":
            body = (
                b"<html><body><form method='POST' action='/transfer'>"
                b"<input type='hidden' name='csrf_token' value='" + CSRF_TOKEN_VALUE.encode() + b"'/>"
                b"<input name='amount' value='10'/>"
                b"</form></body></html>"
            )
            self._send(200, body)
            return

        if path == "/transfer-form-safe":
            body = (
                b"<html><body><form method='POST' action='/transfer-safe'>"
                b"<input type='hidden' name='csrf_token' value='" + CSRF_TOKEN_VALUE.encode() + b"'/>"
                b"<input name='amount' value='10'/>"
                b"</form></body></html>"
            )
            self._send(200, body)
            return

        if path == "/admin":
            # Ownership/authorization enforced by bearer token.
            auth = self.headers.get("Authorization", "")
            if auth == f"Bearer {OWNER_BEARER_TOKEN}":
                self._send(200, b"admin panel")
            else:
                self._send(401, b"unauthorized")
            return

        if path == "/admin-open":
            # Vulnerable on purpose: no auth check at all, forced-browsing works.
            self._send(200, b"admin panel")
            return

        if path == "/search":
            # Vulnerable on purpose: 'q' rendered straight into the page, no escaping.
            q = qs.get("q", [""])[0]
            body = f"<html><body>Results for: {q}</body></html>".encode()
            self._send(200, body)
            return

        if path == "/search-safe":
            q = qs.get("q", [""])[0]
            escaped = q.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
            body = f"<html><body>Results for: {escaped}</body></html>".encode()
            self._send(200, body)
            return

        if path == "/products":
            # Vulnerable on purpose: id concatenated into a query with no escaping.
            raw = qs.get("id", [""])[0]
            rows = _simulate_unescaped_query(raw)
            body = f"<html><body>Found {len(rows)} product(s): {', '.join(rows)}</body></html>".encode()
            self._send(200, body)
            return

        if path == "/products-safe":
            # Parameterized: the whole raw value is the literal id, injection
            # payloads never match a real row either way.
            raw = qs.get("id", [""])[0]
            row = _PRODUCTS.get(raw)
            body = f"<html><body>Found {'1' if row else '0'} product(s): {row or ''}</body></html>".encode()
            self._send(200, body)
            return

        if path == "/comment-form":
            body = (
                b"<html><body><form method='POST' action='/comment'>"
                b"<input name='comment' value=''/></form></body></html>"
            )
            self._send(200, body)
            return

        if path == "/comment-wall":
            # Vulnerable on purpose: stored comment rendered without escaping.
            body = f"<html><body>Comments: {_comment_state['vulnerable']}</body></html>".encode()
            self._send(200, body)
            return

        if path == "/comment-form-safe":
            body = (
                b"<html><body><form method='POST' action='/comment-safe'>"
                b"<input name='comment' value=''/></form></body></html>"
            )
            self._send(200, body)
            return

        if path == "/comment-wall-safe":
            body = f"<html><body>Comments: {_comment_state['safe']}</body></html>".encode()
            self._send(200, body)
            return

        if path == "/fetch":
            # Vulnerable on purpose: fetches whatever URL the caller supplies,
            # server-side, with no allowlist at all — the classic SSRF shape.
            target = qs.get("url", [None])[0]
            if target is None:
                self._send(400, b"missing url param")
                return
            try:
                with urllib.request.urlopen(target, timeout=3) as resp:
                    resp.read(200)
            except Exception:
                pass  # the point is that the outbound request was attempted at all
            self._send(200, b"fetched")
            return

        if path == "/fetch-safe":
            # Safe: never fetches a caller-supplied URL at all.
            self._send(200, b"fetching arbitrary URLs is not supported")
            return

        if path == "/protected-data":
            cookie_header = self.headers.get("Cookie", "")
            current = _login_state["current_session"]
            if not (current and current in cookie_header):
                self._send(401, b'{"error": "unauthorized"}', content_type="application/json")
                return
            if _login_state["successes_this_session"] >= _LOGIN_EXPIRE_AFTER:
                # Session "expired" — a real login is required again.
                self._send(401, b'{"error": "session expired"}', content_type="application/json")
                return
            _login_state["successes_this_session"] += 1
            self._send(200, b'{"ok": true}', content_type="application/json")
            return

        self._send(404, b"not found")

    def do_POST(self):
        path = urlsplit(self.path).path
        length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(length) if length else b""

        if path == "/login":
            posted = parse_qs(body_bytes.decode("utf-8", errors="replace"))
            username = posted.get("username", [""])[0]
            password = posted.get("password", [""])[0]
            if username == LOGIN_USERNAME and password == LOGIN_PASSWORD:
                _login_state["login_count"] += 1
                token = f"session-{_login_state['login_count']}"
                _login_state["current_session"] = token
                _login_state["successes_this_session"] = 0
                self._send(200, b"ok", extra_headers=[("Set-Cookie", f"session={token}; Path=/")])
            else:
                self._send(401, b"bad credentials")
            return

        if path == "/transfer":
            # Vulnerable on purpose: accepts the transfer regardless of
            # whether a valid csrf_token was submitted.
            self._send(200, b"transferred")
            return

        if path == "/transfer-safe":
            posted = parse_qs(body_bytes.decode("utf-8", errors="replace"))
            token = posted.get("csrf_token", [None])[0]
            if token == CSRF_TOKEN_VALUE:
                self._send(200, b"transferred")
            else:
                self._send(403, b"invalid csrf token")
            return

        if path == "/comment":
            # Vulnerable on purpose: stores the raw comment, no HTML-escaping
            # anywhere in the write or read path (see /comment-wall above).
            posted = parse_qs(body_bytes.decode("utf-8", errors="replace"))
            _comment_state["vulnerable"] = posted.get("comment", [""])[0]
            self._send(200, b"thanks")
            return

        if path == "/comment-safe":
            posted = parse_qs(body_bytes.decode("utf-8", errors="replace"))
            _comment_state["safe"] = html.escape(posted.get("comment", [""])[0])
            self._send(200, b"thanks")
            return

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

    def reset_comment_state(self):
        _comment_state["vulnerable"] = ""
        _comment_state["safe"] = ""

    def reset_login_state(self):
        _login_state["login_count"] = 0
        _login_state["current_session"] = None
        _login_state["successes_this_session"] = 0

    def __enter__(self) -> "VulnFixtureServer":
        self._thread.start()
        return self

    def __exit__(self, *exc_info) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
