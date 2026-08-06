"""Track C5 — the "back-end" half of the smuggling proxy-chain fixture.

Deliberately trivial: a single HTTP/1.1, keep-alive-capable server (same
ThreadingHTTPServer/BaseHTTPRequestHandler style as
tests/fixtures/dast_vuln_server.py) that echoes back whatever path it was
asked for. It has no smuggling-specific logic of its own — the desync this
fixture demonstrates happens entirely at the nginx front door (see
nginx-vulnerable.conf's docstring), not here. This file exists only so the
proxy has something real to forward to and to receive a second, distinct
response from if a smuggled request actually reaches it.

Run standalone (`python backend.py [port]`, defaults to 8000) — the
docker-compose service that owns this container runs it directly via a
volume mount, no image build required.
"""
from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class EchoPathHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # required for keep-alive; the whole point of this fixture

    def log_message(self, fmt, *args):  # noqa: A003 - silence default stderr logging
        pass

    def do_GET(self):
        body = f"backend received path: {self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        if length:
            self.rfile.read(length)
        body = f"backend received POST {self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    httpd = ThreadingHTTPServer(("0.0.0.0", port), EchoPathHandler)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
