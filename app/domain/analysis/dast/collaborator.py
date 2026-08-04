"""Out-of-band HTTP collaborator (Track A2 of the static+dynamic plan).

Every check built so far is in-band: send a request, inspect the response
to the *same* request. SSRF confirmation usually can't work that way — a
vulnerable server fetches an internal/attacker-controlled URL server-side
and typically doesn't echo anything back to the caller at all. The only
reliable signal is out-of-band: did the target actually *make* that fetch?

CollaboratorServer is a real HTTP listener (ThreadingHTTPServer, same
weight class as tests/fixtures/dast_vuln_server.py) embedded directly in
the scan process — not an external service like Burp Collaborator or
interactsh. It hands out unique per-probe tokens, records every inbound
request keyed by the token in the URL path, and lets a caller ask "did
token X ever get hit".

Reachability is the whole ballgame and is a deployment concern, not
something this module can solve on its own:
  - Scanning a target on the same host/network as the scanner (this
    project's own fixture server in tests, or an internal app the scanner
    sits next to): the default 127.0.0.1 bind is reachable and this works
    end-to-end, proven in tests/integration/test_dast_live.py.
  - Scanning a real external target over the internet: the collaborator
    must be bound to (and the callback URLs must point at) a
    publicly-reachable host/port — see dynamic_ssrf_collaborator_host/port
    on ScanStart. Nothing here stands up that public infrastructure.
"""
import logging
import secrets
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List

logger = logging.getLogger(__name__)


@dataclass
class CollaboratorHit:
    token: str
    method: str
    path: str
    remote_addr: str
    received_at: float


class _CollaboratorHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # noqa: A003 - silence default stderr logging
        pass

    def _record(self, method: str) -> None:
        token = self.path.lstrip("/").split("/", 1)[0].split("?", 1)[0]
        self.server.record_hit(token, method, self.path, self.client_address[0])  # type: ignore[attr-defined]
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self._record("GET")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        if length:
            self.rfile.read(length)
        self._record("POST")

    do_PUT = do_POST
    do_HEAD = do_GET


class CollaboratorServer:
    """Context-manager wrapper: starts the listener in a background thread,
    tears it down on exit. One instance per scan (not shared/global) so
    concurrent scans never see each other's tokens."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self._httpd = ThreadingHTTPServer((host, port), _CollaboratorHandler)
        self._httpd.record_hit = self._record_hit  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._hits: Dict[str, List[CollaboratorHit]] = {}
        self._lock = threading.Lock()

    def _record_hit(self, token: str, method: str, path: str, remote_addr: str) -> None:
        with self._lock:
            self._hits.setdefault(token, []).append(
                CollaboratorHit(
                    token=token, method=method, path=path, remote_addr=remote_addr, received_at=time.time(),
                )
            )
        logger.debug(f"Collaborator hit: token={token} method={method} from={remote_addr}")

    @property
    def base_url(self) -> str:
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}"

    def new_token(self) -> str:
        return secrets.token_hex(12)

    def callback_url(self, token: str) -> str:
        return f"{self.base_url}/{token}"

    def hits_for(self, token: str) -> List[CollaboratorHit]:
        with self._lock:
            return list(self._hits.get(token, []))

    def __enter__(self) -> "CollaboratorServer":
        self._thread.start()
        return self

    def __exit__(self, *exc_info) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
