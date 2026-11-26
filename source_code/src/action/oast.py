"""K8 -- OAST (Out-of-band Application Security Testing), loopback collaborator.

Catches BLIND vulnerabilities that leak no evidence in the HTTP response:
blind SSRF, blind OS-command injection (curl/wget callback), XXE, and OOB SQLi
(e.g. MySQL LOAD_FILE/UNC). A differential/marker oracle is blind to these by
definition (PortSwigger OAST, Strobes OOB; B8_DESAIN §9.D), so K7 needs an
out-of-band signal.

Public interactsh is out of the question under the localhost-only policy. Instead
this is a LOOPBACK collaborator: a tiny HTTP listener on 127.0.0.1 that the
TARGET (running on the same pod) can reach. The agent injects a payload that
makes the target fetch `http://<loopback>:<port>/<token>`; if our listener logs a
hit for that unique token, the out-of-band interaction is PROVEN -- the server
really made the request. Tokens are random, so a hit cannot be coincidental.

HTTP-callback only (covers SSRF / cmdi-with-curl / OOB file read). DNS-based OAST
would need a DNS listener; noted as a future extension. This module is fully
testable off-pod (http.server runs anywhere).
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


@dataclass
class OASTHit:
    token: str
    ts: float
    method: str
    path: str
    source_ip: str
    user_agent: str = ""


class _Handler(BaseHTTPRequestHandler):
    # Set by the listener before serving.
    registry: dict[str, list[OASTHit]] = {}

    def _record(self, method: str) -> None:
        # First non-empty path segment is the correlation token.
        token = self.path.strip("/").split("/", 1)[0].split("?", 1)[0]
        hit = OASTHit(
            token=token, ts=time.time(), method=method, path=self.path,
            source_ip=self.client_address[0],
            user_agent=self.headers.get("User-Agent", ""),
        )
        _Handler.registry.setdefault(token, []).append(hit)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_GET(self):   # noqa: N802
        self._record("GET")

    def do_POST(self):  # noqa: N802
        self._record("POST")

    def log_message(self, *args):  # silence console spam
        return


@dataclass
class OASTListener:
    """Loopback OAST collaborator. Start it once per run; mint a token per
    injection attempt; poll the token after the attempt to see if the target
    called back."""
    host: str = "127.0.0.1"
    port: int = 0                       # 0 = OS picks a free port
    _server: ThreadingHTTPServer | None = field(default=None, init=False, repr=False)
    _thread: threading.Thread | None = field(default=None, init=False, repr=False)
    _registry: dict[str, list[OASTHit]] = field(default_factory=dict, init=False, repr=False)

    def start(self) -> "OASTListener":
        _Handler.registry = self._registry
        self._server = ThreadingHTTPServer((self.host, self.port), _Handler)
        self.port = self._server.server_address[1]   # resolve real port if 0
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def new_token(self) -> tuple[str, str]:
        """Return (token, callback_url). Inject the callback_url into the payload
        (e.g. SSRF url=, or `; curl <callback_url>`)."""
        token = "oast" + secrets.token_hex(6)
        self._registry.setdefault(token, [])
        return token, f"http://{self.host}:{self.port}/{token}"

    def hits(self, token: str) -> list[OASTHit]:
        return list(self._registry.get(token, []))

    def confirmed(self, token: str) -> bool:
        """True iff the target made at least one out-of-band request for this
        token -- the blind-vuln success signal."""
        return len(self._registry.get(token, [])) > 0

    def wait(self, token: str, timeout_s: float = 5.0, poll_s: float = 0.2) -> bool:
        """Block up to timeout_s for a callback (the target may fetch async)."""
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            if self.confirmed(token):
                return True
            time.sleep(poll_s)
        return self.confirmed(token)

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def __enter__(self) -> "OASTListener":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
