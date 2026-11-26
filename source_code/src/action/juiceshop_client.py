"""HTTP client for OWASP Juice Shop (plan16 target #4). Juice Shop is a modern
Angular SPA + REST backend (default port 3000), an INDEPENDENT, widely-recognised
benchmark distinct from the PHP form apps (DVWA/bWAPP) -- it stresses the agent's
generalisation beyond the training distribution (B8_DESAIN §2 external validity).

It reuses DvwaClient's scope-guarded request plumbing (send_param for GET, cookies)
and adds a JSON POST path for its REST endpoints (e.g. /rest/user/login). It is
UNAUTHENTICATED by default: most of Juice Shop's vulnerable endpoints are reachable
anonymously, and the login itself is an SQLi target, so a forced login would mask
the very bug under test.

Success is judged by the LOCATION-BLIND universal oracle (K7) in the orchestrator,
using known-leak markers (Juice Shop ships fixed secret data -- e.g. the admin
account email) + browser-exec (XSS) + OAST (SSRF). The exact marker strings and
endpoint paths are confirmed in the first on-pod smoke (same TODO-confirm maturity
bWAPP had pre-smoke, run_bwapp_sweep.py); the parsing/judge logic is proven off-pod.
"""
from __future__ import annotations

import json as _json
import time as _time

from src.action.http_client import DvwaClient, HttpResponse

# Known fixed secret strings that should only surface on successful exploitation
# (unauthorised data access / SQLi enumeration). These are stable Juice Shop seed
# data, not canaries we generate. TODO-confirm exact strings in on-pod smoke.
JUICESHOP_LEAK_MARKERS = [
    "admin@juice-sh.op",          # admin account email (user enumeration / SQLi)
    "jim@juice-sh.op",            # another seeded user
    "bender@juice-sh.op",
    "0192023a7bbd73250516f069df18b500",  # MD5('admin123') = admin pw hash (confirmed on-pod smoke)
]


class JuiceShopClient(DvwaClient):
    def login(self) -> HttpResponse:
        """Anonymous by default (see module docstring). Marks logged-in so the
        base-class ensure_logged_in() gate is a no-op; a scenario that needs a JWT
        can call login_json() explicitly."""
        self._logged_in = True
        return HttpResponse(200, "", {}, 0.0, self.base_url)

    def set_security_level(self, level: str) -> None:   # no security levels in Juice Shop
        self.security_level = level

    def ensure_logged_in(self) -> None:
        self._logged_in = True

    def post_json(self, endpoint: str, payload: dict) -> HttpResponse:
        """JSON POST for REST endpoints (e.g. /rest/user/login). Scope-guarded via
        the inherited _full_url(). Returns the raw body so the oracle can scan it."""
        url = self._full_url(endpoint)
        start = _time.monotonic()
        resp = self.session.post(url, json=payload, timeout=self.timeout_s)
        return HttpResponse(status_code=resp.status_code, body=resp.text,
                            headers=dict(resp.headers), elapsed_s=_time.monotonic() - start,
                            url=url)

    def login_json(self, email: str, password: str) -> HttpResponse:
        """REST login -> JWT in {'authentication': {'token': ...}}. Used only when a
        scenario explicitly needs an authenticated session. TODO-confirm path."""
        r = self.post_json("rest/user/login", {"email": email, "password": password})
        try:
            tok = (_json.loads(r.body).get("authentication") or {}).get("token")
            if tok:
                self.session.headers["Authorization"] = f"Bearer {tok}"
        except Exception:
            pass
        return r
