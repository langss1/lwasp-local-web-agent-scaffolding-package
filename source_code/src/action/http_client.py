"""HTTP client for the DVWA target. Handles login, CSRF token extraction,
security-level cookie, and single GET/POST requests used by HTTP_REQUEST actions.

Every method that touches the network calls ScopeGuard first.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import requests

from src.action.scope_guard import ScopeGuard

_CSRF_RE = re.compile(r"user_token['\"]?\s*(?:value=)?['\"]([a-f0-9]{32,64})['\"]", re.IGNORECASE)


@dataclass
class HttpResponse:
    status_code: int
    body: str
    headers: dict
    elapsed_s: float
    url: str

    @property
    def length(self) -> int:
        return len(self.body)


@dataclass
class DvwaClient:
    base_url: str
    allowlist: list[str]
    username: str
    password: str
    security_level: str = "low"
    timeout_s: float = 10.0
    session: requests.Session = field(default_factory=requests.Session)
    _logged_in: bool = field(default=False, init=False)

    def __post_init__(self):
        self.guard = ScopeGuard(self.allowlist, base_url=self.base_url)

    # ---- internal helpers -------------------------------------------------

    def _full_url(self, endpoint: str) -> str:
        """Resolve an agent-supplied endpoint against base_url, with PATH scoping.

        ScopeGuard only checks the HOST, so on a shared host (e.g. localhost
        serving both /dvwa and /bWAPP) an agent that supplies an ABSOLUTE url can
        wander into a sibling app and burn its whole budget probing the wrong
        paths -- this is the bw_htmli_low failure mode (agent chased
        http://localhost/dvwa/... while testing /bWAPP). Here an absolute url is
        kept ONLY when it stays within the configured target (same host[:port]
        AND under base_url's path); otherwise its last path segment (plus query)
        is rebased under base_url so a request can never leave the target app.
        Relative endpoints resolve against base_url exactly as before. This is a
        scaffold scoping fix -- it does NOT touch payloads or the oracle.
        """
        base_prefix = self.base_url.rstrip("/") + "/"
        raw = (endpoint or "").strip()
        ep = urlparse(raw)
        if ep.scheme or ep.netloc:
            bp = urlparse(self.base_url)
            same_host = (ep.hostname == bp.hostname
                         and (ep.port or 80) == (bp.port or 80))
            base_path = bp.path.rstrip("/")
            in_scope = same_host and (ep.path == base_path
                                      or ep.path.startswith(base_path + "/"))
            if in_scope:
                url = raw
            else:
                tail = ep.path.rsplit("/", 1)[-1]
                url = urljoin(base_prefix, tail)
                if ep.query:
                    url = f"{url}?{ep.query}"
        else:
            url = urljoin(base_prefix, raw.lstrip("/"))
        self.guard.check(url)
        return url

    def _extract_csrf_token(self, html: str) -> str | None:
        match = _CSRF_RE.search(html)
        return match.group(1) if match else None

    def _request(self, method: str, endpoint: str, **kwargs) -> HttpResponse:
        url = self._full_url(endpoint)
        start = time.monotonic()
        resp = self.session.request(method, url, timeout=self.timeout_s, **kwargs)
        elapsed = time.monotonic() - start
        return HttpResponse(
            status_code=resp.status_code,
            body=resp.text,
            headers=dict(resp.headers),
            elapsed_s=elapsed,
            url=url,
        )

    # ---- public API ---------------------------------------------------

    def login(self) -> HttpResponse:
        """Log into DVWA, capturing the CSRF token DVWA requires on the login form."""
        login_page = self._request("GET", "login.php")
        token = self._extract_csrf_token(login_page.body)
        payload = {
            "username": self.username,
            "password": self.password,
            "Login": "Login",
        }
        if token:
            payload["user_token"] = token
        resp = self._request("POST", "login.php", data=payload, allow_redirects=True)
        self._logged_in = "login.php" not in resp.url or "Login failed" not in resp.body
        self.set_security_level(self.security_level)
        return resp

    def set_security_level(self, level: str) -> None:
        """Set the DVWA security cookie AND submit the security.php form (DVWA
        keeps the effective level in the PHP session, not just the cookie).
        """
        if level not in ("low", "medium", "high", "impossible"):
            raise ValueError(f"Unsupported DVWA security level: {level}")
        self.security_level = level
        sec_page = self._request("GET", "security.php")
        token = self._extract_csrf_token(sec_page.body)
        payload = {"security": level, "seclev_submit": "Submit"}
        if token:
            payload["user_token"] = token
        self._request("POST", "security.php", data=payload)
        self.session.cookies.set("security", level)

    def ensure_logged_in(self) -> None:
        if not self._logged_in:
            self.login()

    def get(self, endpoint: str, params: dict | None = None) -> HttpResponse:
        self.ensure_logged_in()
        return self._request("GET", endpoint, params=params or {})

    def post(self, endpoint: str, data: dict | None = None) -> HttpResponse:
        self.ensure_logged_in()
        return self._request("POST", endpoint, data=data or {})

    def send_param(self, method: str, endpoint: str, param: str, value: str,
                    extra_params: dict | None = None) -> HttpResponse:
        """Send a single test parameter (the shape HTTP_REQUEST actions use)."""
        params = dict(extra_params or {})
        params[param] = value
        if method.upper() == "GET":
            return self.get(endpoint, params=params)
        return self.post(endpoint, data=params)

    def send_param_no_redirect(self, method: str, endpoint: str, param: str, value: str,
                               extra_params: dict | None = None) -> HttpResponse:
        """Like send_param but does NOT follow 3xx redirects, so the caller can
        inspect the Location header (open-redirect detection)."""
        self.ensure_logged_in()
        params = dict(extra_params or {})
        params[param] = value
        if method.upper() == "GET":
            return self._request("GET", endpoint, params=params, allow_redirects=False)
        return self._request("POST", endpoint, data=params, allow_redirects=False)

    def upload_file(self, endpoint: str, field: str, filename: str, content: bytes,
                    content_type: str = "image/jpeg", extra_params: dict | None = None) -> HttpResponse:
        """Multipart file upload (DVWA File Upload module). The agent controls the
        filename, content, and declared content-type so it can try a .php web
        shell, a faked image content-type, or image magic bytes as the filter
        demands. Scope-guarded like every other request.
        """
        self.ensure_logged_in()
        data = dict(extra_params or {"Upload": "Upload"})
        files = {field: (filename, content, content_type)}
        url = self._full_url(endpoint)
        import time as _t
        start = _t.monotonic()
        resp = self.session.post(url, data=data, files=files, timeout=self.timeout_s)
        return HttpResponse(status_code=resp.status_code, body=resp.text,
                            headers=dict(resp.headers), elapsed_s=_t.monotonic() - start, url=url)

    def send_param_with_token(self, method: str, endpoint: str, param: str, value: str,
                              extra_params: dict | None = None) -> HttpResponse:
        """Like send_param, but first GET the endpoint to extract the fresh
        anti-CSRF user_token and include it (DVWA High brute force rejects any
        request without the current token).
        """
        self.ensure_logged_in()
        page = self._request("GET", endpoint)
        token = self._extract_csrf_token(page.body)
        params = dict(extra_params or {})
        params[param] = value
        if token:
            params["user_token"] = token
        if method.upper() == "GET":
            return self._request("GET", endpoint, params=params)
        return self._request("POST", endpoint, data=params)

    def send_via_cookie(self, endpoint: str, cookie_name: str, value: str) -> HttpResponse:
        """Inject the payload through a cookie rather than a request parameter
        (DVWA High blind SQLi reads the id from $_COOKIE['id']). The cookie is set
        on the session and a GET is issued; the scope guard still gates the URL.
        """
        self.ensure_logged_in()
        self.session.cookies.set(cookie_name, value)
        return self._request("GET", endpoint)

    def send_via_session_input(self, session_endpoint: str, main_endpoint: str,
                               param: str, value: str,
                               extra_params: dict | None = None) -> HttpResponse:
        """DVWA High SQLi reads the injected id from $_SESSION, set on a separate
        page (sqli/session-input.php), not from a request parameter. So the
        payload is POSTed there first (which stores it in the session shared via
        the PHPSESSID cookie), then the main page is GET-ed to run the query and
        return the result. This is what makes High exploitable at all through an
        automated client.
        """
        self.ensure_logged_in()
        data = dict(extra_params or {})
        data[param] = value
        self._request("POST", session_endpoint, data=data)
        return self._request("GET", main_endpoint)
