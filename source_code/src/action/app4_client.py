"""HTTP client for App#4 (plan16). App#4 is an unauthenticated localhost lab, so
it reuses DvwaClient's request plumbing (send_param, upload_file, cookies, scope
guard) but skips login and the DVWA security-level form -- there is none.
"""
from __future__ import annotations

from src.action.http_client import DvwaClient, HttpResponse


class App4Client(DvwaClient):
    def login(self) -> HttpResponse:          # no auth in the lab
        self._logged_in = True
        return HttpResponse(200, "", {}, 0.0, self.base_url)

    def set_security_level(self, level: str) -> None:   # no security levels
        self.security_level = level

    def ensure_logged_in(self) -> None:
        self._logged_in = True
