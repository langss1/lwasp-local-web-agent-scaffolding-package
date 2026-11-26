"""HTTP client for the bWAPP target (external-validity replication, plan14.md).

bWAPP is served as a sibling of DVWA on the SAME Kali pod. It uses the same kind
of classic PHP GET/POST-parameter vulnerabilities as DVWA, so this client
subclasses DvwaClient and REUSES every request/upload/cookie method unchanged.
Only two things differ and are overridden here:

  1. login form fields   -- bWAPP posts {login, password, security_level, form}
                            with credentials bee/bug (no anti-CSRF user_token).
  2. security level       -- bWAPP uses numeric levels 0/1/2 (low/medium/high),
                            set via security_level.php + a "security_level" cookie
                            (DVWA uses a "security" cookie + security.php).

Everything that touches the network still goes through ScopeGuard (inherited),
so the target stays pinned to localhost.

NOTE (plan14 P1b): the exact form field names, endpoint paths and the login
redirect/landing text are bWAPP-version dependent. Items marked TODO-confirm are
verified against the live install during the P1b smoke and corrected there.
"""

from __future__ import annotations

from src.action.http_client import DvwaClient, HttpResponse

# bWAPP numeric security levels. TODO-confirm against the running install.
_BWAPP_LEVEL_NUM = {"low": "0", "medium": "1", "high": "2"}
# Text present on the post-login landing page (portal.php) but NOT on a failed
# login. TODO-confirm the exact marker during smoke.
_BWAPP_LOGIN_OK_MARKERS = ("portal.php", "/bWAPP/logout", "Choose your bug", "welcome", "bee")


class BwappClient(DvwaClient):
    """Drop-in client for bWAPP. Same public API as DvwaClient."""

    def login(self) -> HttpResponse:
        """Log into bWAPP (bee/bug). The security level is chosen on the login
        form itself, then re-asserted via set_security_level()."""
        # prime a session (cookie) by loading the login page first
        self._request("GET", "login.php")
        level_num = _BWAPP_LEVEL_NUM.get(self.security_level, "0")
        payload = {
            "login": self.username,          # TODO-confirm field name ("login")
            "password": self.password,
            "security_level": level_num,
            "form": "submit",                # TODO-confirm submit field
        }
        resp = self._request("POST", "login.php", data=payload, allow_redirects=True)
        body_l = resp.body.lower()
        url_l = resp.url.lower()
        self._logged_in = any(m.lower() in body_l or m.lower() in url_l
                              for m in _BWAPP_LOGIN_OK_MARKERS)
        # make sure the level is really applied (cookie + session)
        self.set_security_level(self.security_level)
        return resp

    def set_security_level(self, level: str) -> None:
        """Set bWAPP security via security_level_set.php (CONFIRMED on the raesene
        fork 2026-11-08: the old `security_level.php` 404s). bWAPP keeps the effective
        level in the PHP SESSION, set by POSTing the embedded security form
        (`security_level`=0/1/2 + the `form_security_level` submit button). Verified:
        after this POST, sqli_1.php switches from injectable (low) to escaped (medium).
        """
        if level not in _BWAPP_LEVEL_NUM:
            raise ValueError(f"Unsupported bWAPP security level: {level}")
        self.security_level = level
        num = _BWAPP_LEVEL_NUM[level]
        payload = {"security_level": num, "form_security_level": "submit"}
        # security_level_set.php is the dedicated setter; it reads the form and stores
        # the level in the session, then redirects. (Posting the same form to any page
        # works too, but the dedicated endpoint is unambiguous.)
        self._request("POST", "security_level_set.php", data=payload, allow_redirects=True)
        self.session.cookies.set("security_level", num)
