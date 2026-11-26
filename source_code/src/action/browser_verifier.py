"""Playwright-based headless verifier. Used ONLY for confirming exploit
success (XSS execution / DOM change), not for broad crawling. Always goes
through ScopeGuard before navigating anywhere.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin

from playwright.sync_api import sync_playwright

from src.action.scope_guard import ScopeGuard


@dataclass
class VerificationResult:
    success: bool
    signal: str
    dom_snapshot: str = ""
    console_messages: list[str] = None
    screenshot_path: str = ""   # saved PNG so the user can SEE what the agent's browser did


class BrowserVerifier:
    def __init__(self, base_url: str, allowlist: list[str], login_user: str, login_pass: str,
                 security_level: str = "low", headless: bool = True,
                 artifacts_dir: str | Path | None = None, slow_mo_ms: int = 0,
                 app: str = "dvwa"):
        self.base_url = base_url
        self.guard = ScopeGuard(allowlist, base_url=base_url)
        self.login_user = login_user
        self.login_pass = login_pass
        self.security_level = security_level
        self.app = app   # "dvwa" | "bwapp" -- selects the login form shape (plan14.md)
        # headless=False opens a visible window so the user can watch the agent's
        # browser live; slow_mo slows each action so it is followable by eye.
        self.headless = headless
        self.slow_mo_ms = slow_mo_ms
        # Where to drop a screenshot of the verified page so the run is auditable
        # even when the browser ran headless/offline.
        self.artifacts_dir = Path(artifacts_dir) if artifacts_dir else None

    def _full_url(self, endpoint: str) -> str:
        url = urljoin(self.base_url.rstrip("/") + "/", endpoint.lstrip("/"))
        self.guard.check(url)
        return url

    def _login(self, page) -> None:
        if self.app in ("app4", "juiceshop"):
            # Login-less labs: App#4's vulnerable endpoints are anonymous, and Juice
            # Shop's are reachable without auth (its login is itself an SQLi target).
            # The DVWA/bWAPP login form below does not exist on them, so attempting it
            # timed out and made verify_xss report a FALSE-NEGATIVE on genuinely
            # executing XSS (browser_exec always negative). Skipping it is correct.
            return
        if self.app == "bwapp":
            # bWAPP login: fields login/password, numeric security level 0/1/2,
            # cookie "security_level". TODO-confirm selectors at P1b smoke.
            _num = {"low": "0", "medium": "1", "high": "2"}.get(self.security_level, "0")
            page.goto(self._full_url("login.php"))
            page.fill("input[name=login]", self.login_user)
            page.fill("input[name=password]", self.login_pass)
            page.click("button[type=submit], input[type=submit]")
            page.context.add_cookies([{
                "name": "security_level", "value": _num,
                "url": self.base_url,
            }])
            return
        # DVWA login (default, unchanged)
        page.goto(self._full_url("login.php"))
        page.fill("input[name=username]", self.login_user)
        page.fill("input[name=password]", self.login_pass)
        page.click("input[name=Login]")
        page.context.add_cookies([{
            "name": "security", "value": self.security_level,
            "url": self.base_url,
        }])

    def snapshot_html(self, html: str, tag: str, endpoint: str = "") -> str:
        """Render an HTML string we ALREADY HAVE (the exact resp.body returned
        by the HTTP_REQUEST action) and screenshot it, for full-system N=1
        per-step reporting (plan5.md SS6, 2026-10-13: "ss untuk setiap cara
        atau tahapan yang dilakukan agent").

        Deliberately does NOT re-request the vulnerable endpoint: for
        state-mutating scenarios (CSRF password change, File Upload, Brute
        Force token consumption) re-submitting the payload would duplicate the
        side effect. The BODY rendered is the exact captured response.

        BUT we inject a `<base href="{base_url}/">` tag so the browser resolves
        DVWA's RELATIVE asset URLs (stylesheet, logo) against the live server
        and fetches them -- those are harmless static GETs, not the attack
        request. Result: the screenshot looks like the styled DVWA page the
        user expects (matching LAPORAN_HASIL_DVWA.md), while the exploit
        request itself is never re-sent. (2026-10-13: user noted the earlier
        offline render had no CSS; this is the fix.)
        """
        if self.artifacts_dir is None:
            return ""
        try:
            self.artifacts_dir.mkdir(parents=True, exist_ok=True)
            path = str(self.artifacts_dir / f"step_{tag}_{int(time.time()*1000)}.png")
            # base href MUST be the page's OWN url (base_url + endpoint), not just
            # base_url: DVWA links its stylesheet with a relative "../../dvwa/css/
            # main.css", which only resolves correctly when the base matches the
            # endpoint the body was served from (e.g. .../dvwa/vulnerabilities/
            # sqli/). Using just base_url strips too many "../" levels and the CSS
            # 404s -- which is exactly why the earlier attempt had no styling.
            base_url = urljoin(self.base_url.rstrip("/") + "/", (endpoint or "").lstrip("/"))
            if not base_url.endswith("/"):
                base_url += "/"
            base_tag = f'<base href="{base_url}">'
            if "<head" in html.lower():
                import re
                styled = re.sub(r"(<head[^>]*>)", r"\1" + base_tag, html, count=1,
                                flags=re.IGNORECASE)
            else:
                styled = base_tag + html
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=self.headless, slow_mo=self.slow_mo_ms)
                page = browser.new_page()
                # networkidle so the stylesheet/images have time to load before
                # the screenshot (set_content defaults to "load" which can fire
                # before late subresources settle).
                page.set_content(styled, wait_until="load")
                try:
                    page.wait_for_load_state("networkidle", timeout=4000)
                except Exception:
                    pass
                page.screenshot(path=path, full_page=True)
                browser.close()
            return path
        except Exception:
            return ""

    def verify_xss(self, endpoint: str, param: str, payload: str, method: str = "GET",
                   extra_params: dict | None = None) -> VerificationResult:
        """Navigate to endpoint with payload injected and watch for a dialog
        (alert/confirm/prompt) or a DOM mutation that indicates the script ran.

        `extra_params` are the OTHER form fields the vulnerable endpoint requires
        for the injected value to reach its sink (e.g. bWAPP xss_get.php needs
        firstname+lastname+form=submit; a reflected param alone is never echoed).
        They mirror Scenario.extra_params, which the HTTP_REQUEST path already
        sends -- without them the browser verifier hit a page that never rendered
        the payload, reporting a false-negative on a genuinely working XSS
        (root cause of the bWAPP XSS 0/18, plan14 audit). When empty, the GET URL
        and POST fill are byte-identical to the old behaviour, so DVWA runs are
        unchanged.
        """
        extra_params = extra_params or {}
        triggered = {"alert": False, "message": None}
        console_messages: list[str] = []

        screenshot_path = ""
        dom = ""
        interact_error = None
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=self.headless, slow_mo=self.slow_mo_ms)
            try:
                page = browser.new_page()
                # FAIL FAST: default 30s Playwright timeout made a missing form field
                # (stored-XSS field name != scenario param) hang 30s PER call then
                # crash the whole run -- ~130 runs / hours wasted on 2026-11-01/02.
                # 5s + try/except below turns a crash into a graceful "unverified".
                page.set_default_timeout(5000)
                page.on("dialog", lambda dialog: (triggered.__setitem__("alert", True),
                                                   triggered.__setitem__("message", dialog.message),
                                                   dialog.dismiss()))
                page.on("console", lambda msg: console_messages.append(msg.text))
                try:
                    self._login(page)
                    url = self._full_url(endpoint)
                    if method.upper() == "GET":
                        # Append the required sibling params so the value reaches its
                        # sink. Payload stays RAW (DVWA depends on unencoded quotes);
                        # only the extra values are percent-encoded. Empty extra =>
                        # identical URL to before.
                        from urllib.parse import quote
                        extra_qs = "".join(f"&{k}={quote(str(v))}" for k, v in extra_params.items())
                        target = f"{url}?{param}={payload}{extra_qs}"
                        self.guard.check(target)
                        page.goto(target)
                    else:
                        page.goto(url)
                        try:
                            page.fill(f"[name={param}]", payload)
                        except Exception:
                            # stored-XSS form field may be named differently than the
                            # scenario param (e.g. mtxMessage/txtName) -> use the first
                            # text field instead of hanging on a non-existent selector.
                            page.fill("textarea, input[type=text]:not([name=user_token])", payload)
                        # Fill the other required form fields (bWAPP needs them) so the
                        # submit actually triggers the reflected/stored render.
                        for _k, _v in extra_params.items():
                            try:
                                page.fill(f"[name={_k}]", str(_v))
                            except Exception:
                                pass
                        try:
                            page.click("input[type=submit], button[type=submit]")
                        except Exception:
                            pass
                    page.wait_for_timeout(1500)
                    dom = page.content()
                except Exception as e:
                    # Any browser interaction failure -> graceful unverified, never a
                    # crash. The run still finishes and writes a report.
                    interact_error = type(e).__name__
                    try:
                        dom = page.content()
                    except Exception:
                        dom = ""
                # Save a screenshot so the user can SEE what the agent's browser did.
                if self.artifacts_dir is not None:
                    try:
                        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
                        screenshot_path = str(self.artifacts_dir / f"xss_verify_{int(time.time())}.png")
                        page.screenshot(path=screenshot_path, full_page=True)
                    except Exception:
                        screenshot_path = ""
            finally:
                browser.close()

        if triggered["alert"]:
            return VerificationResult(True, f"JS dialog triggered: {triggered['message']}", dom,
                                      console_messages, screenshot_path)
        if interact_error:
            return VerificationResult(False, f"Browser verify could not interact ({interact_error}); "
                                      "treated as unverified", dom, console_messages, screenshot_path)
        if payload.lower() in dom.lower() and "<script" in payload.lower():
            return VerificationResult(False, "Payload reflected in DOM but no script execution observed", dom,
                                      console_messages, screenshot_path)
        return VerificationResult(False, "No script execution or reflection observed", dom,
                                  console_messages, screenshot_path)

    def solve_js_challenge(self, endpoint: str, phrase: str = "success") -> VerificationResult:
        """Defeat the client-side JavaScript token challenge by letting the page's
        OWN JavaScript compute the token: type the phrase, let the page's handler
        fill #token (whatever the algorithm -- rot13+md5 at Low, reverse at Medium,
        obfuscated sha256 at High), then submit. This works at every level without
        reverse-engineering the obfuscation -- a legitimate 'use the app's own
        code' technique.
        """
        screenshot_path = ""
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=self.headless, slow_mo=self.slow_mo_ms)
            page = browser.new_page()
            self._login(page)
            page.goto(self._full_url(endpoint))
            page.wait_for_timeout(700)   # let page-load timers (setTimeout 300ms) settle
            page.fill("[name=phrase]", phrase)
            # Drive the page's OWN token functions whichever exist (Low: generate_token
            # = md5(rot13); Medium: do_elsesomething = reverse), and fire the events a
            # real keystroke would, so the token is recomputed for THIS phrase.
            page.evaluate(
                "() => { const p = document.querySelector('[name=phrase]');"
                " p.dispatchEvent(new Event('keyup', {bubbles:true}));"
                " try { if (typeof generate_token === 'function') generate_token(); } catch(e){}"
                " try { if (typeof do_elsesomething === 'function') do_elsesomething('XX'); } catch(e){} }"
            )
            page.wait_for_timeout(500)
            token = page.input_value("[name=token]")
            page.click("[name=send]")   # High builds the final part on this click
            page.wait_for_timeout(600)
            content = page.content()
            if self.artifacts_dir is not None:
                try:
                    self.artifacts_dir.mkdir(parents=True, exist_ok=True)
                    screenshot_path = str(self.artifacts_dir / f"js_solve_{int(time.time())}.png")
                    page.screenshot(path=screenshot_path, full_page=True)
                except Exception:
                    screenshot_path = ""
            browser.close()
        ok = "well done" in content.lower()
        return VerificationResult(ok, f"token computed by page JS={token[:16]}..., result: "
                                  + ("Well done" if ok else "not accepted"),
                                  content, [], screenshot_path)

    def close(self) -> None:
        pass
