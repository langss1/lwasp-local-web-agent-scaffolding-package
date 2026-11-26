"""Execute model-written Python in an isolated subprocess. Turns "the model
claims this payload encodes to X" into "here is what it actually encodes to".

A small local model invents API names and mis-counts UNION columns with great
confidence. Letting it run a few lines -- to base64/url-encode a payload, compute
a hash, count columns, reshape a candidate string, parse a captured response --
returns the real answer instead of a second guess.

## Limits, stated plainly

This is a guard against ACCIDENTS, not a security boundary against hostile code.
What is actually enforced:

- separate process, killed on timeout
- its own temp cwd, deleted afterwards
- isolated mode (`-I`): the user's PYTHONPATH and site-packages are ignored
- output capped so it cannot flood the context
- sockets and new-process creation blocked via an injected preamble

What is NOT enforced: deliberately malicious code could still read files outside
the cwd, and the preamble can be defeated with ctypes or by reloading modules.
The code here comes from a reasoning model working against a local lab target,
not from an attacker.

There is one property this sandbox enforces that matters for THIS project's
scope rule: **network access is blocked inside the script.** Any interaction
with the DVWA target must go through the scope-guarded http_client / RUN_TOOL
path, never through a raw socket a script opened. Blocking sockets here means a
model-written script cannot quietly reach the target (or anything else) behind
scope_guard's back.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

DEFAULT_TIMEOUT_S = 15
# Hard ceiling on the per-script timeout. The agent proposes a timeout; without
# a cap a single RUN_SCRIPT could sit past the run's whole wall-clock budget.
MAX_TIMEOUT_S = 30
MAX_OUTPUT_CHARS = 8_000
MAX_CODE_CHARS = 20_000

# Filesystem-path env vars that legitimate stdlib code needs on Windows
# (Path.home(), tempfile.gettempdir()). None of these touch network or process
# creation, so forwarding them does not loosen the guard.
_SAFE_ENV = ("USERPROFILE", "HOMEDRIVE", "HOMEPATH", "SystemRoot", "TEMP", "TMP")

# Injected ahead of the model's code. Neutralises the common accidental egress /
# process-spawn paths at the Python level before the user code runs.
_PREAMBLE = '''\
def _deny(name):
    def _f(*a, **k):
        raise RuntimeError(
            name + " is blocked in the pentest-agent sandbox. Scripts run with "
            "no network and cannot spawn processes; reach the target only "
            "through the orchestrator's scope-guarded tools."
        )
    return _f

try:
    import socket as _s

    # Replace socket.socket with a CLASS, not a bare function: ssl.py (imported
    # automatically by urllib/http.client/requests) does `class SSLSocket(socket)`
    # at module level, and subclassing a function raises a confusing CPython
    # TypeError. An empty class stays valid to subclass and only raises the clear
    # RuntimeError when actually instantiated.
    class _DeniedSocket:
        def __init__(self, *a, **k):
            raise RuntimeError(
                "Network access is blocked in the pentest-agent sandbox."
            )

    _s.socket = _DeniedSocket
    _s.create_connection = _deny("Network access")
except Exception:
    pass
try:
    import subprocess as _sp
    _sp.Popen = _deny("Spawning a process")
    _sp.run = _deny("Spawning a process")
except Exception:
    pass
try:
    import os as _o
    for _n in ("system", "popen", "execv", "execve", "spawnv"):
        if hasattr(_o, _n):
            setattr(_o, _n, _deny("Spawning a process"))
except Exception:
    pass
del _deny
'''


def _clamp_timeout(timeout: int) -> int:
    """Clamp a requested timeout into [1, MAX_TIMEOUT_S]. Isolated so it can be
    checked without paying the wall-clock cost of actually hitting the ceiling.
    """
    return max(1, min(int(timeout), MAX_TIMEOUT_S))


def _safe_env() -> dict[str, str]:
    import os

    env = {"PATH": "", "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
    for name in _SAFE_ENV:
        val = os.environ.get(name)
        if val:
            env[name] = val
    return env


def _truncate(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    if len(text) <= limit:
        return text
    # Keep the tail: the error message and final result are at the bottom, and
    # that is what the model needs to fix the next attempt.
    return f"[truncated -- {len(text)} chars]\n...\n" + text[-limit:]


@dataclass
class ScriptResult:
    ok: bool
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    seconds: float = 0.0
    timed_out: bool = False

    def summary(self) -> str:
        if self.timed_out:
            return f"timed out after {self.seconds:.0f}s"
        if self.ok:
            lines = len([b for b in self.stdout.splitlines() if b.strip()])
            return f"ran ({self.seconds:.1f}s, {lines} output line(s))"
        tail = (self.stderr or "").strip().splitlines()
        return f"failed: {tail[-1][:100]}" if tail else "failed with no message"

    def as_observation(self) -> dict:
        """Shape the orchestrator feeds back to the agent as an observation."""
        signal = self.summary()
        detail = self.stdout if self.ok else (self.stderr or self.stdout)
        return {
            "success": False,           # a helper script never verifies an exploit by itself
            "signal": f"{signal}\n{detail}".strip(),
            "returncode": self.returncode,
            "timed_out": self.timed_out,
        }


def run_script(code: str, timeout: int = DEFAULT_TIMEOUT_S,
               language: str = "python") -> ScriptResult:
    """Run a Python snippet and return its result. Never raises for bad code --
    the failure is captured and handed back so the agent can react to it.
    """
    if language.lower() not in {"python", "py", ""}:
        return ScriptResult(
            ok=False,
            stderr=(f"The sandbox only runs Python; '{language}' is unsupported. "
                    f"Rewrite the logic in Python."),
        )
    code = (code or "").strip()
    if not code:
        return ScriptResult(ok=False, stderr="No code to run.")
    if len(code) > MAX_CODE_CHARS:
        return ScriptResult(
            ok=False,
            stderr=f"Code too long ({len(code)} chars, limit {MAX_CODE_CHARS}).",
        )
    timeout = _clamp_timeout(timeout)

    work = Path(tempfile.mkdtemp(prefix="pa_sandbox_"))
    script = work / "agent_script.py"
    script.write_text(_PREAMBLE + "\n" + code + "\n", encoding="utf-8")

    t0 = time.time()
    try:
        proc = subprocess.run(
            [sys.executable, "-I", "-X", "utf8", str(script)],
            cwd=str(work),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=_safe_env(),
            # No stdin: an input() call gets EOF immediately instead of blocking
            # on the parent's terminal until the timeout fires.
            stdin=subprocess.DEVNULL,
        )
        return ScriptResult(
            ok=proc.returncode == 0,
            stdout=_truncate(proc.stdout or ""),
            stderr=_truncate(proc.stderr or ""),
            returncode=proc.returncode,
            seconds=time.time() - t0,
        )
    except subprocess.TimeoutExpired:
        return ScriptResult(
            ok=False,
            stderr=(f"Script killed after {timeout}s. Likely an infinite loop or "
                    f"a wait for input that never comes -- the sandbox has no stdin."),
            seconds=time.time() - t0,
            timed_out=True,
        )
    except OSError as e:
        return ScriptResult(ok=False, stderr=f"Sandbox failed to launch: {e}",
                            seconds=time.time() - t0)
    finally:
        shutil.rmtree(work, ignore_errors=True)
