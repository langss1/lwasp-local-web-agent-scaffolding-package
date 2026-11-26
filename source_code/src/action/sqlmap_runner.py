"""Subprocess wrapper around sqlmap, locked to the configured DVWA target.
Used for RUN_TOOL actions. Captures stdout/stderr as an observation instead
of parsing sqlmap's internal state -- the cognitive engine reasons over text.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from src.action.scope_guard import ScopeGuard


@dataclass
class SqlmapResult:
    returncode: int
    stdout: str
    stderr: str
    command: list[str]


def _find_sqlmap() -> list[str] | None:
    """Locate a runnable sqlmap: a `sqlmap` binary on PATH, a `sqlmap.exe`
    console-script next to the current Python interpreter (pip install sqlmap
    on Windows does not always end up on PATH), or `python -m sqlmap` as a
    fallback since the package is importable either way.
    """
    exe = shutil.which("sqlmap") or shutil.which("sqlmap.py")
    if exe:
        return [exe]
    for scripts_dir in (Path(sys.executable).parent / "Scripts",
                         Path(sys.executable).parent.parent / "Scripts"):
        candidate = scripts_dir / "sqlmap.exe"
        if candidate.exists():
            return [str(candidate)]
    # The pip package ships sqlmap.py at its root but has no __main__, so
    # `python -m sqlmap` fails ("No module named sqlmap.__main__"). Invoke the
    # script file directly instead.
    try:
        import sqlmap
        pkg_script = Path(sqlmap.__file__).parent / "sqlmap.py"
        if pkg_script.exists():
            return [sys.executable, str(pkg_script)]
    except ImportError:
        pass
    return None


class SqlmapRunner:
    def __init__(self, allowlist: list[str], cookie: str | None = None, timeout_s: int = 120):
        self.guard = ScopeGuard(allowlist)
        self.cookie = cookie
        self.timeout_s = timeout_s
        self.binary = _find_sqlmap()

    def available(self) -> bool:
        return self.binary is not None

    def run(self, url: str, extra_args: list[str] | None = None,
            data: str | None = None, level: int = 1, risk: int = 1) -> SqlmapResult:
        self.guard.check(url)
        if not self.available():
            return SqlmapResult(returncode=-1, stdout="",
                                 stderr="sqlmap binary not found on PATH", command=[])

        # Per-invocation output dir + --flush-session so concurrent sqlmap runs
        # (parallel lanes on the SAME host, e.g. DVWA+bWAPP both 'localhost')
        # never share output/<host>/session.sqlite. The injection verdict is
        # unchanged; this is pure isolation. Cleaned up in the finally below.
        outdir = tempfile.mkdtemp(prefix="sqlmap-")
        args = list(self.binary) + ["-u", url, "--batch",
                                    f"--level={level}", f"--risk={risk}",
                                    f"--output-dir={outdir}", "--flush-session"]
        if data:
            # POST body (e.g. a JSON login). sqlmap auto-detects a JSON body and
            # injects its values; this is how a modern REST endpoint is tested.
            args += ["--data", data]
        if self.cookie:
            args += ["--cookie", self.cookie]
        if extra_args:
            for a in extra_args:
                # Refuse any argument that looks like it targets another host.
                if a.startswith("-u") or "://" in a:
                    self.guard.check(a.split("=", 1)[-1])
            args += extra_args

        try:
            try:
                proc = subprocess.run(args, capture_output=True, text=True,
                                      timeout=self.timeout_s)
            except subprocess.TimeoutExpired as e:
                # Return whatever sqlmap printed before the timeout rather than
                # crashing the RUN_TOOL action; detection usually completes first.
                out = e.stdout or ""
                err = e.stderr or ""
                if isinstance(out, bytes):
                    out = out.decode("utf-8", "replace")
                if isinstance(err, bytes):
                    err = err.decode("utf-8", "replace")
                return SqlmapResult(returncode=-2, stdout=out,
                                     stderr=(err + "\n[sqlmap timed out]").strip(),
                                     command=args)
            return SqlmapResult(returncode=proc.returncode, stdout=proc.stdout,
                                 stderr=proc.stderr, command=args)
        finally:
            shutil.rmtree(outdir, ignore_errors=True)
