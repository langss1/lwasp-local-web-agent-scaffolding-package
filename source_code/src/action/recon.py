"""K4 -- Recon / perception (plan16).

Lets the agent DISCOVER the attack surface itself (endpoints, parameters, tech,
WAF) instead of being spoon-fed endpoint+param+method by scenarios.yaml -- the
B-layer overfit in B8_DESAIN §2 (at a target without a scenario file the current
agent is blind). Wraps the standard Kali recon tools, scope-locked to the
allowlist, and parses their output into a compact structured finding the agent
can reason over.

Same conventions as sqlmap_runner.py: subprocess + ScopeGuard + graceful
degradation (a missing tool returns an empty finding with a note, never a crash,
so a run on a host lacking a tool -- e.g. Windows dev -- still completes).

Tool execution is Linux/Kali (verified on pod). The PARSERS below are pure
functions, unit-tested with captured fixture output, so parsing logic is proven
off-pod.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field

from src.action.scope_guard import ScopeGuard


@dataclass
class ReconFinding:
    tech: list[str] = field(default_factory=list)       # whatweb fingerprints
    waf: str | None = None                               # wafw00f
    params: list[str] = field(default_factory=list)      # arjun
    paths: list[str] = field(default_factory=list)       # ffuf/gobuster
    notes: list[str] = field(default_factory=list)       # tool-missing / errors

    def summary(self) -> str:
        """Compact one-block summary for the prompt (kept small on purpose)."""
        out = []
        if self.tech:
            out.append("tech: " + ", ".join(self.tech[:12]))
        if self.waf:
            out.append("waf: " + self.waf)
        if self.params:
            out.append("params found: " + ", ".join(self.params[:20]))
        if self.paths:
            out.append("paths found: " + ", ".join(self.paths[:20]))
        for n in self.notes:
            out.append("note: " + n)
        return "\n".join(out) if out else "(recon produced no findings)"


# --------------------------------------------------------------------------
# PURE PARSERS (unit-tested off-pod with fixtures)
# --------------------------------------------------------------------------

def parse_whatweb(stdout: str) -> list[str]:
    """whatweb prints e.g.:
    http://localhost/dvwa [200 OK] Apache[2.4.58], PHP[8.2.4], JQuery, X-Powered-By[PHP/8.2.4]
    Also supports `--log-json`. Extract the technology tokens (name, dropping the
    [version] detail into 'name version')."""
    techs: list[str] = []
    # Try JSON lines first (whatweb --log-json -).
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("{") and '"plugins"' in line:
            try:
                obj = json.loads(line)
                for name, detail in (obj.get("plugins") or {}).items():
                    ver = ""
                    if isinstance(detail, dict):
                        v = detail.get("version") or detail.get("string")
                        if isinstance(v, list) and v:
                            ver = str(v[0])
                        elif isinstance(v, str):
                            ver = v
                    techs.append(f"{name} {ver}".strip())
                if techs:
                    return _dedup(techs)
            except Exception:
                pass
    # Fallback: the human line "Name[version], Other, ..."
    m = re.search(r"\[\d{3}[^\]]*\]\s*(.+)$", stdout.strip().splitlines()[-1]) if stdout.strip() else None
    blob = m.group(1) if m else stdout
    for tok in re.split(r",\s*", blob):
        tok = tok.strip()
        if not tok:
            continue
        mm = re.match(r"([A-Za-z0-9_\-]+)(?:\[([^\]]+)\])?", tok)
        if mm:
            name, ver = mm.group(1), (mm.group(2) or "")
            if name and name.lower() not in ("http", "https"):
                techs.append(f"{name} {ver}".strip())
    return _dedup(techs)


def parse_wafw00f(stdout: str) -> str | None:
    """wafw00f prints 'The site ... is behind <WAF> WAF.' or 'No WAF detected'."""
    m = re.search(r"is behind\s+(.+?)\s+WAF", stdout, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    if re.search(r"seems to be behind a WAF", stdout, re.IGNORECASE):
        m2 = re.search(r"behind a WAF.*?:\s*(.+)", stdout, re.IGNORECASE)
        return m2.group(1).strip() if m2 else "unknown WAF"
    return None


def parse_arjun(stdout: str) -> list[str]:
    """arjun (text run) prints 'parameters found: a, b, c' or one per line with
    a [+] prefix; `-oJ` writes JSON {"url": {"params": [...]}}. Handle both."""
    params: list[str] = []
    # JSON output
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                for v in obj.values() if isinstance(obj, dict) else []:
                    if isinstance(v, dict) and isinstance(v.get("params"), list):
                        params += [str(p) for p in v["params"]]
                    elif isinstance(v, list):
                        params += [str(p) for p in v]
            except Exception:
                pass
    if params:
        return _dedup(params)
    # Text output
    m = re.search(r"parameters?\s+found\s*:?\s*(.+)", stdout, re.IGNORECASE)
    if m:
        params += [p.strip() for p in re.split(r"[,\s]+", m.group(1)) if p.strip()]
    for line in stdout.splitlines():
        mm = re.match(r"\s*\[\+\]\s*(?:parameter\s+)?([A-Za-z0-9_\-]+)", line, re.IGNORECASE)
        if mm:
            params.append(mm.group(1))
    return _dedup(params)


def parse_ffuf(stdout: str) -> list[str]:
    """ffuf -of json writes {"results":[{"url":..,"input":{"FUZZ":"admin"},"status":200}]}.
    Also parse the plain console '<path> [Status: 200, ...]'. Keep only 2xx/3xx/401/403
    (interesting), drop 404."""
    paths: list[str] = []
    # JSON
    try:
        start = stdout.find("{")
        if start >= 0:
            obj = json.loads(stdout[start:])
            for r in obj.get("results", []):
                status = r.get("status", 0)
                val = (r.get("input") or {}).get("FUZZ") or r.get("url", "")
                if val and (200 <= status < 400 or status in (401, 403)):
                    paths.append(str(val))
            if paths:
                return _dedup(paths)
    except Exception:
        pass
    # Console
    for line in stdout.splitlines():
        m = re.search(r"^\s*(\S+)\s+\[Status:\s*(\d{3})", line)
        if m:
            status = int(m.group(2))
            if 200 <= status < 400 or status in (401, 403):
                paths.append(m.group(1))
    return _dedup(paths)


def _dedup(items: list[str]) -> list[str]:
    seen: list[str] = []
    for it in items:
        if it and it not in seen:
            seen.append(it)
    return seen


# --------------------------------------------------------------------------
# RUNNER (Linux/Kali; graceful if a tool is absent)
# --------------------------------------------------------------------------

class ReconRunner:
    def __init__(self, allowlist: list[str], timeout_s: int = 90,
                 wordlist: str | None = None):
        self.guard = ScopeGuard(allowlist)
        self.timeout_s = timeout_s
        # A small built-in path list keeps ffuf bounded; override with a real
        # SecLists path on the pod.
        self.wordlist = wordlist

    def _run(self, args: list[str]) -> str:
        try:
            proc = subprocess.run(args, capture_output=True, text=True,
                                  timeout=self.timeout_s)
            return (proc.stdout or "") + (proc.stderr or "")
        except subprocess.TimeoutExpired:
            return "__TIMEOUT__"
        except Exception as e:  # noqa: BLE001
            return f"__ERR__ {type(e).__name__}"

    def fingerprint(self, url: str) -> ReconFinding:
        """whatweb + wafw00f. Never raises: missing tool -> note."""
        self.guard.check(url)
        f = ReconFinding()
        if shutil.which("whatweb"):
            out = self._run(["whatweb", "--color=never", "-a", "1", url])
            if out.startswith("__"):
                f.notes.append(f"whatweb {out}")
            else:
                f.tech = parse_whatweb(out)
        else:
            f.notes.append("whatweb not installed")
        if shutil.which("wafw00f"):
            out = self._run(["wafw00f", url])
            if out.startswith("__"):
                f.notes.append(f"wafw00f {out}")
            else:
                f.waf = parse_wafw00f(out)
        else:
            f.notes.append("wafw00f not installed")
        return f

    def discover_params(self, url: str) -> list[str]:
        self.guard.check(url)
        if not shutil.which("arjun"):
            return []
        out = self._run(["arjun", "-u", url, "-oT", "/dev/stdout"])
        return [] if out.startswith("__") else parse_arjun(out)

    def discover_paths(self, url: str) -> list[str]:
        self.guard.check(url)
        if not shutil.which("ffuf") or not self.wordlist:
            return []
        base = url.rstrip("/") + "/FUZZ"
        out = self._run(["ffuf", "-u", base, "-w", self.wordlist, "-of", "json",
                         "-o", "/dev/stdout", "-s"])
        return [] if out.startswith("__") else parse_ffuf(out)

    def recon(self, url: str) -> ReconFinding:
        """Full pass: fingerprint + params (+ paths if a wordlist is set)."""
        f = self.fingerprint(url)
        f.params = self.discover_params(url)
        f.paths = self.discover_paths(url)
        return f
