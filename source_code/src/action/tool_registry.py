"""MCP-style tool layer: a registry of named tools the agent can discover and
call through a single RUN_TOOL action, instead of each capability being
hard-wired into the orchestrator.

The registry gives two things a bare dispatch does not:

1. **Discovery.** `catalog()` renders the available tools -- their names,
   purpose and parameters -- into the prompt, so the model chooses from what
   actually exists rather than inventing a tool name and failing.
2. **One safe boundary.** Every tool returns an observation dict and never
   raises; a broken tool call becomes a signal the agent can react to, not a
   crashed run. Network-facing tools stay behind scope_guard exactly as before.

Scope discipline for THIS project: the local tools here are read-only and never
touch the network. The only tool that reaches the target (sqlmap) is registered
by the orchestrator with the same ScopeGuard the rest of the action layer uses.
There is no tool that fetches a public URL or shells out to an arbitrary binary
-- that would break the DVWA-only rule this project is built on.
"""

from __future__ import annotations

import base64
import hashlib
import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

MAX_READ_BYTES = 20_000
MAX_GREP_HITS = 40


@dataclass
class Tool:
    name: str
    description: str
    params: dict[str, str]                       # param name -> one-line description
    handler: Callable[[dict], dict]              # args -> observation dict
    example: str = ""

    def signature(self) -> str:
        arg_list = ", ".join(f"{k}=<{v}>" for k, v in self.params.items())
        line = f"- {self.name}({arg_list}): {self.description}"
        if self.example:
            line += f"\n    e.g. {self.example}"
        return line


class ToolRegistry:
    def __init__(self):
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def unregister(self, name: str) -> None:
        """Remove a registered tool if present (used by F3 tool-vuln gating)."""
        self._tools.pop(name, None)

    def names(self) -> list[str]:
        return sorted(self._tools)

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def catalog(self) -> str:
        """Agent-facing tool listing, injected into the prompt for discovery."""
        if not self._tools:
            return "(no tools registered)"
        return "\n".join(self._tools[n].signature() for n in self.names())

    def call(self, name: str, args: dict | None = None) -> dict:
        """Dispatch a tool call. Always returns an observation dict; never raises,
        so a bad call is a signal the agent can recover from, not a crash.
        """
        tool = self._tools.get(name)
        if tool is None:
            return {
                "success": False,
                "signal": (f"Unknown tool '{name}'. Available: "
                           f"{', '.join(self.names()) or '(none)'}."),
            }
        try:
            obs = tool.handler(args or {})
            # Normalise: a handler may return just a signal string.
            if isinstance(obs, str):
                return {"success": False, "signal": obs}
            obs.setdefault("success", False)
            return obs
        except Exception as exc:  # a tool must never take the run down
            return {"success": False, "signal": f"Tool '{name}' errored: {exc}"}


# ---------------------------------------------------------------------------
# Local, read-only, offline tools
# ---------------------------------------------------------------------------

def _tool_encode(args: dict) -> dict:
    """Encode/decode a string deterministically. Useful for adapting a payload
    to a filter (url-encoding, base64, hex, html entities) without guessing.
    """
    text = str(args.get("text", ""))
    scheme = str(args.get("scheme", "url")).lower()
    mode = str(args.get("mode", "encode")).lower()
    try:
        if scheme == "url":
            out = urllib.parse.quote(text) if mode == "encode" else urllib.parse.unquote(text)
        elif scheme == "base64":
            out = (base64.b64encode(text.encode()).decode() if mode == "encode"
                   else base64.b64decode(text.encode()).decode(errors="replace"))
        elif scheme == "hex":
            out = (text.encode().hex() if mode == "encode"
                   else bytes.fromhex(text).decode(errors="replace"))
        elif scheme == "html":
            if mode == "encode":
                out = (text.replace("&", "&amp;").replace("<", "&lt;")
                       .replace(">", "&gt;").replace('"', "&quot;"))
            else:
                out = (text.replace("&lt;", "<").replace("&gt;", ">")
                       .replace("&quot;", '"').replace("&amp;", "&"))
        else:
            return {"success": False,
                    "signal": f"Unknown scheme '{scheme}'. Use: url, base64, hex, html."}
    except Exception as exc:
        return {"success": False, "signal": f"{mode} ({scheme}) failed: {exc}"}
    return {"success": False, "signal": f"{scheme} {mode}: {out}"}


def _tool_hash(args: dict) -> dict:
    """Compute a hash of a string locally (DVWA sometimes stores md5 passwords).
    Local computation replaces the idea of an external hash-lookup site -- this
    project stays offline and on-target.
    """
    text = str(args.get("text", ""))
    algo = str(args.get("algo", "md5")).lower()
    if algo not in hashlib.algorithms_available:
        return {"success": False,
                "signal": f"Unknown hash algo '{algo}'. Try: md5, sha1, sha256."}
    digest = hashlib.new(algo, text.encode()).hexdigest()
    return {"success": False, "signal": f"{algo}({text!r}) = {digest}"}


def _resolve_within(path_str: str, base_dirs: list[Path]) -> Path | None:
    """Resolve `path_str` and confirm it sits inside one of `base_dirs`. Returns
    the resolved path, or None if it escapes every allowed base (path-traversal
    guard -- the same spirit as scope_guard, applied to the filesystem).
    """
    try:
        target = Path(path_str).resolve()
    except (OSError, RuntimeError):
        return None
    for base in base_dirs:
        try:
            if target == base or target.is_relative_to(base):
                return target
        except AttributeError:  # Python < 3.9 has no is_relative_to
            try:
                target.relative_to(base)
                return target
            except ValueError:
                continue
    return None


def _make_read_file(base_dirs: list[Path]) -> Callable[[dict], dict]:
    def handler(args: dict) -> dict:
        target = _resolve_within(str(args.get("path", "")), base_dirs)
        if target is None:
            return {"success": False,
                    "signal": ("Path is outside the readable directories "
                               f"({', '.join(b.name for b in base_dirs)}).")}
        if not target.is_file():
            return {"success": False, "signal": f"Not a file: {target}"}
        data = target.read_text(encoding="utf-8", errors="replace")[:MAX_READ_BYTES]
        return {"success": False, "signal": f"[{target.name}]\n{data}"}
    return handler


def _make_grep(base_dirs: list[Path]) -> Callable[[dict], dict]:
    def handler(args: dict) -> dict:
        pattern = str(args.get("pattern", ""))
        if not pattern:
            return {"success": False, "signal": "grep needs a 'pattern'."}
        try:
            rx = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            return {"success": False, "signal": f"Bad regex: {exc}"}
        hits: list[str] = []
        for base in base_dirs:
            if not base.is_dir():
                continue
            for f in sorted(base.rglob("*")):
                if not f.is_file():
                    continue
                try:
                    for i, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                        if rx.search(line):
                            hits.append(f"{f.name}:{i}: {line.strip()[:200]}")
                            if len(hits) >= MAX_GREP_HITS:
                                break
                except OSError:
                    continue
                if len(hits) >= MAX_GREP_HITS:
                    break
        signal = "\n".join(hits) if hits else "(no matches)"
        return {"success": False, "signal": signal}
    return handler


def build_local_tools(base_dirs: list[Path]) -> list[Tool]:
    """The offline, read-only tool set. `base_dirs` bounds file access (e.g.
    knowledge/ and runs/) so read_file/grep can never wander the whole disk.
    """
    return [
        Tool(
            name="encode",
            description="Encode or decode a string (url/base64/hex/html) to adapt a payload to a filter.",
            params={"text": "string", "scheme": "url|base64|hex|html", "mode": "encode|decode"},
            handler=_tool_encode,
            example='{"tool":"encode","args":{"text":"<script>","scheme":"url","mode":"encode"}}',
        ),
        Tool(
            name="hash",
            description="Compute md5/sha1/sha256 of a string locally.",
            params={"text": "string", "algo": "md5|sha1|sha256"},
            handler=_tool_hash,
            example='{"tool":"hash","args":{"text":"password","algo":"md5"}}',
        ),
        Tool(
            name="read_file",
            description="Read a file from the knowledge/runs directories (read-only).",
            params={"path": "path inside an allowed directory"},
            handler=_make_read_file(base_dirs),
        ),
        Tool(
            name="grep",
            description="Regex-search the local knowledge corpus and run logs.",
            params={"pattern": "regular expression"},
            handler=_make_grep(base_dirs),
            example='{"tool":"grep","args":{"pattern":"UNION SELECT"}}',
        ),
    ]
