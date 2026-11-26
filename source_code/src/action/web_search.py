"""Web search for KNOWLEDGE gathering (plan7.md req K, authorized 2026-10-14).

The agent emits a WEB_SEARCH action to look up a technique / payload it does not
know; results return into its context and are promoted into memory. Deliberate,
explicit exception to localhost-only (CLAUDE.md SS5): reads PUBLIC docs only, the
attack target stays DVWA on localhost.

BACKEND (2026-10-14): DuckDuckGo and Bing are blocked/intercepted on this
connection (Telkomsel returns a captive-portal TLS cert for them), so a generic
search engine is unusable here. Instead we query PayloadsAllTheThings -- the
canonical, reachable (raw.githubusercontent.com = HTTP 200) pentest payload repo
-- mapped by vulnerability class, and return the lines most relevant to the
query. This is higher-signal for pentest knowledge than a generic web search
anyway. Degrades to [] on any error so a failed lookup never crashes a run.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

import requests

# PayloadsAllTheThings sections per DVWA vuln_type (raw GitHub, reachable).
_PATT = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master"
_SECTION = {
    "sqli": f"{_PATT}/SQL%20Injection/README.md",
    "sqli_blind": f"{_PATT}/SQL%20Injection/MySQL%20Injection.md",
    "xss_reflected": f"{_PATT}/XSS%20Injection/README.md",
    "xss_stored": f"{_PATT}/XSS%20Injection/README.md",
    "xss_dom": f"{_PATT}/XSS%20Injection/README.md",
    "cmdi": f"{_PATT}/Command%20Injection/README.md",
    "fi": f"{_PATT}/File%20Inclusion/README.md",
    "upload": f"{_PATT}/Upload%20Insecure%20Files/README.md",
    "csrf": f"{_PATT}/CSRF%20Injection/README.md",
    "open_redirect": f"{_PATT}/Open%20Redirect/README.md",
    "brute": f"{_PATT}/Account%20Takeover/README.md",
}


@dataclass
class WebResult:
    title: str
    snippet: str
    url: str

    def line(self) -> str:
        return f"- {self.snippet} ({self.title})"


def _stopwords(q: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9]+", q.lower()) if len(w) > 2}


def web_search(query: str, max_results: int = 5, vuln_type: str = "") -> list[WebResult]:
    """Fetch the authoritative payload section for this vuln class and return the
    lines most relevant to the query. Returns [] on failure."""
    query = (query or "").strip()
    url = _SECTION.get(vuln_type)
    if url is None:
        # Pick a section from keywords in the query when vuln_type is unknown.
        for key, u in _SECTION.items():
            if key.split("_")[0] in query.lower():
                url = u
                break
    if url is None:
        return []
    try:
        resp = requests.get(url, timeout=12)
        if resp.status_code != 200:
            return []
        text = resp.text
    except Exception:
        return []

    # Rank non-trivial lines (payload / technique lines) by keyword overlap.
    terms = _stopwords(query) or {vuln_type}
    scored: list[tuple[int, str]] = []
    for ln in text.splitlines():
        s = ln.strip().lstrip("#*->` ").strip()
        if len(s) < 8 or len(s) > 300:
            continue
        score = sum(1 for t in terms if t in s.lower())
        if score > 0:
            scored.append((score, s))
    scored.sort(key=lambda x: x[0], reverse=True)
    seen, out = set(), []
    for _, s in scored:
        if s in seen:
            continue
        seen.add(s)
        out.append(WebResult(title="PayloadsAllTheThings", snippet=s[:280], url=url))
        if len(out) >= max_results:
            break
    return out


def block(query: str, results: list[WebResult]) -> str:
    if not results:
        return f"Web search for '{query}' returned no usable results."
    body = "\n".join(r.line() for r in results)
    return (f"Web search results for '{query}' (PayloadsAllTheThings -- public reference, "
            f"adapt to the DVWA target):\n{body}")
