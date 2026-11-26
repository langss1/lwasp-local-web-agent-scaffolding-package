"""K12 -- Context summarizer (plan16).

Rule-based (NOT an LLM) extractive compressor for verbose tool / HTTP output
before it enters the prompt. A Kali tool (nuclei, sqlmap -v, whatweb, nikto) can
emit many KB per call; with num_ctx=5120 that blows the window and the agent dies
mid-run (the CHAP / HackSynth failure mode, B8_DESAIN §6.C).

Design constraints (why rule-based, not an LLM):
  * REPRODUCIBLE -- no sampling, so a smoke/sweep run is deterministic given the
    same tool output. An LLM summarizer would add nondeterminism + token cost.
  * CANNOT DROP AN ORACLE SIGNAL -- lines matching `keep_patterns` are preserved
    verbatim and never truncated. The oracle's own markers (SQL rows, command
    output, file-inclusion contents, OAST hits, HTTP errors) are passed in by the
    caller, so compression can never hide the one line that proves success.

Everything NOT matched is head+tail kept with the middle elided, so the agent
still sees the shape of the output without the bulk.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Signals that must survive compression no matter what. The orchestrator extends
# this with the active scenario's own oracle markers (interpret_* markers) so the
# summarizer is oracle-aware without importing the orchestrator (no cycle).
DEFAULT_KEEP: tuple[str, ...] = (
    # HTTP / error shapes
    r"HTTP/\d", r"\b[45]\d\d\b", r"(?i)\berror\b", r"(?i)exception", r"(?i)traceback",
    r"(?i)warning", r"(?i)denied", r"(?i)forbidden",
    # generic exploit evidence
    r"(?i)vulnerab", r"(?i)inject", r"(?i)payload", r"(?i)success",
    r"root:x:", r"uid=", r"(?i)Directory of", r"(?i)Volume Serial",
    # OAST / nuclei / sqlmap hit lines
    r"(?i)\[.*\]", r"(?i)interact\.sh", r"(?i)oast", r"(?i)callback",
    r"(?i)is vulnerable", r"(?i)parameter .* appears to be",
)


@dataclass
class ContextSummarizer:
    """Compress a block of tool/HTTP output to <= max_chars while preserving every
    line that matches a keep-pattern.
    """
    max_chars: int = 1200
    head_lines: int = 6
    tail_lines: int = 6
    keep_patterns: tuple[str, ...] = DEFAULT_KEEP
    _compiled: list[re.Pattern] = field(default_factory=list, init=False, repr=False)

    def __post_init__(self) -> None:
        self._compiled = [re.compile(p) for p in self.keep_patterns]

    def with_markers(self, markers: list[str]) -> "ContextSummarizer":
        """Return a summarizer that also keeps these literal oracle markers
        (escaped so they match as substrings, not regex). Used by the orchestrator
        to inject the active scenario's interpret_* markers."""
        extra = tuple(re.escape(m) for m in markers if m)
        return ContextSummarizer(self.max_chars, self.head_lines, self.tail_lines,
                                 self.keep_patterns + extra)

    def _is_kept(self, line: str) -> bool:
        return any(p.search(line) for p in self._compiled)

    def summarize(self, text: str) -> str:
        if not text:
            return text
        if len(text) <= self.max_chars:
            return text
        lines = text.splitlines()
        kept_idx = {i for i, ln in enumerate(lines) if self._is_kept(ln)}
        # Always keep head + tail so the output's shape stays legible.
        for i in range(min(self.head_lines, len(lines))):
            kept_idx.add(i)
        for i in range(max(0, len(lines) - self.tail_lines), len(lines)):
            kept_idx.add(i)

        out: list[str] = []
        prev = -1
        for i in sorted(kept_idx):
            if i > prev + 1:
                omitted = i - prev - 1
                out.append(f"[... {omitted} line(s) omitted ...]")
            out.append(lines[i])
            prev = i
        if prev < len(lines) - 1:
            out.append(f"[... {len(lines) - 1 - prev} line(s) omitted ...]")

        result = "\n".join(out)
        # Hard cap: if kept lines alone still exceed the budget (pathological: a
        # huge matched line), head/tail-truncate the CHARACTERS but keep both ends
        # so a marker at either end is never lost silently.
        if len(result) > self.max_chars:
            keep = self.max_chars - 40
            half = keep // 2
            result = (result[:half] + f"\n[... {len(result) - keep} chars omitted ...]\n"
                      + result[-half:])
        return result
