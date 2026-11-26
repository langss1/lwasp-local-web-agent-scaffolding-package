"""Progress-protection controller (N2, rule-based = condition C1). plan9.md S5.

Core idea: the current controller abandons a branch purely on repeated failure
(`StateGraph.branch_dead` = consecutive_fails >= threshold). That prunes branches
that are still making *diagnostic progress* (e.g. boolean-blind SQLi accumulating
one bit per attempt looks like repeated "failure"). This module adds a rule that
WITHHOLDS the redirect while the branch keeps producing NEW diagnostic evidence,
and only permits the redirect once a bounded no-progress streak is reached.

No ML here (that is C2 / M4). This is a deterministic, auditable policy over an
evidence ledger, so it can be unit-tested with synthetic trajectories.

Key terms:
  * evidence signature = a cheap, stable fingerprint of what was observed
    (response signature + outcome token). A genuinely different observation is
    "new information".
  * patience = how many CONSECUTIVE no-new-information attempts are tolerated
    (bounded, frozen before any experiment) before a dead branch may be redirected.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


def context_key(context: dict[str, Any]) -> tuple:
    return (context.get("endpoint"), context.get("param"), context.get("dvwa_level"))


def evidence_token(observation: dict[str, Any]) -> str:
    """SEMANTIC label of WHAT was diagnostically observed (audit GPT 2026-10-18).

    A NEW token in a context = genuinely NEW diagnostic information, NOT merely a
    different response body. The old version keyed on the raw response signature
    (prior_response_sig), so any cosmetic/dynamic byte change counted as "progress"
    -- too naive. This version keys only on MEANINGFUL diagnostic signals:
      - verified success,
      - SQL error family (new error type = new info),
      - boolean-blind bit (true/false),
      - a COARSE response-size bucket (200-char buckets, so a real size change
        registers but pixel-level noise does not),
      - HTTP status.
    So two syntactically different payloads whose observations carry the same
    diagnostic meaning collapse to the SAME token (no false "progress"), while a
    new error / new blind bit / real size change does register as progress.
    """
    if observation.get("success"):
        return "success"
    parts: list[str] = []
    err = observation.get("error_sig")
    if err and err not in ("none", ""):
        parts.append("err:" + re.sub(r"\s+", "_", str(err).lower())[:40])
    signal = str(observation.get("signal", "")).lower()
    if "exists in the database" in signal or "user id exists" in signal:
        parts.append("blind:true")
    elif "missing from the database" in signal:
        parts.append("blind:false")
    rl = observation.get("resp_len")
    if rl is not None:
        parts.append(f"len:{int(rl) // 200}")          # coarse bucket, not exact bytes
    status = observation.get("http_status")
    if status is not None:
        parts.append(f"st:{status}")
    return "|".join(sorted(parts)) if parts else "no_effect"


@dataclass
class _CtxState:
    seen: set[str] = field(default_factory=set)
    stale_streak: int = 0        # consecutive no-new-information observations
    new_info_count: int = 0
    observations: int = 0


class EvidenceLedger:
    """Per-context record of distinct evidence seen, and whether the latest
    observation added new information."""

    def __init__(self) -> None:
        self._ctx: dict[tuple, _CtxState] = {}

    def observe(self, context: dict[str, Any], observation: dict[str, Any]) -> bool:
        """Record an observation; return True iff it added NEW diagnostic info."""
        k = context_key(context)
        st = self._ctx.setdefault(k, _CtxState())
        st.observations += 1
        tok = evidence_token(observation)
        is_new = tok not in st.seen
        if is_new:
            st.seen.add(tok)
            st.stale_streak = 0
            st.new_info_count += 1
        else:
            st.stale_streak += 1
        return is_new

    def stale_streak(self, context: dict[str, Any]) -> int:
        st = self._ctx.get(context_key(context))
        return st.stale_streak if st else 0

    def stats(self, context: dict[str, Any]) -> dict[str, int]:
        st = self._ctx.get(context_key(context))
        if not st:
            return {"distinct": 0, "stale_streak": 0, "observations": 0}
        return {"distinct": len(st.seen), "stale_streak": st.stale_streak,
                "observations": st.observations}


class ProgressController:
    """Decides whether a redirect that the base controller WOULD perform
    (branch dead) is allowed yet, protecting branches still making progress.

    patience: consecutive no-new-information attempts tolerated before a dead
              branch may be redirected. Bounded -> cannot hold forever; the
              graph's hard limits (max_depth/branching, max_iterations) still apply.
    """

    def __init__(self, ledger: EvidenceLedger, patience: int = 2) -> None:
        self.ledger = ledger
        self.patience = patience
        self.holds = 0           # redirects withheld to protect progress
        self.redirects = 0       # redirects permitted

    def allow_redirect(self, branch_dead: bool, context: dict[str, Any]) -> bool:
        """True = permit the redirect/backtrack. False = HOLD (keep refining).

        A redirect is permitted only when the branch is dead AND the branch has
        gone `patience` consecutive observations without new information."""
        if not branch_dead:
            return False
        if self.ledger.stale_streak(context) >= self.patience:
            self.redirects += 1
            return True
        self.holds += 1
        return False
