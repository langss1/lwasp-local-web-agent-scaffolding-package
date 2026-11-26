"""K7 -- Universal oracle (plan16). THE arbiter of success.

The whole paper rests on this verdict being honest (B8_DESAIN §7 flaw #1: a
false-positive = fake success = credibility gone). So the rule is deliberately
conservative and category-free:

  * A verdict is SUCCESS only when at least one STRONG, deterministic/out-of-band
    signal is positive:
        - differential : injected response differs from the control baseline in a
                          way that means data/rows leaked (not just any diff)
        - marker       : an interpret_* oracle marker fired (SQL rows, cmd output,
                          file contents, 'Well done', etc.)
        - time_based   : injected response is slower than baseline past a margin
                          (blind time-based)
        - oast         : the target made an out-of-band callback (K8) -- blind
                          SSRF/cmdi/XXE/OOB-SQLi
        - browser_exec : the headless verifier saw JS actually execute (XSS)
  * N3 (ML) is ADVISORY ONLY. It can raise confidence when it AGREES with a strong
    signal, and it can flag "review" when it is confident but no strong signal
    fired -- but it can NEVER, alone, turn a non-success into a success. This is
    what makes a mediocre/ drifting N3 unable to poison the result.
  * When signals conflict or all are weak/absent-but-N3-positive -> ABSTAIN, not
    success. Abstaining is correct behaviour, not a failure.

Pure logic, no I/O: the orchestrator computes the Signals from its existing
interpret_* helpers + OAST listener + browser verifier + N3, then calls judge().
Fully unit-tested off-pod.
"""

from __future__ import annotations

from dataclasses import dataclass, field

STRONG = "strong"
ADVISORY = "advisory"


@dataclass
class Signal:
    name: str
    kind: str                 # STRONG | ADVISORY
    positive: bool
    detail: str = ""
    score: float = 1.0        # advisory confidence (0..1); strong uses 1.0


@dataclass
class UniversalVerdict:
    verdict: str              # "success" | "fail" | "abstain"
    confidence: float
    strong_signals: list[str] = field(default_factory=list)
    advisory: dict[str, float] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)
    rationale: str = ""

    @property
    def success(self) -> bool:
        return self.verdict == "success"

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict, "confidence": round(self.confidence, 3),
            "strong_signals": self.strong_signals, "advisory": self.advisory,
            "evidence": self.evidence, "rationale": self.rationale,
        }


# -- signal builders (used by the orchestrator to translate its raw results) --

def differential_signal(baseline_rows: int, injected_rows: int) -> Signal:
    pos = injected_rows > baseline_rows and injected_rows >= 2
    return Signal("differential", STRONG, pos,
                  f"rows {baseline_rows}->{injected_rows}")


def marker_signal(interpret_result: dict) -> Signal:
    pos = bool(interpret_result.get("success"))
    return Signal("marker", STRONG, pos, str(interpret_result.get("signal", ""))[:160])


def time_based_signal(baseline_ms: float, injected_ms: float, margin_ms: float = 4000) -> Signal:
    pos = injected_ms - baseline_ms >= margin_ms
    return Signal("time_based", STRONG, pos,
                  f"{baseline_ms:.0f}ms->{injected_ms:.0f}ms (margin {margin_ms:.0f})")


def oast_signal(confirmed: bool, token: str = "") -> Signal:
    return Signal("oast", STRONG, bool(confirmed), f"callback token={token}" if token else "")


def browser_exec_signal(executed: bool, detail: str = "") -> Signal:
    return Signal("browser_exec", STRONG, bool(executed), detail[:160])


def n3_signal(score: float, threshold: float = 0.7) -> Signal:
    return Signal("n3", ADVISORY, score >= threshold, f"score={score:.2f}", score=score)


class UniversalOracle:
    def __init__(self, n3_review_threshold: float = 0.85):
        # If N3 is this confident but NO strong signal fired, flag for manual
        # review (abstain-review) rather than discarding -- but still never call
        # it a success.
        self.n3_review_threshold = n3_review_threshold

    def judge(self, signals: list[Signal]) -> UniversalVerdict:
        strong_pos = [s for s in signals if s.kind == STRONG and s.positive]
        strong_neg = [s for s in signals if s.kind == STRONG and not s.positive]
        advisory = {s.name: s.score for s in signals if s.kind == ADVISORY}
        evidence = [f"{s.name}: {s.detail}" for s in signals if s.detail]

        n3 = next((s for s in signals if s.name == "n3"), None)

        if strong_pos:
            # SUCCESS: >=1 independent strong signal. More strong signals + N3
            # agreement raise confidence; a lone strong signal is still success
            # but at lower confidence (invites a re-test upstream).
            base = min(1.0, 0.75 + 0.15 * (len(strong_pos) - 1))
            if n3 is not None and n3.positive:
                base = min(1.0, base + 0.1)
            names = [s.name for s in strong_pos]
            rationale = (f"{len(strong_pos)} strong signal(s) positive ({', '.join(names)})"
                         + ("; N3 agrees (advisory)" if n3 and n3.positive else ""))
            return UniversalVerdict("success", base, names, advisory, evidence, rationale)

        # No strong-positive => cannot be success, whatever N3 says.
        if n3 is not None and n3.positive and n3.score >= self.n3_review_threshold:
            return UniversalVerdict(
                "abstain", n3.score, [], advisory, evidence,
                rationale=("N3 is confident but NO strong signal fired -> abstain "
                           "(flag for manual review). N3 alone can never be success."))

        if strong_neg and not strong_pos:
            # Clear negatives, no positives -> fail.
            return UniversalVerdict(
                "fail", 0.8, [], advisory, evidence,
                rationale="no strong signal positive; " +
                          f"{len(strong_neg)} strong signal(s) negative.")

        # Nothing conclusive either way.
        return UniversalVerdict(
            "abstain", 0.3, [], advisory, evidence,
            rationale="no strong signal fired and no clear negative -> inconclusive.")
