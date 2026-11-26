"""Live integration of the trained N3 evidence oracle (eyes=ML / condition P1) and
the N4 learned promise scorer (condition C2). plan9.md M5.

N3Oracle: given an executed attempt's response, predict the evidence class and attach
it to the agent's FEEDBACK signal. It does NOT decide success (the independent
verifier/interpreter still does) -- it changes what the agent *reads*, isolating the
value of ML perception (P1) vs the deterministic interpreter (P0).

PromptScorer: given the trajectory-prefix features, predict a promise in [0,1] used to
fill node.score so backtracking prefers higher-promise branches (C2 vs C1).

Both load frozen artefacts trained on DVWA (data/n3_model.joblib, data/n4_promise_model.joblib).
Embedding uses the orchestrator's embed_fn (nomic-embed-text, local). Degrades to no-op
if artefacts are missing.
"""
from __future__ import annotations
import re
from pathlib import Path
from typing import Any, Callable

import numpy as np

ROOT = Path(__file__).resolve().parent.parent.parent
_SQL_ERR = ("you have an error in your sql syntax", "unknown column", "mysql",
            "sqlstate", "query failure", "lookup error", "unrecognized token", "no such column")

# must match eval/train_n3.py RAW_FEATS order
RAW_FEATS = ["status", "body_len", "elapsed_ms", "delta_len", "char_diff_ratio",
             "payload_len", "p_quote", "p_angle", "p_union", "p_comment",
             "p_tautology", "p_false", "level_ord", "fam_sqli", "fam_blind", "fam_xss"]
_LVL = {"low": 0, "medium": 1, "high": 2}
_FAM = {"sqli": (1, 0, 0), "sqli_blind": (0, 1, 0), "xss_reflected": (0, 0, 1)}


def _raw_features(family, level, payload, body, status, elapsed_ms, base_body):
    import difflib
    a, b = (base_body or "")[:4000], (body or "")[:4000]
    diff = difflib.SequenceMatcher(None, a, b).quick_ratio() if (a or b) else 1.0
    low = payload.lower()
    fam = _FAM.get(family, (0, 0, 0))
    return [
        status, len(body or ""), round(elapsed_ms, 1), len(body or "") - len(base_body or ""),
        round(diff, 4), len(payload),
        int("'" in payload or "%27" in low or "&#39;" in payload),
        int("<" in payload), int("union" in low), int("--" in payload or "#" in payload),
        int("1=1" in payload or "'1'='1" in payload), int("1=2" in payload or "'1'='2" in payload),
        _LVL.get(level, 0), *fam,
    ]


class N3Oracle:
    def __init__(self, embed_fn: Callable[[str], list[float]], model_path: str | None = None):
        import joblib
        p = Path(model_path) if model_path else ROOT / "data" / "n3_model.joblib"
        self.ok = p.exists()
        self.embed_fn = embed_fn
        self._base: dict[str, str] = {}
        self.feat_idx = None
        if self.ok:
            b = joblib.load(p)
            self.model, self.labels = b["model"], b["labels"]
            # model may be trained on a feature SUBSET (domain-invariant); match it.
            self.feat_idx = b.get("feat_idx")

    def set_baseline(self, endpoint: str, benign_body: str) -> None:
        """Register the BENIGN baseline response for an endpoint, so the char-diff
        feature matches how N3 was TRAINED (collector used a benign baseline, not the
        first attack response). audit GPT 2026-10-18 -- train/runtime baseline contract."""
        self._base[endpoint] = benign_body or ""

    def predict(self, family, level, payload, body, status, elapsed_ms, endpoint) -> tuple[str, float]:
        if not self.ok:
            return ("", 0.0)
        # prefer the registered BENIGN baseline; fall back to first-seen only if unset.
        base = self._base.setdefault(endpoint, body or "")
        raw = np.array(_raw_features(family, level, payload, body, status, elapsed_ms, base),
                       dtype=np.float32)
        if self.feat_idx is not None:          # match the subset the model was trained on
            raw = raw[self.feat_idx]
        try:
            emb = np.array(self.embed_fn((body or "")[:2000]), dtype=np.float32)
        except Exception:
            return ("", 0.0)
        X = np.hstack([raw, emb]).reshape(1, -1)
        try:
            proba = self.model.predict_proba(X)[0]
            j = int(np.argmax(proba))
            return (self.model.classes_[j], float(proba[j]))
        except Exception:
            return (str(self.model.predict(X)[0]), 0.0)


class PromiseScorer:
    """C2: learned promise over trajectory prefix features (n4 model)."""
    FEATS = ["iter", "payload_len", "has_err", "is_http", "n_fail",
             "distinct_evi", "stale_streak", "is_new_info", "level", "fam_sqli", "fam_blind", "fam_xss"]

    def __init__(self, model_path: str | None = None):
        import joblib
        p = Path(model_path) if model_path else ROOT / "data" / "n4_promise_model.joblib"
        self.ok = p.exists()
        if self.ok:
            b = joblib.load(p)
            self.model = b["model"]

    def score(self, feats: dict[str, Any]) -> float:
        if not self.ok:
            return 0.5
        x = np.array([[feats.get(k, 0) for k in self.FEATS]], dtype=np.float32)
        try:
            return float(self.model.predict_proba(x)[0][1])
        except Exception:
            return 0.5
