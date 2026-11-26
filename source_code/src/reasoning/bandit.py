"""K14 -- Contextual bandit (LinUCB) for tool/payload-family selection (plan16).

A SCAFFOLD policy, not a change to the base model (which stays frozen): given a
context vector (phase, vuln-family, level, WAF present, #fails so far), choose
which action family to try next -- {sqlmap, commix, hydra, dalfox, manual-union,
manual-boolean, ...} -- and learn from the oracle's reward (success/fail). This
is the gradient-free "learn which weapon works where" layer (LinUCB, Li et al.
WWW'10, B8_DESAIN §9.G ref [81]).

SAFETY: the bandit only picks WHAT TO TRY. It never decides success -- that is
K7's job. A bad bandit only wastes iterations (lower SR), it can never create a
false positive. Reward comes from the universal oracle's verdict.

Persists arm state to disk so learning carries across runs (toggleable for
ablation). Cold-starts gracefully. numpy only. Fully unit-tested off-pod.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent.parent


class LinUCB:
    """Disjoint LinUCB: one ridge-regression model per arm, UCB exploration."""

    def __init__(self, arms: list[str], dim: int, alpha: float = 1.0,
                 store_path: str | None = None):
        self.arms = list(arms)
        self.dim = dim
        self.alpha = alpha                       # exploration strength
        self.store_path = Path(store_path) if store_path else None
        # A = identity (d x d), b = zero (d) per arm.
        self.A = {a: np.identity(dim) for a in self.arms}
        self.b = {a: np.zeros(dim) for a in self.arms}
        if self.store_path and self.store_path.exists():
            self._load()

    # -- core -------------------------------------------------------------
    def _ucb(self, arm: str, x: np.ndarray) -> float:
        A_inv = np.linalg.inv(self.A[arm])
        theta = A_inv @ self.b[arm]
        mean = float(theta @ x)
        bonus = self.alpha * float(np.sqrt(x @ A_inv @ x))
        return mean + bonus

    def select(self, context: dict | np.ndarray, allowed: list[str] | None = None) -> str:
        x = self._vec(context)
        pool = [a for a in self.arms if (allowed is None or a in allowed)]
        if not pool:
            pool = self.arms
        # Highest UCB; ties broken by arm order (deterministic given same state).
        scored = [(self._ucb(a, x), a) for a in pool]
        scored.sort(key=lambda t: (-t[0], self.arms.index(t[1])))
        return scored[0][1]

    def update(self, arm: str, context: dict | np.ndarray, reward: float) -> None:
        if arm not in self.A:                    # unknown arm -> register cold
            self.A[arm] = np.identity(self.dim)
            self.b[arm] = np.zeros(self.dim)
            self.arms.append(arm)
        x = self._vec(context)
        self.A[arm] += np.outer(x, x)
        self.b[arm] += reward * x
        if self.store_path:
            self._save()

    # -- context encoding -------------------------------------------------
    def _vec(self, context: dict | np.ndarray) -> np.ndarray:
        if isinstance(context, np.ndarray):
            v = context.astype(np.float32)
        else:
            v = np.array([float(context.get(f"f{i}", 0.0)) for i in range(self.dim)],
                         dtype=np.float32)
        if v.shape[0] != self.dim:
            raise ValueError(f"context dim {v.shape[0]} != {self.dim}")
        return v

    # -- persistence ------------------------------------------------------
    def _save(self) -> None:
        try:
            import joblib
            self.store_path.parent.mkdir(parents=True, exist_ok=True)
            joblib.dump({"arms": self.arms, "dim": self.dim,
                         "A": self.A, "b": self.b}, self.store_path)
        except Exception:
            pass   # persistence is best-effort; never crash a run

    def _load(self) -> None:
        try:
            import joblib
            blob = joblib.load(self.store_path)
            if blob.get("dim") == self.dim:
                self.arms = blob["arms"]
                self.A = blob["A"]
                self.b = blob["b"]
        except Exception:
            pass
