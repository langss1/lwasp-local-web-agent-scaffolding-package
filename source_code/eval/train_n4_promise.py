"""M4 — learned promise scorer (C2, plan9.md S5.2). Trains a small sklearn model to
estimate, from the trajectory prefix up to attempt t, the probability that diagnostic
progress OR a verified success occurs within the next K attempts of the SAME run.

Honest protocol:
  * Features use ONLY the prefix up to t (no future info online).
  * Label uses the recorded continuation t+1..t+K (future info for LABEL-MAKING only,
    which is allowed -- plan9.md S5.2). Runs with no recoverable continuation are dropped.
  * Group = run_id (GroupKFold) so no prefix of a run leaks across folds.
  * Report AUROC + F1 + Brier (calibration); this is a PRELIMINARY scorer trained on
    the C0/C1 DEV runs (limited n) -- labelled as such for Bab 4.

Reads runs/c0c1-*/trace.jsonl. Usage: python eval/train_n4_promise.py [K]
"""
from __future__ import annotations
import sys, json, glob
from pathlib import Path
import numpy as np

ROOT = Path(r"C:\Spesial TA\pentest-agent")
sys.path.insert(0, str(ROOT))
from src.reasoning.progress import EvidenceLedger, evidence_token, context_key  # noqa: E402

K = int(sys.argv[1]) if len(sys.argv) > 1 else 3
OUT = ROOT / "report" / "N4_RESULTS.md"
MODEL_OUT = ROOT / "data" / "n4_promise_model.joblib"

FAM = {"sqli": (1, 0, 0), "sqli_blind": (0, 1, 0), "xss": (0, 0, 1)}


def fam_of(run_id: str):
    if "blind" in run_id:
        return "sqli_blind"
    if "xss" in run_id:
        return "xss"
    return "sqli"


def level_of(run_id: str):
    for i, lv in enumerate(("low", "medium", "high")):
        if lv in run_id:
            return i
    return 0


def load_trace(p):
    recs = []
    for ln in open(p, encoding="utf-8"):
        ln = ln.strip()
        if not ln:
            continue
        try:
            recs.append(json.loads(ln))
        except json.JSONDecodeError:
            pass
    return recs


def attempt_records(recs):
    """Keep only executed attempts that carry an observation with a success flag."""
    out = []
    for r in recs:
        a, o = r.get("action", {}), r.get("observation", {})
        if not isinstance(o, dict):
            continue
        if o.get("blocked"):
            continue
        if a.get("type") in ("HTTP_REQUEST", "RUN_TOOL", "RUN_SCRIPT"):
            out.append(r)
    return out


def build():
    X, y, groups = [], [], []
    # FIXED continuation policy (plan9.md S5.2): train the promise label on ONE
    # policy's trajectories. We use the BASE policy (C0) so the label
    # P(progress in <=K | prefix) is defined under a single, consistent continuation
    # policy; C1 trajectories are NOT used for the label (deployment in C1/C2 is a
    # disclosed cold-start / distribution-shift limitation).
    # BASE-policy trajectories only (fixed continuation policy, plan9 S5.2): C0 runs
    # (no progress-protection) from both c0c1 and matrix experiments. More data than before.
    runs = sorted(set(glob.glob(str(ROOT / "runs" / "c0c1-*-C0*" / "trace.jsonl")))
                  | set(glob.glob(str(ROOT / "runs" / "mtx-*-P0C0" / "trace.jsonl"))))
    for tp in runs:
        rid = Path(tp).parent.name
        recs = attempt_records(load_trace(tp))
        if len(recs) < 2:
            continue
        fam = fam_of(rid); lv = level_of(rid)
        led = EvidenceLedger()
        # precompute per-attempt evidence tokens + rolling features
        toks, succ, feats, ctxs = [], [], [], []
        n_fail = 0
        for r in recs:
            o = r["observation"]; a = r["action"]
            param = a.get("params", {}).get("param", "")
            ctx = {"endpoint": fam, "param": param, "dvwa_level": lv}
            ctxs.append((fam, param, lv))     # branch/context key (anti-leak label window)
            is_new = led.observe(ctx, o)
            tok = evidence_token(o)
            s = bool(o.get("success"))
            toks.append(tok); succ.append(s)
            pval = str(a.get("params", {}).get("value", ""))
            if not s:
                n_fail += 1
            st = led.stats(ctx)
            feats.append([
                r.get("iteration", 0), len(pval),
                int(bool(o.get("error_sig") and o.get("error_sig") not in ("none", ""))),
                int(a.get("type") == "HTTP_REQUEST"),
                n_fail, st["distinct"], st["stale_streak"], int(is_new),
                lv, *FAM[fam],
            ])
        # label: progress (new evidence) OR success within next K attempts,
        # restricted to the SAME branch/context (anti-leak: don't credit another
        # branch's progress to this attempt -- audit GPT 2026-10-18).
        for t in range(len(recs) - 1):
            if succ[t]:
                continue  # terminal; exclude
            window = [j for j in range(t + 1, min(t + 1 + K, len(recs))) if ctxs[j] == ctxs[t]]
            seen_before = set(toks[: t + 1])
            prog = any(succ[j] or (toks[j] not in seen_before) for j in window)
            X.append(feats[t]); y.append(int(prog)); groups.append(rid)
    return np.array(X, dtype=np.float32), np.array(y), np.array(groups)


def main():
    X, y, g = build()
    out = ["# N4 — Learned Promise Scorer (C2), hasil M4 (PRELIMINARY, DEV)\n"]
    if len(X) < 20 or len(set(y)) < 2:
        out.append(f"**Data belum cukup**: samples={len(X)}, positif={int(y.sum()) if len(y) else 0}. "
                   "Butuh lebih banyak run C0/C1 selesai dulu. (Scorer tidak dilatih; N2 tetap sah sebagai "
                   "metode berbasis aturan C1 — fallback jujur plan9.md.)\n")
        OUT.write_text("\n".join(out), encoding="utf-8")
        print("insufficient data:", len(X), "samples"); return

    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.pipeline import make_pipeline
    from sklearn.model_selection import GroupKFold
    from sklearn.metrics import roc_auc_score, f1_score, brier_score_loss
    from sklearn.base import clone

    feat_names = ["iter", "payload_len", "has_err", "is_http", "n_fail",
                  "distinct_evi", "stale_streak", "is_new_info", "level", "fam_sqli", "fam_blind", "fam_xss"]
    out.append(f"Samples (attempt-prefix): {len(X)} | positif (progress≤K={K}): {int(y.sum())} "
               f"({100*y.mean():.0f}%) | runs: {len(set(g))} | fitur: {len(feat_names)}\n")
    out.append("Label = ADA evidence baru ATAU sukses dalam K langkah berikut (look-ahead utk LABEL saja; "
               "fitur online hanya prefix ≤ t). Group=run_id (GroupKFold). PRELIMINARY (n kecil, DEV).\n")

    from sklearn.ensemble import HistGradientBoostingClassifier, GradientBoostingClassifier
    from sklearn.neighbors import KNeighborsClassifier
    from sklearn.naive_bayes import GaussianNB
    from sklearn.neural_network import MLPClassifier
    models = {
        "LogReg": make_pipeline(StandardScaler(), LogisticRegression(max_iter=3000, class_weight="balanced")),
        "RandomForest": RandomForestClassifier(n_estimators=300, random_state=42, class_weight="balanced"),
        "HistGB": HistGradientBoostingClassifier(random_state=42),
        "GradientBoosting": GradientBoostingClassifier(random_state=42),
        "kNN": make_pipeline(StandardScaler(), KNeighborsClassifier(n_neighbors=5)),
        "GaussianNB": make_pipeline(StandardScaler(), GaussianNB()),
        "MLP": make_pipeline(StandardScaler(), MLPClassifier(hidden_layer_sizes=(32,), max_iter=800, random_state=42)),
    }
    n_groups = len(set(g))
    splits = max(2, min(5, n_groups))
    gkf = GroupKFold(n_splits=splits)
    out.append(f"| Model | AUROC | F1 | Brier |\n|---|---|---|---|")
    best_name, best_auc, best_model = None, -1, None
    for name, proto in models.items():
        aucs, f1s, briers = [], [], []
        for tri, tei in gkf.split(X, y, g):
            if len(set(y[tri])) < 2 or len(set(y[tei])) < 2:
                continue
            m = clone(proto); m.fit(X[tri], y[tri])
            p = m.predict_proba(X[tei])[:, 1]
            aucs.append(roc_auc_score(y[tei], p))
            f1s.append(f1_score(y[tei], (p >= 0.5).astype(int), zero_division=0))
            briers.append(brier_score_loss(y[tei], p))
        if aucs:
            out.append(f"| {name} | {np.mean(aucs):.3f} ± {np.std(aucs):.3f} | "
                       f"{np.mean(f1s):.3f} | {np.mean(briers):.3f} |")
            if np.mean(aucs) > best_auc:
                best_auc, best_name = np.mean(aucs), name
    # fit best on all data, report feature importance if RF
    final = clone(models.get(best_name, models["RandomForest"])); final.fit(X, y)
    if best_name == "RandomForest":
        imp = sorted(zip(feat_names, final.feature_importances_), key=lambda z: -z[1])
        out.append("\n**Fitur terpenting (RF):** " + ", ".join(f"{n}={v:.2f}" for n, v in imp[:6]))
    import joblib
    joblib.dump({"model": final, "feat_names": feat_names, "K": K}, MODEL_OUT)
    out.append(f"\nModel: data/n4_promise_model.joblib (best={best_name}, AUROC {best_auc:.3f}). "
               "Pakai sbg skor promise C2 utk isi node.score (M5).")
    OUT.write_text("\n".join(out), encoding="utf-8")
    print("wrote", OUT, "| samples", len(X), "| best", best_name, best_auc)


if __name__ == "__main__":
    main()
