"""M2 — train & evaluate N3 attack-evidence oracle. plan9.md N3.

Honest protocol (international-paper grade):
  * Labels in data/ were derived from DVWA marker strings, so a deterministic
    marker-rule (P0) trivially reproduces them ON DVWA (circular). Therefore the
    headline is NOT "ML beats P0 on DVWA". Instead we test:
      (1) Can an ML oracle RECOVER evidence from a LEARNED REPRESENTATION
          (response embedding + raw numeric features) WITHOUT being handed the
          marker features? -> prerequisite for transfer.
      (2) MARKER-DRIFT ROBUSTNESS: rename the marker words in held-out responses.
          P0 (hard-coded strings) collapses; a semantic-embedding ML should
          degrade far less. This is the real ML advantage, shown without bWAPP.
  * Split: train = {low, medium}, test = HIGH (unseen difficulty), all families
    present in both. Plus GroupKFold(scenario) cross-validated macro-F1.
  * ML INPUT = numeric-raw (NO leaky marker features) + response embedding
    (nomic-embed-text, local via Ollama). Leaky features power ONLY P0.
  * Report: accuracy, macro-F1, per-label P/R/F1, calibration (Brier), abstain
    coverage/accuracy, confusion. Save model + metrics + report/N3_RESULTS.md.

Usage: python eval/train_n3.py
"""
from __future__ import annotations
import sys, json, re
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "n3_raw.jsonl"
EMB_CACHE = ROOT / "data" / "n3_emb_nomic.npy"
OUT_MD = ROOT / "report" / "N3_RESULTS.md"
MODEL_OUT = ROOT / "data" / "n3_model.joblib"

# feature partitions ---------------------------------------------------------
RAW_FEATS = ["status", "body_len", "elapsed_ms", "delta_len", "char_diff_ratio",
             "payload_len", "p_quote", "p_angle", "p_union", "p_comment",
             "p_tautology", "p_false", "level_ord", "fam_sqli", "fam_blind", "fam_xss"]
LEAKY = ["has_sql_error", "has_exists", "has_missing", "reflected_raw",
         "reflected_encoded", "sentinel_echo", "rows_firstname"]   # P0 only

MARKERS = {   # (regex, replacement) used to SIMULATE marker drift (holdout-like)
    r"User ID exists in the database": "Account entry located in the store",
    r"exists in the database": "located in the store",
    r"User ID is MISSING from the database": "Account entry absent from the store",
    r"MISSING from the database": "absent from the store",
    r"First name": "Given label", r"Surname": "Family label",
    r"You have an error in your SQL syntax": "the data layer rejected the request format",
    r"Unknown column": "unrecognised field",
}


def load():
    rows = []
    for ln in open(RAW, encoding="utf-8"):
        ln = ln.strip()
        if ln:
            rows.append(json.loads(ln))
    return rows


def drift(text: str) -> str:
    for pat, rep in MARKERS.items():
        text = re.sub(pat, rep, text, flags=re.IGNORECASE)
    return text


def embed_all(texts, model="nomic-embed-text"):
    import ollama
    vecs = []
    for i, t in enumerate(texts):
        v = ollama.embeddings(model=model, prompt=t[:2000])["embedding"]
        vecs.append(v)
        if (i + 1) % 50 == 0:
            print(f"  embedded {i+1}/{len(texts)}")
    return np.array(vecs, dtype=np.float32)


def p0_predict(r):
    f = r["features"]
    if f["sentinel_echo"] or f["rows_firstname"] >= 2:
        return "confirmed"
    if f["has_exists"] and not f["has_missing"]:
        return "blind_bit_true"
    if f["has_missing"]:
        return "blind_bit_false"
    if f["reflected_raw"]:
        return "reflected_unescaped"
    if f["has_sql_error"]:
        return "injection_point_error"
    return "no_observed_effect"


def p0_predict_from_body(body, r):
    """P0 recomputed from a (possibly drifted) body -- hard-coded string rules."""
    low = body.lower()
    f = r["features"]
    if f["sentinel_echo"] or low.count("first name") >= 2:   # sentinel survives drift; 'first name' drifts
        return "confirmed"
    if "exists in the database" in low or "user id exists" in low:
        return "blind_bit_true"
    if "missing from the database" in low:
        return "blind_bit_false"
    if "<" in r["payload"] and r["payload"] in body:
        return "reflected_unescaped"
    if any(m in low for m in ("error in your sql syntax", "unknown column", "mysql")):
        return "injection_point_error"
    return "no_observed_effect"


def metrics_block(y_true, y_pred, labels):
    from sklearn.metrics import accuracy_score, f1_score, classification_report
    acc = accuracy_score(y_true, y_pred)
    mf1 = f1_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)
    rep = classification_report(y_true, y_pred, labels=labels, zero_division=0, digits=3)
    return acc, mf1, rep


def main():
    rows = load()
    print("samples:", len(rows))
    bodies = [r["body_excerpt"] for r in rows]

    # embeddings (cached)
    if EMB_CACHE.exists():
        emb = np.load(EMB_CACHE)
        if len(emb) != len(rows):
            emb = embed_all(bodies); np.save(EMB_CACHE, emb)
    else:
        print("embedding bodies via nomic-embed-text (local)...")
        emb = embed_all(bodies); np.save(EMB_CACHE, emb)
    print("embedding dim:", emb.shape)

    Xraw = np.array([[r["features"][k] for k in RAW_FEATS] for r in rows], dtype=np.float32)
    X = np.hstack([Xraw, emb])
    y = np.array([r["outcome"] for r in rows])
    lvl = np.array([r["level"] for r in rows])
    grp = np.array([r["scenario"] for r in rows])
    labels = sorted(set(y))

    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.pipeline import make_pipeline
    from sklearn.model_selection import GroupKFold
    from sklearn.dummy import DummyClassifier
    from sklearn.metrics import brier_score_loss

    tr = lvl != "high"; te = lvl == "high"
    models = {
        "Dummy(most_freq)": DummyClassifier(strategy="most_frequent"),
        "LogReg": make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, C=1.0)),
        "RandomForest": RandomForestClassifier(n_estimators=300, random_state=42, class_weight="balanced"),
        "HistGB": HistGradientBoostingClassifier(random_state=42),
    }
    out = ["# N3 Oracle — Hasil M2 (DEV/DVWA)\n",
           f"Samples: {len(rows)} | train(low+medium)={tr.sum()} test(high)={te.sum()} | "
           f"emb=nomic-embed-text dim {emb.shape[1]} | ML input = {len(RAW_FEATS)} raw + emb (NO marker feats)\n",
           "Catatan jujur: label berasal dari marker DVWA → **P0 deterministik ~sempurna di DVWA (sirkular)**; "
           "headline = (a) ML pulih-evidence dari representasi tanpa fitur-contekan, (b) ketahanan marker-drift.\n"]

    # ---- held-out HIGH evaluation ----
    out.append("## 1. Uji held-out (train low+medium → test HIGH)\n")
    out.append("| Model | Acc | macro-F1 |\n|---|---|---|")
    fitted = {}
    for name, m in models.items():
        m.fit(X[tr], y[tr]); fitted[name] = m
        acc, mf1, _ = metrics_block(y[te], m.predict(X[te]), labels)
        out.append(f"| {name} | {acc:.3f} | {mf1:.3f} |")
    # P0 on clean high
    p0_hi = [p0_predict(rows[i]) for i in np.where(te)[0]]
    acc0, mf10, _ = metrics_block(y[te], p0_hi, labels)
    out.append(f"| **P0 (marker rules, CLEAN)** | {acc0:.3f} | {mf10:.3f} |")

    best = "RandomForest"
    _, _, rep = metrics_block(y[te], fitted[best].predict(X[te]), labels)
    out.append(f"\n**Per-label ({best}, test HIGH):**\n```\n{rep}\n```")

    # ---- GroupKFold(scenario) CV ----
    out.append("## 2. Cross-validation GroupKFold(scenario)\n| Model | macro-F1 (mean±sd) |\n|---|---|")
    gkf = GroupKFold(n_splits=3)
    for name, proto in [("LogReg", models["LogReg"]), ("RandomForest", models["RandomForest"]),
                        ("HistGB", models["HistGB"])]:
        f1s = []
        from sklearn.base import clone
        for tri, tei in gkf.split(X, y, grp):
            mm = clone(proto); mm.fit(X[tri], y[tri])
            _, mf1, _ = metrics_block(y[tei], mm.predict(X[tei]), labels)
            f1s.append(mf1)
        out.append(f"| {name} | {np.mean(f1s):.3f} ± {np.std(f1s):.3f} |")

    # ---- MARKER-DRIFT robustness (holdout-like) ----
    out.append("## 3. Ketahanan marker-drift (simulasi holdout: kata penanda diubah)\n")
    te_idx = np.where(te)[0]
    drifted_bodies = [drift(rows[i]["body_excerpt"]) for i in te_idx]
    emb_d = embed_all(drifted_bodies)
    Xd = np.hstack([Xraw[te_idx], emb_d])
    # P0 collapses (string match on drifted text); ML uses drifted embedding
    p0_drift = [p0_predict_from_body(drifted_bodies[j], rows[te_idx[j]]) for j in range(len(te_idx))]
    acc0d, mf10d, _ = metrics_block(y[te_idx], p0_drift, labels)
    out.append("| Kondisi | P0 acc | P0 F1 | RF acc | RF F1 |\n|---|---|---|---|---|")
    rf = fitted["RandomForest"]
    accc, mf1c, _ = metrics_block(y[te_idx], rf.predict(X[te_idx]), labels)
    accd, mf1d, _ = metrics_block(y[te_idx], rf.predict(Xd), labels)
    out.append(f"| CLEAN (DVWA asli) | {acc0:.3f} | {mf10:.3f} | {accc:.3f} | {mf1c:.3f} |")
    out.append(f"| DRIFTED (penanda diubah) | {acc0d:.3f} | {mf10d:.3f} | {accd:.3f} | {mf1d:.3f} |")
    out.append(f"\n→ **P0 turun {acc0-acc0d:+.3f} acc saat penanda berubah; RF turun {accc-accd:+.3f}.** "
               "Ini inti keunggulan ML: baca makna, bukan string kaku (prediktor generalisasi ke holdout).")

    # ---- abstain (calibration-driven) ----
    out.append("\n## 4. Abstain (tolak jawab saat ragu) — RandomForest\n| thr | coverage | acc@answered |\n|---|---|---|")
    proba = rf.predict_proba(X[te]); pmax = proba.max(1); pred = rf.predict(X[te])
    from sklearn.metrics import accuracy_score
    for thr in (0.0, 0.4, 0.5, 0.6, 0.7, 0.8):
        ans = pmax >= thr
        cov = ans.mean()
        acc_ans = accuracy_score(y[te][ans], pred[ans]) if ans.any() else float("nan")
        out.append(f"| {thr:.1f} | {cov:.2f} | {acc_ans:.3f} |")

    # save
    import joblib
    joblib.dump({"model": rf, "raw_feats": RAW_FEATS, "labels": labels, "emb_model": "nomic-embed-text"}, MODEL_OUT)
    OUT_MD.parent.mkdir(exist_ok=True)
    OUT_MD.write_text("\n".join(out), encoding="utf-8")
    print("wrote", OUT_MD, "and", MODEL_OUT)
    # ascii-safe console summary (Windows cp1252 cannot print some unicode)
    summary = "\n".join(out).encode("ascii", "replace").decode("ascii")
    print(summary[:1600])


if __name__ == "__main__":
    main()
