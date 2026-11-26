"""M2 benchmark: train N3 on DVWA, SELECT BY TRANSFER to LabApp2 (not DVWA score).
plan10 §7 + audit GPT (metrik seleksi = transfer). Compares ~8 algorithms + PCA
variants + baselines. LabApp2 here is a DEV transfer-check (bWAPP stays sealed).

Contract (fixed per audit): embedding = body[:2000], baseline = benign response,
features identical to collector. Run labapp2 first (python holdout/labapp2.py 8099).
Usage: python eval/bench_n3.py
"""
from __future__ import annotations
import sys, json, time
from pathlib import Path
import numpy as np
import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from eval.collect_n3_data import features, sqli_payloads, blind_payloads, xss_payloads, SENTINEL  # noqa
from eval.train_n3 import RAW_FEATS, embed_all  # noqa

BASE = "http://127.0.0.1:8099"
EP = {"sqli": ("/sqli", "q"), "sqli_blind": ("/blind", "id"), "xss_reflected": ("/greet", "name")}
CORP = {"sqli": sqli_payloads, "sqli_blind": blind_payloads, "xss_reflected": xss_payloads}
OUT = ROOT / "report" / "N3_BENCH.md"
MODEL_OUT = ROOT / "data" / "n3_model.joblib"


class _R:
    def __init__(self, r, dt): self.body, self.status_code, self.elapsed_s = r.text, r.status_code, dt
    @property
    def length(self): return len(self.body)


def la_send(fam, value):
    ep, p = EP[fam]; t = time.monotonic()
    return _R(requests.get(BASE + ep, params={p: value}, timeout=8), time.monotonic() - t)


def la_oracle(fam, body, payload):
    low = body.lower()
    if fam == "sqli":
        if SENTINEL.lower() in low or low.count("member:") >= 2: return "confirmed"
        return "injection_point_error" if "query failure" in low else "no_observed_effect"
    if fam == "sqli_blind":
        if "account active" in low: return "blind_bit_true"
        if "account not found" in low: return "blind_bit_false"
        return "injection_point_error" if "lookup error" in low else "no_observed_effect"
    if "<" in payload and payload in body: return "reflected_unescaped"
    return "no_observed_effect"


def load_dvwa():
    rows = [json.loads(l) for l in open(ROOT / "data" / "n3_raw.jsonl", encoding="utf-8") if l.strip()]
    y = np.array([r["outcome"] for r in rows]); lvl = np.array([r["level"] for r in rows])
    Xr = np.array([[r["features"][k] for k in RAW_FEATS] for r in rows], dtype=np.float32)
    emb = embed_all([r["body_excerpt"] for r in rows])
    return np.hstack([Xr, emb]), y, lvl


def load_labapp2():
    rows = []
    for fam in CORP:
        base = la_send(fam, "1" if fam != "xss_reflected" else "guest")
        for _, p in CORP[fam]():
            try: resp = la_send(fam, p)
            except Exception: continue
            f = features(fam, "low", p, resp, base.length, base.body)
            rows.append({"y": la_oracle(fam, resp.body, p),
                         "x": [f[k] for k in RAW_FEATS], "body": resp.body[:2000]})
    y = np.array([r["y"] for r in rows])
    Xr = np.array([r["x"] for r in rows], dtype=np.float32)
    emb = embed_all([r["body"] for r in rows])
    return np.hstack([Xr, emb]), y


def main():
    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
    from sklearn.svm import SVC
    from sklearn.neighbors import KNeighborsClassifier
    from sklearn.naive_bayes import GaussianNB
    from sklearn.neural_network import MLPClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.decomposition import PCA
    from sklearn.pipeline import make_pipeline
    from sklearn.dummy import DummyClassifier
    from sklearn.metrics import accuracy_score, f1_score

    print("embedding DVWA..."); Xd, yd, lvl = load_dvwa()
    print("embedding LabApp2..."); Xl, yl = load_labapp2()
    tr, te = lvl != "high", lvl == "high"
    labs = sorted(set(yd) | set(yl))

    def sc(*s): return make_pipeline(StandardScaler(), *s)
    models = {
        "Dummy": DummyClassifier(strategy="most_frequent"),
        "LogReg": sc(LogisticRegression(max_iter=3000, C=1.0)),
        "LogReg_L2strong": sc(LogisticRegression(max_iter=3000, C=0.1)),
        "RandomForest": RandomForestClassifier(n_estimators=300, random_state=42, class_weight="balanced"),
        "HistGB": HistGradientBoostingClassifier(random_state=42),
        "SVM_linear": sc(SVC(kernel="linear")),
        "SVM_rbf": sc(SVC(kernel="rbf")),
        "kNN": sc(KNeighborsClassifier(n_neighbors=5)),
        "GaussianNB": sc(GaussianNB()),
        "MLP": sc(MLPClassifier(hidden_layer_sizes=(64,), max_iter=800, random_state=42)),
        "PCA50+LogReg": sc(PCA(n_components=50, random_state=42), LogisticRegression(max_iter=3000, C=0.5)),
        "PCA50+SVMrbf": sc(PCA(n_components=50, random_state=42), SVC(kernel="rbf")),
        "PCA30+kNN": sc(PCA(n_components=30, random_state=42), KNeighborsClassifier(n_neighbors=5)),
    }
    out = ["# N3 Benchmark — pilih by TRANSFER (DVWA→LabApp2). plan10 M2.\n",
           f"DVWA train(low+med)={tr.sum()} test(high)={te.sum()} | LabApp2={len(yl)} | emb nomic 768+raw16.\n",
           "Seleksi = **transfer LabApp2 (F1)**, BUKAN skor DVWA. (LabApp2=DEV; bWAPP tetap disegel.)\n",
           "| Algoritma | DVWA-high acc | DVWA-high F1 | **LabApp2 acc** | **LabApp2 F1 (transfer)** |",
           "|---|---|---|---|---|"]
    results = []
    for name, m in models.items():
        try:
            m.fit(Xd[tr], yd[tr])
            da = accuracy_score(yd[te], m.predict(Xd[te]))
            df = f1_score(yd[te], m.predict(Xd[te]), labels=labs, average="macro", zero_division=0)
            la = accuracy_score(yl, m.predict(Xl))
            lf = f1_score(yl, m.predict(Xl), labels=labs, average="macro", zero_division=0)
            out.append(f"| {name} | {da:.3f} | {df:.3f} | {la:.3f} | {lf:.3f} |")
            results.append((name, m, da, df, la, lf))
        except Exception as e:
            out.append(f"| {name} | ERR | {str(e)[:30]} | - | - |")
    # pick best by transfer F1, tie-break DVWA F1
    results.sort(key=lambda z: (z[5], z[3]), reverse=True)
    best = results[0]
    out.append(f"\n**TERPILIH (transfer tertinggi): {best[0]}** — LabApp2 F1 {best[5]:.3f} / acc {best[4]:.3f}; "
               f"DVWA-high F1 {best[3]:.3f}. Dibandingkan RF lama (transfer ~0.10).")
    # refit best on ALL dvwa, save
    import joblib
    best[1].fit(Xd, yd)
    joblib.dump({"model": best[1], "labels": labs, "raw_feats": RAW_FEATS,
                 "emb_model": "nomic-embed-text", "selected_by": "labapp2_transfer_f1",
                 "algo": best[0]}, MODEL_OUT)
    OUT.write_text("\n".join(out), encoding="utf-8")
    print("wrote", OUT, "| best:", best[0], "transferF1=%.3f" % best[5])


if __name__ == "__main__":
    main()
