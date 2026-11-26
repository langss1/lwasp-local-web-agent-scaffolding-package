"""M2-2d: train+benchmark N3 on the BIG dataset (data/n3_big.jsonl). Compares many
algorithms, SELECTS BY TRANSFER to LabApp3 (held). Multi-app training (DVWA+LabApp2)
is the main lever; also reports DVWA-only. Embeddings cached. Saves best to n3_model.joblib.
Offline. Usage: python eval/bench_big.py"""
from __future__ import annotations
import sys, json
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from eval.train_n3 import RAW_FEATS, embed_all  # noqa

BIG = ROOT / "data" / "n3_big.jsonl"
EMB = ROOT / "data" / "n3_big_emb.npy"
OUT = ROOT / "report" / "N3_BENCH_BIG.md"
MODEL = ROOT / "data" / "n3_model.joblib"
INV = [i for i, k in enumerate(RAW_FEATS) if k not in ("status", "body_len", "elapsed_ms", "delta_len")]


def main():
    rows = [json.loads(l) for l in open(BIG, encoding="utf-8") if l.strip()]
    app = np.array([r["app"] for r in rows]); lvl = np.array([r["level"] for r in rows])
    y = np.array([r["outcome"] for r in rows])
    Xr = np.array([[r["features"][k] for k in RAW_FEATS] for r in rows], dtype=np.float32)
    if EMB.exists() and len(np.load(EMB)) == len(rows):
        E = np.load(EMB)
    else:
        print(f"embedding {len(rows)} bodies (sekali, dicache)...")
        E = embed_all([r["body_excerpt"] for r in rows]); np.save(EMB, E)
    print("dataset:", len(rows), "| emb", E.shape)

    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
    from sklearn.svm import SVC, LinearSVC
    from sklearn.neighbors import KNeighborsClassifier
    from sklearn.naive_bayes import GaussianNB
    from sklearn.neural_network import MLPClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.decomposition import PCA
    from sklearn.pipeline import make_pipeline
    from sklearn.metrics import accuracy_score, f1_score

    d, l2, l3 = app == "DVWA", app == "LabApp2", app == "LabApp3"
    labs = sorted(set(y))
    dtr = d & (lvl != "high"); dte = d & (lvl == "high")

    def X(mask, idx): return np.hstack([Xr[mask][:, idx], E[mask]])
    def sc(*s): return make_pipeline(StandardScaler(), *s)
    models = {
        "LogReg": sc(LogisticRegression(max_iter=4000, C=1.0)),
        "LogReg_C0.1": sc(LogisticRegression(max_iter=4000, C=0.1)),
        "LinearSVC": sc(LinearSVC(C=0.5, max_iter=5000)),
        "SVM_rbf": sc(SVC(kernel="rbf", C=1.0)),
        "RandomForest": RandomForestClassifier(n_estimators=400, random_state=42, class_weight="balanced", n_jobs=-1),
        "HistGB": HistGradientBoostingClassifier(random_state=42),
        "kNN": sc(KNeighborsClassifier(n_neighbors=7)),
        "GaussianNB": sc(GaussianNB()),
        "MLP": sc(MLPClassifier(hidden_layer_sizes=(128, 32), max_iter=1000, random_state=42)),
        "PCA50+LogReg": sc(PCA(n_components=50, random_state=42), LogisticRegression(max_iter=4000, C=0.5)),
        "PCA80+LinSVC": sc(PCA(n_components=80, random_state=42), LinearSVC(C=0.5, max_iter=5000)),
    }
    out = ["# N3 Benchmark (BIG dataset) — pilih by TRANSFER ke LabApp3. plan10 M2-2d.\n",
           f"Dataset: {len(rows)} sampel (DVWA {d.sum()}, LabApp2 {l2.sum()}, LabApp3 {l3.sum()}). "
           f"Latih = DVWA(low+med)+LabApp2 [multi-app]; uji DVWA-high + **transfer LabApp3 (held)**. "
           f"Fitur invariant ({len(INV)}) + emb768.\n",
           "| Algoritma | DVWA-high F1 | **LabApp3 F1 (transfer)** | LabApp3 acc |",
           "|---|---|---|---|"]
    tr = dtr | l2            # multi-app training
    results = []
    for name, m in models.items():
        try:
            m.fit(X(tr, INV), y[tr])
            df = f1_score(y[dte], m.predict(X(dte, INV)), labels=labs, average="macro", zero_division=0)
            l3p = m.predict(X(l3, INV))
            lf = f1_score(y[l3], l3p, labels=labs, average="macro", zero_division=0)
            la = accuracy_score(y[l3], l3p)
            out.append(f"| {name} | {df:.3f} | {lf:.3f} | {la:.3f} |")
            results.append((lf, la, df, name, m))
        except Exception as e:
            out.append(f"| {name} | ERR | {str(e)[:30]} | - |")
    results.sort(reverse=True)
    best = results[0]
    out.append(f"\n**TERPILIH (transfer LabApp3 tertinggi): {best[3]}** — F1 {best[0]:.3f} / acc {best[1]:.3f}; "
               f"DVWA-high F1 {best[2]:.3f}. (Bandingkan iterasi lama: multi-app kecil ~0.44.)")
    import joblib
    best[4].fit(X(tr, INV), y[tr])
    joblib.dump({"model": best[4], "labels": labs, "raw_feats": RAW_FEATS, "feat_idx": INV,
                 "emb_model": "nomic-embed-text", "algo": best[3], "selected_by": "labapp3_transfer_f1",
                 "trained_on": "DVWA_lowmed+LabApp2", "big": True}, MODEL)
    OUT.write_text("\n".join(out), encoding="utf-8")
    print("wrote", OUT, "| best", best[3], "transferF1=%.3f" % best[0])


if __name__ == "__main__":
    main()
