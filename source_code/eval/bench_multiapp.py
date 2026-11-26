"""M2 multi-app transfer study (plan10). Tests whether (a) multi-app training and
(b) domain-invariant features improve N3 cross-app transfer. Train on DVWA-only vs
DVWA+LabApp2; features full vs invariant (drop absolute status/body_len/elapsed/delta);
TEST transfer on LabApp3 (never trained on). Model = PCA50+LogReg (best from bench_n3).
Offline (no 7B). Run labapp2 (8099) & labapp3 (8100) first. Usage: python eval/bench_multiapp.py"""
from __future__ import annotations
import sys, json, time
from pathlib import Path
import numpy as np
import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from eval.collect_n3_data import features, sqli_payloads, blind_payloads, xss_payloads, SENTINEL  # noqa
from eval.train_n3 import RAW_FEATS, embed_all  # noqa

CORP = {"sqli": sqli_payloads, "sqli_blind": blind_payloads, "xss_reflected": xss_payloads}
INVARIANT = [i for i, k in enumerate(RAW_FEATS)
             if k not in ("status", "body_len", "elapsed_ms", "delta_len")]  # drop app-absolute
OUT = ROOT / "report" / "N3_MULTIAPP.md"

APPS = {
    "LabApp2": {"base": "http://127.0.0.1:8099",
                "ep": {"sqli": ("/sqli", "q"), "sqli_blind": ("/blind", "id"), "xss_reflected": ("/greet", "name")},
                "mark": {"row": "member:", "true": "account active", "false": "account not found", "err": "query failure"}},
    "LabApp3": {"base": "http://127.0.0.1:8100",
                "ep": {"sqli": ("/find", "title"), "sqli_blind": ("/auth", "uid"), "xss_reflected": ("/echo", "msg")},
                "mark": {"row": "title:", "true": "access granted", "false": "access denied", "err": "fault:"}},
}


class _R:
    def __init__(s, r, dt): s.body, s.status_code, s.elapsed_s = r.text, r.status_code, dt
    @property
    def length(s): return len(s.body)


def oracle(mark, fam, body, payload):
    low = body.lower()
    if fam == "sqli":
        if SENTINEL.lower() in low or low.count(mark["row"]) >= 2: return "confirmed"
        return "injection_point_error" if mark["err"] in low else "no_observed_effect"
    if fam == "sqli_blind":
        if mark["true"] in low: return "blind_bit_true"
        if mark["false"] in low: return "blind_bit_false"
        return "injection_point_error" if mark["err"] in low else "no_observed_effect"
    if "<" in payload and payload in body: return "reflected_unescaped"
    return "no_observed_effect"


def collect_app(cfg):
    base, ep, mark = cfg["base"], cfg["ep"], cfg["mark"]
    rows = []
    for fam in CORP:
        e, p = ep[fam]
        bb = _R(requests.get(base + e, params={p: ("1" if fam != "xss_reflected" else "guest")}, timeout=8), 0.0)
        for _, pl in CORP[fam]():
            try:
                t = time.monotonic(); r = _R(requests.get(base + e, params={p: pl}, timeout=8), time.monotonic() - t)
            except Exception:
                continue
            f = features(fam, "low", pl, r, bb.length, bb.body)
            rows.append({"y": oracle(mark, fam, r.body, pl), "x": [f[k] for k in RAW_FEATS], "body": r.body[:2000]})
    y = np.array([r["y"] for r in rows]); Xr = np.array([r["x"] for r in rows], dtype=np.float32)
    return Xr, embed_all([r["body"] for r in rows]), y


def load_dvwa():
    rows = [json.loads(l) for l in open(ROOT / "data" / "n3_raw.jsonl", encoding="utf-8") if l.strip()]
    y = np.array([r["outcome"] for r in rows])
    Xr = np.array([[r["features"][k] for k in RAW_FEATS] for r in rows], dtype=np.float32)
    return Xr, embed_all([r["body_excerpt"] for r in rows]), y


def main():
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler
    from sklearn.decomposition import PCA
    from sklearn.pipeline import make_pipeline
    from sklearn.metrics import accuracy_score, f1_score

    print("DVWA..."); dXr, dE, dy = load_dvwa()
    print("LabApp2..."); l2Xr, l2E, l2y = collect_app(APPS["LabApp2"])
    print("LabApp3..."); l3Xr, l3E, l3y = collect_app(APPS["LabApp3"])
    labs = sorted(set(dy) | set(l2y) | set(l3y))

    def build(Xr, E, idx): return np.hstack([Xr[:, idx], E])
    def model(): return make_pipeline(StandardScaler(), PCA(n_components=50, random_state=42),
                                      LogisticRegression(max_iter=3000, C=0.5))

    def ev(m, Xr, E, y, idx):
        p = m.predict(build(Xr, E, idx))
        return accuracy_score(y, p), f1_score(y, p, labels=labs, average="macro", zero_division=0)

    out = ["# N3 Multi-app Transfer (plan10 M2) — PCA50+LogReg\n",
           "Uji: latih DVWA-saja vs DVWA+LabApp2; fitur FULL vs DOMAIN-INVARIANT (buang status/body_len/"
           "elapsed/delta absolut). **Transfer diuji di LabApp3 (tak pernah dilatih).**\n",
           f"DVWA={len(dy)} LabApp2={len(l2y)} LabApp3={len(l3y)}. Fitur full={len(RAW_FEATS)} invariant={len(INVARIANT)} (+emb768).\n",
           "| Latih | Fitur | LabApp3 acc | **LabApp3 F1 (transfer)** |",
           "|---|---|---|---|"]
    ALL = list(range(len(RAW_FEATS)))
    best = None
    for idxname, idx in [("full", ALL), ("invariant", INVARIANT)]:
        for trname, (Xr, E, y) in [("DVWA", (dXr, dE, dy)),
                                   ("DVWA+LA2", (np.vstack([dXr, l2Xr]), np.vstack([dE, l2E]), np.concatenate([dy, l2y])))]:
            m = model(); m.fit(build(Xr, E, idx), y)
            a3, f3 = ev(m, l3Xr, l3E, l3y, idx)
            out.append(f"| {trname} | {idxname} | {a3:.3f} | {f3:.3f} |")
            if best is None or f3 > best[0]:
                best = (f3, a3, trname, idxname, m, idx)
    out.append(f"\n**Terbaik transfer LabApp3: latih={best[2]}, fitur={best[3]} → F1 {best[0]:.3f} / acc {best[1]:.3f}.** "
               "Bandingkan DVWA-only+full (baseline) di baris pertama.")
    # also report: does DVWA+LA2 beat DVWA-only? does invariant beat full?
    OUT.write_text("\n".join(out), encoding="utf-8")
    print("wrote", OUT, "| best transferF1=%.3f (%s/%s)" % (best[0], best[2], best[3]))


if __name__ == "__main__":
    main()
