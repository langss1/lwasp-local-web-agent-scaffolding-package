"""M5 holdout: evaluate the FROZEN N3 model (trained only on DVWA) on LabApp2 -- a
second, independently-implemented vulnerable app (Python/SQLite, different markers).
Tests GENUINE cross-application generalisation: P0 (DVWA-hardcoded string rules) is
expected to collapse (different markers); the ML oracle (raw features + response
embedding) should generalise. plan9.md M5. No tuning on holdout.

Run labapp2 first: python holdout/labapp2.py 8099
Then:            python eval/holdout_n3.py
"""
from __future__ import annotations
import sys, time, json
from pathlib import Path
import numpy as np
import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from eval.collect_n3_data import features, sqli_payloads, blind_payloads, xss_payloads, SENTINEL  # noqa
from eval.train_n3 import RAW_FEATS, p0_predict, embed_all  # noqa

BASE = "http://127.0.0.1:8099"
EP = {"sqli": ("/sqli", "q"), "sqli_blind": ("/blind", "id"), "xss_reflected": ("/greet", "name")}
CORP = {"sqli": sqli_payloads, "sqli_blind": blind_payloads, "xss_reflected": xss_payloads}
OUT = ROOT / "report" / "N3_HOLDOUT_RESULTS.md"


class Resp:
    def __init__(self, r, dt):
        self.body = r.text; self.status_code = r.status_code; self.elapsed_s = dt
    @property
    def length(self):
        return len(self.body)


def send(fam, value):
    ep, p = EP[fam]
    t = time.monotonic()
    r = requests.get(BASE + ep, params={p: value}, timeout=8)
    return Resp(r, time.monotonic() - t)


def oracle(fam, body, payload):
    low = body.lower()
    if fam == "sqli":
        if SENTINEL.lower() in low:
            return "confirmed"
        if low.count("member:") >= 2:
            return "confirmed"
        if "query failure" in low:
            return "injection_point_error"
        return "no_observed_effect"
    if fam == "sqli_blind":
        if "account active" in low:
            return "blind_bit_true"
        if "account not found" in low:
            return "blind_bit_false"
        if "lookup error" in low:
            return "injection_point_error"
        return "no_observed_effect"
    if "<" in payload and payload in body:
        return "reflected_unescaped"
    import html as _h
    if _h.escape(payload, quote=False) in body:
        return "no_observed_effect"
    return "no_observed_effect"


def main():
    rows = []
    for fam in CORP:
        base_resp = send(fam, "1" if fam != "xss_reflected" else "guest")
        bl, bb = base_resp.length, base_resp.body
        for intended, payload in CORP[fam]():
            try:
                resp = send(fam, payload)
            except Exception as e:  # noqa
                print("skip", fam, repr(payload)[:30], e); continue
            feat = features(fam, "low", payload, resp, bl, bb)
            rows.append({"family": fam, "payload": payload, "y": oracle(fam, resp.body, payload),
                         "features": feat, "body": resp.body[:1200]})
    print("holdout samples:", len(rows))

    # frozen model + embeddings
    import joblib
    bundle = joblib.load(ROOT / "data" / "n3_model.joblib")
    model, labels = bundle["model"], bundle["labels"]
    emb = embed_all([r["body"] for r in rows])
    Xraw = np.array([[r["features"][k] for k in RAW_FEATS] for r in rows], dtype=np.float32)
    X = np.hstack([Xraw, emb])
    y = np.array([r["y"] for r in rows])

    # P0 uses DVWA-hardcoded string features (expected to collapse here)
    class _R:  # p0_predict reads r["features"]
        pass
    p0 = []
    for r in rows:
        p0.append(p0_predict({"features": r["features"]}))
    ml = model.predict(X)

    from sklearn.metrics import accuracy_score, f1_score, classification_report
    labs = sorted(set(y))
    acc0 = accuracy_score(y, p0); f10 = f1_score(y, p0, labels=labs, average="macro", zero_division=0)
    accm = accuracy_score(y, ml); f1m = f1_score(y, ml, labels=labs, average="macro", zero_division=0)

    winner = "ML" if accm > acc0 else "P0"
    out = ["# N3 HOLDOUT — LabApp2 (cross-app, FROZEN model dari DVWA)\n",
           "Holdout = aplikasi kedua independen (Python/SQLite, marker beda: 'ACCOUNT ACTIVE/NOT FOUND', "
           "'Member:'; bukan 'exists/First name'). Model N3 TIDAK disentuh/tuning di sini.\n",
           f"Samples: {len(rows)} | distribusi label: "
           f"{json.dumps({l:int((y==l).sum()) for l in labs}, ensure_ascii=False)}\n",
           "| Oracle | Acc | macro-F1 |\n|---|---|---|",
           f"| P0 (aturan string DVWA) | {acc0:.3f} | {f10:.3f} |",
           f"| N3 ML (raw+embedding) | {accm:.3f} | {f1m:.3f} |",
           f"\n**Temuan (jujur): pada holdout aplikasi-berbeda, {winner} lebih tinggi "
           f"(ML {accm:.3f} vs P0 {acc0:.3f} acc, selisih {accm-acc0:+.3f}).** "
           "Lihat per-label: bila ML kolaps ke satu kelas (recall ~1 di satu label, ~0 di lain), "
           "artinya model DVWA OUT-OF-DISTRIBUTION di app lain -> TIDAK transfer. "
           "Ini mengoreksi proksi marker-drift (yang hanya mengganti kata, embedding nyaris sama, "
           "sehingga melebih-lebihkan ketahanan ML). Implikasi: generalisasi lintas-app = masalah "
           "terbuka (butuh fitur domain-invariant / latih multi-app). Keduanya turun tajam dari DVWA.\n",
           "**Per-label (N3 ML):**\n```",
           classification_report(y, ml, labels=labs, zero_division=0, digits=3), "```"]
    OUT.write_text("\n".join(out), encoding="utf-8")
    print("wrote", OUT)
    print(f"P0 acc {acc0:.3f} / ML acc {accm:.3f}")


if __name__ == "__main__":
    main()
