"""M2-2c: fire the big clean corpus (data/corpus_payloads.json) at DVWA (3 levels) +
LabApp2 + LabApp3, auto-label each response with the independent oracle -> a LARGE
labeled dataset data/n3_big.jsonl (per-sample: app, family, level, payload, outcome,
features, body[:2000]). Only HTTP (no 7B, no LLM). Run labapp2(8099)+labapp3(8100) first.
Usage: python eval/build_dataset.py"""
from __future__ import annotations
import sys, json, time
from pathlib import Path
import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import yaml  # noqa
from src.orchestrator import Scenario  # noqa
from src.action.http_client import DvwaClient  # noqa
from eval.collect_n3_data import features, oracle as dvwa_oracle, send as dvwa_send, SENTINEL  # noqa
from src.orchestrator import load_config  # noqa

CORPUS = json.loads((ROOT / "data" / "corpus_payloads.json").read_text(encoding="utf-8"))
OUT = ROOT / "data" / "n3_big.jsonl"
LAB = {
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


def lab_oracle(mark, fam, body, payload):
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


def main():
    cfg = load_config(str(ROOT / "config.yaml")); t = cfg["target"]
    scen = [Scenario.from_dict(s) for s in yaml.safe_load(open(ROOT / "eval/scenarios.yaml", encoding="utf-8"))["scenarios"]
            if s.get("vuln_type") in CORPUS]
    fout = open(OUT, "w", encoding="utf-8"); n = 0

    # ---- DVWA (3 levels) ----
    for sc in scen:
        client = DvwaClient(base_url=t["base_url"], allowlist=t["allowlist"],
                            username=t["login_user"], password=t["login_pass"], security_level=sc.level)
        client.login()
        base = dvwa_send(client, sc, "1")
        bl, bb = base.length, base.body
        for p in CORPUS[sc.vuln_type]:
            try: r = dvwa_send(client, sc, p)
            except Exception: continue
            out = dvwa_oracle(sc.vuln_type, r.body, p)[0]   # oracle returns (outcome, filter); keep outcome
            f = features(sc.vuln_type, sc.level, p, r, bl, bb)
            fout.write(json.dumps({"app": "DVWA", "family": sc.vuln_type, "level": sc.level,
                                   "payload": p, "outcome": out, "features": f,
                                   "body_excerpt": r.body[:2000]}, ensure_ascii=False) + "\n")
            n += 1
        print(f"  DVWA {sc.id}: {len(CORPUS[sc.vuln_type])} payloads")

    # ---- LabApp2 & LabApp3 ----
    for app, c in LAB.items():
        for fam in CORPUS:
            ep, pm = c["ep"][fam]
            bb = requests.get(c["base"] + ep, params={pm: ("1" if fam != "xss_reflected" else "guest")}, timeout=8).text
            bl = len(bb)
            for p in CORPUS[fam]:
                try:
                    st = time.monotonic()
                    r = _R(requests.get(c["base"] + ep, params={pm: p}, timeout=8), time.monotonic() - st)
                except Exception: continue
                out = lab_oracle(c["mark"], fam, r.body, p)
                f = features(fam, "low", p, r, bl, bb)
                fout.write(json.dumps({"app": app, "family": fam, "level": "na",
                                       "payload": p, "outcome": out, "features": f,
                                       "body_excerpt": r.body[:2000]}, ensure_ascii=False) + "\n")
                n += 1
        print(f"  {app}: done")
    fout.close()

    from collections import Counter
    apps = Counter(); outs = Counter()
    for l in open(OUT, encoding="utf-8"):
        d = json.loads(l); apps[d["app"]] += 1; outs[d["outcome"]] += 1
    print("TOTAL samples:", n)
    print("per app:", dict(apps))
    print("per label:", dict(outs))


if __name__ == "__main__":
    main()
