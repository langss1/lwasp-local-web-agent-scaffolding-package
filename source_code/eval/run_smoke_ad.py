"""Smoke x3 per condition (A-D) to VALIDATE the 2026-11-01 fixes before the full
480-run sweep. Portable (Linux pod): ROOT is derived from this file.

Scenario choice exercises exactly what was fixed:
  - brute_medium : the worst L3 regression (100%->0%); tests the new `hydra` tool
                   + the raised iteration budget. On A/C (base, no tools) it tests
                   that base still behaves; on B/D (system) it tests the tool.
  - cmdi_high    : tests the new `commix` tool and filter-bypass payload sweep.
  - sqli_low     : control -- must stay solved; catches any regression from the edits.

Conditions: A=q25/L1(base) B=q25/L3(system) C=q35/L1(base) D=q35/L3(system),
seed 42. 3 scenarios x 4 conditions = 12 runs (3 per condition, as asked).
Prints a pass/fail matrix with iters/finish/tool_calls so a healthy tool call is
visible on B/D. Usage: python eval/run_smoke_ad.py
"""
import sys, subprocess, json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
SCEN = ["brute_medium", "cmdi_high", "sqli_low"]
COND = [("A", "q25", "qwen2.5:latest", "L1"),
        ("B", "q25", "qwen2.5:latest", "L3"),
        ("C", "q35", "qwen3.5:latest", "L1"),
        ("D", "q35", "qwen3.5:latest", "L3")]
SEED = 42


def main():
    results = {}
    for name, mtag, model, lvl in COND:
        for sid in SCEN:
            rid = f"smoke-{mtag}-{sid}-{lvl}-s{SEED}"
            print(f"=== {name} {sid} ({model} {lvl}) -> {rid} ===", flush=True)
            try:
                subprocess.run([PY, str(ROOT / "eval" / "one_run_seed.py"),
                                mtag, model, lvl, sid, str(SEED), "smoke"],
                               cwd=str(ROOT), timeout=1800)
            except subprocess.TimeoutExpired:
                print("  TIMEOUT_KILLED", flush=True)
            rep = ROOT / "runs" / rid / "report.json"
            if rep.exists():
                d = json.loads(rep.read_text(encoding="utf-8"))
                results[(name, sid)] = (d.get("success"), d.get("iterations_used"),
                                        d.get("finish_reason"), d.get("tool_calls"))
            else:
                results[(name, sid)] = (None, None, "NO_REPORT", None)

    print("\n==== SMOKE RESULTS (3 per condition) ====", flush=True)
    print(f"{'cond':<5}{'scenario':<15}{'ok':<7}{'iters':<7}{'finish':<16}{'tools':<6}")
    for name, mtag, model, lvl in COND:
        for sid in SCEN:
            ok, it, fr, tc = results[(name, sid)]
            print(f"{name:<5}{sid:<15}{str(ok):<7}{str(it):<7}{str(fr):<16}{str(tc):<6}")


if __name__ == "__main__":
    main()
