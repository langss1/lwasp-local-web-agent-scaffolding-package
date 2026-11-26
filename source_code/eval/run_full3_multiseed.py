"""Multi-seed robustness confirmation for the 3 hard-set TCs FULL failed without boost.

Re-run FULL (boost=True, fix_retry=False) on sqli_high / csrf_medium / csrf_high at
seeds 7 and 123 (seed 42 already confirmed 3/3 in run_full3.py). Writes
full3_multiseed.csv and prints FULL3MS_DONE with per-(seed,TC) verdict. Per-run
try/except so a transient hiccup cannot abort the batch.

Usage (on pod, in venv):  python eval/run_full3_multiseed.py
"""
import sys, csv, shutil, subprocess
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from src.orchestrator import Orchestrator, Scenario, load_config

MTAG, MODEL, PREFIX = "q35", "qwen3.5:latest", "full3ms"
SEEDS = [7, 123]

FULL = {"pure_mode": False,
        "working_memory": True, "rag": True, "reflection": True, "guardrail": True,
        "state_graph": True, "tools_mcp": True, "sandbox": True, "auto_verify_xss": True,
        "long_term_memory": False, "web_search": False, "web_search_fallback": False,
        "skills": False, "eyes_ml": True, "progress_protection": True, "use_promise": True}

TARGET = ["sqli_high", "csrf_medium", "csrf_high"]


def reset_dvwa_state():
    try:
        subprocess.run(
            ["mariadb", "-uroot", "-e",
             "USE dvwa; UPDATE users SET password=md5('password') WHERE user='admin';"],
            timeout=15, check=False,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def main():
    data = yaml.safe_load(open(ROOT / "eval" / "scenarios.yaml", encoding="utf-8"))["scenarios"]
    byid = {str(s["id"]): s for s in data}

    out_csv = ROOT / "full3_multiseed.csv"
    f = open(out_csv, "w", newline="", encoding="utf-8")
    w = csv.writer(f)
    w.writerow(["config", "seed", "scenario", "success", "iters", "wall", "finish_reason"])

    results = {}
    for seed in SEEDS:
        for sid in TARGET:
            s = byid[sid]
            rid = f"{PREFIX}-FULL-{MTAG}-{sid}-s{seed}"
            rd = ROOT / "runs" / rid
            if rd.exists():
                shutil.rmtree(rd, ignore_errors=True)
            try:
                scen = Scenario.from_dict(s)
                cfg = load_config(ROOT / "config.yaml")
                cfg["components"] = dict(FULL)
                cfg["model"]["name"] = MODEL
                cfg["model"]["seed"] = seed
                cfg.setdefault("run", {})["fix_retry"] = False
                cfg["run"]["boost"] = True
                reset_dvwa_state()
                rep = Orchestrator(cfg, scen, run_id=rid).run()
                ok = bool(rep.get("success"))
                row = ["FULL", seed, sid, int(ok), rep.get("iterations_used"),
                       round(rep.get("wall_clock_s", 0)), rep.get("finish_reason", "")]
                results[(seed, sid)] = ok
                print(f"  seed={seed} {sid}: success={ok} it={rep.get('iterations_used')} "
                      f"wall={rep.get('wall_clock_s', 0):.0f}s finish={rep.get('finish_reason')}", flush=True)
            except Exception as e:
                row = ["FULL", seed, sid, 0, "", "", f"error:{type(e).__name__}"]
                results[(seed, sid)] = False
                print(f"  seed={seed} {sid}: ERROR {type(e).__name__}: {str(e)[:120]}", flush=True)
            w.writerow(row); f.flush()
    f.close()
    n = sum(1 for v in results.values() if v)
    tot = len(results)
    detail = ", ".join(f"s{se}:{sid}={'OK' if ok else 'FAIL'}" for (se, sid), ok in results.items())
    print(f"FULL3MS_DONE {n}/{tot} passed :: {detail}", flush=True)


if __name__ == "__main__":
    main()
