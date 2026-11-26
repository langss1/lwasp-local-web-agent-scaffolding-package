"""Re-run FULL (boost=True) on the 3 testcases FULL failed in the boost batch.

Target: FULL solves sqli_high, csrf_medium, csrf_high -> 16/16 on the hard-set.
Same FULL toggles / seed / model / budget as eval/run_boost_hardset.py. Writes
full3.csv and prints FULL3_DONE with the per-TC verdict. Per-run try/except so a
transient localhost hiccup cannot abort the batch.

Usage (on pod, in venv):  python eval/run_full3.py
"""
import sys, csv, shutil, subprocess
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from src.orchestrator import Orchestrator, Scenario, load_config

MTAG, MODEL, SEED, PREFIX = "q35", "qwen3.5:latest", 42, "full3"

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
    scens = [byid[t] for t in TARGET]
    assert len(scens) == 3, "missing a target TC in scenarios.yaml"

    out_csv = ROOT / "full3.csv"
    f = open(out_csv, "w", newline="", encoding="utf-8")
    w = csv.writer(f)
    w.writerow(["config", "scenario", "success", "iters", "wall", "finish_reason"])

    results = {}
    for s in scens:
        sid = s["id"]
        rid = f"{PREFIX}-FULL-{MTAG}-{sid}-s{SEED}"
        rd = ROOT / "runs" / rid
        if rd.exists():
            shutil.rmtree(rd, ignore_errors=True)
        try:
            scen = Scenario.from_dict(s)
            cfg = load_config(ROOT / "config.yaml")
            cfg["components"] = dict(FULL)
            cfg["model"]["name"] = MODEL
            cfg["model"]["seed"] = SEED
            cfg.setdefault("run", {})["fix_retry"] = False
            cfg["run"]["boost"] = True
            reset_dvwa_state()
            rep = Orchestrator(cfg, scen, run_id=rid).run()
            ok = bool(rep.get("success"))
            row = ["FULL", sid, int(ok), rep.get("iterations_used"),
                   round(rep.get("wall_clock_s", 0)), rep.get("finish_reason", "")]
            results[sid] = ok
            print(f"  {sid}: success={ok} it={rep.get('iterations_used')} "
                  f"wall={rep.get('wall_clock_s', 0):.0f}s finish={rep.get('finish_reason')}", flush=True)
        except Exception as e:
            row = ["FULL", sid, 0, "", "", f"error:{type(e).__name__}"]
            results[sid] = False
            print(f"  {sid}: ERROR {type(e).__name__}: {str(e)[:120]}", flush=True)
        w.writerow(row); f.flush()
    f.close()
    n = sum(1 for v in results.values() if v)
    print(f"FULL3_DONE {n}/3 passed :: " + ", ".join(f"{k}={'OK' if v else 'FAIL'}" for k, v in results.items()), flush=True)


if __name__ == "__main__":
    main()
