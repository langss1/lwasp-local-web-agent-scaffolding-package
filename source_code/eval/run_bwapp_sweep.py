"""External-validity replication sweep against bWAPP (plan14.md).

Runs the SAME agent (same budget, model, oracle dispatch) as the DVWA headline,
changing ONLY the target app (DVWA -> bWAPP), to test whether the scaffolding
effect (Full > Base) replicates on an independent, recognised benchmark.

Matrix (108 run):  18 scenarios (6 classes x 3 levels)
                   x {Base (L1), Full (L3)}
                   x seeds {42, 7, 123}
                   x model qwen3.5:latest (9B), non-boost.

Writes results/bwapp_sweep.csv + runs/bw-* trajectories. Per-run try/except so
one crash never aborts the sweep.

Run ON the pod, in venv, AFTER bWAPP is deployed + smoke-confirmed (plan14 P1b):
    python eval/run_bwapp_sweep.py
    python eval/run_bwapp_sweep.py --conditions Full      # Full-only (tahap-1)
"""
import sys, csv, json, argparse, subprocess
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from src.orchestrator import (Orchestrator, Scenario, load_config,
                              set_sqli_row_markers, set_blind_markers)

MODEL = "qwen3.5:latest"
SEEDS = [42, 7, 123]

# bWAPP served as a sibling of DVWA on the same pod. TODO-confirm path/case (P1b).
BWAPP_BASE_URL = "http://localhost/bWAPP"
BWAPP_USER, BWAPP_PASS = "bee", "bug"

# bWAPP in-band SQLi (sqli_1.php movie search) repeats this per-row token in the
# result table. TODO-confirm the exact token during P1b smoke, then correct here.
BWAPP_SQLI_ROW_MARKERS = ['<tr height="30">']   # confirmed P1b smoke: bWAPP movie result data-row
# Blind boolean SQLi (sqli_6.php, POST): TRUE branch returns real movie rows (which
# carry an IMDb link), FALSE branch shows "No movies were found!". Confirmed P1b smoke.
BWAPP_BLIND_EXISTS = ["imdb.com/title/"]
BWAPP_BLIND_MISSING = ["No movies were found"]

# L3 = Full (all scaffolding, non-boost). Identical to the DVWA headline's D.
FULL = {"pure_mode": False,
        "working_memory": True, "rag": True, "reflection": True, "guardrail": True,
        "state_graph": True, "tools_mcp": True, "sandbox": True, "auto_verify_xss": True,
        "long_term_memory": False, "web_search": False, "web_search_fallback": False,
        "skills": False, "eyes_ml": True, "progress_protection": True, "use_promise": True}
# L1 = Base (pure ReAct, 0 components). Identical to the DVWA headline's A/C.
BASE = {"pure_mode": True,
        "working_memory": False, "rag": False, "reflection": False, "guardrail": False,
        "state_graph": False, "tools_mcp": False, "sandbox": False, "auto_verify_xss": False,
        "long_term_memory": False, "web_search": False, "web_search_fallback": False,
        "skills": False, "eyes_ml": False, "progress_protection": False, "use_promise": False}
CONDITIONS = {"Base": BASE, "Full": FULL}


def reset_bwapp_state():
    """Best-effort reset of bWAPP stored state (blog entries for stored-XSS) so
    each seed starts clean. TODO-confirm the reset path/DB during P1b; no-op-safe."""
    try:
        subprocess.run(
            ["mysql", "-uroot", "-e",
             "USE bWAPP; DELETE FROM blog;"],   # TODO-confirm db/table name
            timeout=15, check=False,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--conditions", nargs="+", default=["Base", "Full"],
                    choices=["Base", "Full"], help="which conditions to run")
    ap.add_argument("--scenarios", default=str(ROOT / "eval" / "scenarios_bwapp.yaml"))
    args = ap.parse_args()

    set_sqli_row_markers(BWAPP_SQLI_ROW_MARKERS)
    set_blind_markers(exists=BWAPP_BLIND_EXISTS, missing=BWAPP_BLIND_MISSING)
    data = yaml.safe_load(open(args.scenarios, encoding="utf-8"))["scenarios"]

    out_csv = ROOT / "results" / "bwapp_sweep.csv"
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    f = open(out_csv, "w", newline="", encoding="utf-8")
    w = csv.writer(f)
    w.writerow(["config", "mtag", "scenario", "level", "seed",
                "success", "iters", "wall", "tokens", "finish_reason"])

    total = len(data) * len(args.conditions) * len(SEEDS)
    done = npass = 0
    for cond in args.conditions:
        comps = CONDITIONS[cond]
        for s in data:
            sid = str(s["id"])
            for seed in SEEDS:
                done += 1
                rid = f"bw-{cond}-q35-{sid}-s{seed}"
                try:
                    scen = Scenario.from_dict(s)
                    cfg = load_config(ROOT / "config.yaml")
                    cfg["components"] = dict(comps)
                    cfg["model"]["name"] = MODEL
                    cfg["model"]["seed"] = seed
                    cfg.setdefault("run", {})["fix_retry"] = False
                    cfg["run"]["boost"] = False
                    # --- only the target app changes vs the DVWA headline ---
                    cfg["target"]["base_url"] = BWAPP_BASE_URL
                    cfg["target"]["login_user"] = BWAPP_USER
                    cfg["target"]["login_pass"] = BWAPP_PASS
                    cfg["target"]["app"] = "bwapp"
                    reset_bwapp_state()
                    rep = Orchestrator(cfg, scen, run_id=rid).run()
                    ok = bool(rep.get("success"))
                    npass += int(ok)
                    row = [cond, "q35", sid, s.get("level"), seed, int(ok),
                           rep.get("iterations_used"), round(rep.get("wall_clock_s", 0)),
                           rep.get("tokens_used", ""), rep.get("finish_reason", "")]
                    print(f"[{done}/{total}] {cond} {sid} s{seed}: success={ok} "
                          f"it={rep.get('iterations_used')} wall={rep.get('wall_clock_s', 0):.0f}s",
                          flush=True)
                except Exception as e:
                    row = [cond, "q35", sid, s.get("level"), seed, 0, "", "", "",
                           f"error:{type(e).__name__}"]
                    print(f"[{done}/{total}] {cond} {sid} s{seed}: ERROR "
                          f"{type(e).__name__}: {str(e)[:120]}", flush=True)
                w.writerow(row); f.flush()
    f.close()
    print(f"BWAPP_SWEEP_DONE pass={npass}/{done} :: csv={out_csv}", flush=True)


if __name__ == "__main__":
    main()
