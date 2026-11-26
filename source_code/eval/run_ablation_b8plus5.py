"""Leave-one-out ablation on the CURRENT b8+5 system (12 components), DVWA 39 cells.

Replaces the old `run_ablation_loo.py` table, which was (a) only b8 (7 comp, the 5
new K-components were never ablated) and (b) run IN-PROCESS so a single environment
crash contaminated a config -- producing the implausible "every LOO beats Full"
artifact. This runner is HARDENED like run_dvwa_matrix: each cell in its OWN
subprocess (a hard crash kills one cell, not the config), resume-safe via
report.json, CSV rebuilt from report.json each run.

ΔSR = Full(b8+5) − LOO = marginal contribution of the removed component.
The Full reference is the CLEAN seed-42 run produced by run_dvwa_matrix
(rid dvext-q35-<sid>-s42) / run_dvwa_ext headline -- measured in the SAME healthy
environment, so ΔSR is apples-to-apples.

Base model qwen3.5 FROZEN. Oracle STRICT. 1 seed (42), matching the existing
ablation methodology. rid = abl2-<cname>-q35-<sid>-s42 (fresh namespace).

Run on pod:
    .venv/bin/python eval/run_ablation_b8plus5.py
"""
import csv, json, os, shutil, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from eval.run_dvwa_ext import FULL_EXT, reset_dvwa_state, scenarios as all_scenarios  # noqa: E402

MODEL, MTAG, SEED = "qwen3.5:latest", "q35", 42
CELL_TIMEOUT_S = 900

# Leave-one-out: FULL_EXT with exactly one component (or one coupled group) removed.
#   7 prior (b8) components + 5 new K-components = 12 configs.
#   L-SG removes the whole backtracking subsystem (state_graph + progress_protection
#   + use_promise); L-C2 removes ONLY the ML promise scorer, keeping state_graph.
CONFIGS = [
    # --- b8 (prior) ---
    ("L-RAG", {"rag": False}),
    ("L-REF", {"reflection": False}),
    ("L-GRD", {"guardrail": False}),
    ("L-TLS", {"tools_mcp": False}),
    ("L-N3",  {"eyes_ml": False}),
    ("L-SG",  {"state_graph": False, "progress_protection": False, "use_promise": False}),
    ("L-C2",  {"use_promise": False}),
    # --- b8+5 (new K-components) ---
    ("L-K4",  {"recon": False}),
    ("L-K7",  {"oracle_universal": False}),
    ("L-K8",  {"oast": False}),
    ("L-K12", {"context_summarizer": False}),
    ("L-K14", {"bandit": False}),
]
CMAP = {c: ov for c, ov in CONFIGS}


def run_one(cname, sid):
    from src.orchestrator import Orchestrator, Scenario, load_config
    s = next(x for x in all_scenarios() if str(x["id"]) == sid)
    scen = Scenario.from_dict(s)
    cfg = load_config(ROOT / "config.yaml")
    comp = dict(FULL_EXT); comp.update(CMAP[cname])
    cfg["components"] = comp
    cfg["bandit"] = {"store_path": f"data/bandit/abl2_{cname}_dvwa.joblib"}
    cfg["model"]["name"] = MODEL
    cfg["model"]["seed"] = SEED
    cfg.setdefault("run", {})["fix_retry"] = False
    reset_dvwa_state()
    Orchestrator(cfg, scen, run_id=f"abl2-{cname}-{MTAG}-{sid}-s{SEED}").run()


def run_config(cname, scens, w, f):
    npass = 0
    print(f"\n=== CONFIG {cname} (remove {CMAP[cname]}) ===", flush=True)
    for s in scens:
        sid = str(s["id"]); level = s.get("level")
        rd = ROOT / "runs" / f"abl2-{cname}-{MTAG}-{sid}-s{SEED}"
        rep = rd / "report.json"
        if rep.exists():
            try:
                r = json.loads(rep.read_text(encoding="utf-8"))
                ok = bool(r.get("success")); npass += int(ok)
                w.writerow([cname, sid, level, int(ok), r.get("iterations_used"),
                            round(r.get("wall_clock_s", 0)), r.get("finish_reason", "")])
                f.flush(); print(f"  SKIP {sid} ({ok})", flush=True); continue
            except Exception:
                shutil.rmtree(rd, ignore_errors=True)
        if rd.exists():
            shutil.rmtree(rd, ignore_errors=True)
        try:
            subprocess.run([sys.executable, str(Path(__file__).resolve()), "--one", cname, sid],
                           cwd=str(ROOT), timeout=CELL_TIMEOUT_S, env={**os.environ})
        except subprocess.TimeoutExpired:
            print(f"  [{sid}] TIMEOUT", flush=True)
        except Exception as e:  # noqa: BLE001
            print(f"  [{sid}] SUBPROC_ERR {type(e).__name__}", flush=True)
        if rep.exists():
            try:
                r = json.loads(rep.read_text(encoding="utf-8"))
                ok = bool(r.get("success")); npass += int(ok)
                w.writerow([cname, sid, level, int(ok), r.get("iterations_used"),
                            round(r.get("wall_clock_s", 0)), r.get("finish_reason", "")])
                print(f"  [{sid}] success={ok} it={r.get('iterations_used')}", flush=True)
            except Exception:
                w.writerow([cname, sid, level, 0, "", "", "badjson"])
        else:
            w.writerow([cname, sid, level, 0, "", "", "crash:no_report"])
            print(f"  [{sid}] CRASH no report.json", flush=True)
        f.flush()
    print(f"### CFG_DONE {cname}: {npass}/{len(scens)} = {npass/len(scens):.0%}", flush=True)
    return npass


def main():
    scens = all_scenarios()
    n = len(scens)
    print(f"ABLATION b8+5 LOO: {len(CONFIGS)} configs x {n} cells x 1 seed({SEED}) "
          f"= {len(CONFIGS)*n} cells [subprocess-isolated, resume-safe]", flush=True)
    out = ROOT / "results" / "ablation_b8plus5.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    f = open(out, "w", newline="", encoding="utf-8")
    w = csv.writer(f)
    w.writerow(["config", "scenario", "level", "success", "iters", "wall", "finish_reason"])
    summ = []
    for cname, _ in CONFIGS:
        p = run_config(cname, scens, w, f)
        summ.append(f"{cname}={p}/{n}")
    f.close()
    print(f"\nABLATION_B8PLUS5_DONE :: " + " | ".join(summ), flush=True)
    print(f"  (ΔSR per komponen = Full(b8+5 s42) − LOO; Full ref = dvext-q35-*-s42)", flush=True)


if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "--one":
        run_one(sys.argv[2], sys.argv[3])
    else:
        main()
