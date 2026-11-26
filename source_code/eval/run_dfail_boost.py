"""Re-run (with boost) ONLY the D (FULL) cells that did NOT succeed in the main sweep.

Reads eval/dfail_cells.json = list of [scenario, seed] (23 ran-but-failed + 3 no-report = 26).
Runs FULL (boost=True, fix_retry=False, qwen3.5) on each, writes dfail_boost.csv.
Final FULL/120 = 94 (already-passing) + (newly passing here). Per-run try/except.

Usage (on pod, in venv):  python eval/run_dfail_boost.py
"""
import sys, csv, json, shutil, subprocess
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from src.orchestrator import Orchestrator, Scenario, load_config

MTAG, MODEL, PREFIX = "q35", "qwen3.5:latest", "dfail"
FULL = {"pure_mode": False,
        "working_memory": True, "rag": True, "reflection": True, "guardrail": True,
        "state_graph": True, "tools_mcp": True, "sandbox": True, "auto_verify_xss": True,
        "long_term_memory": False, "web_search": False, "web_search_fallback": False,
        "skills": False, "eyes_ml": True, "progress_protection": True, "use_promise": True}


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
    cells = json.load(open(ROOT / "eval" / "dfail_cells.json"))
    data = yaml.safe_load(open(ROOT / "eval" / "scenarios.yaml", encoding="utf-8"))["scenarios"]
    byid = {str(s["id"]): s for s in data}

    out_csv = ROOT / "dfail_boost.csv"
    f = open(out_csv, "w", newline="", encoding="utf-8")
    w = csv.writer(f)
    w.writerow(["config", "seed", "scenario", "success", "iters", "wall", "finish_reason"])

    npass = 0
    for i, (sid, seed) in enumerate(cells, 1):
        seed = int(seed)
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
            npass += int(ok)
            row = ["FULL", seed, sid, int(ok), rep.get("iterations_used"),
                   round(rep.get("wall_clock_s", 0)), rep.get("finish_reason", "")]
            print(f"  [{i}/{len(cells)}] {sid} s{seed}: success={ok} it={rep.get('iterations_used')} "
                  f"wall={rep.get('wall_clock_s', 0):.0f}s finish={rep.get('finish_reason')}", flush=True)
        except Exception as e:
            row = ["FULL", seed, sid, 0, "", "", f"error:{type(e).__name__}"]
            print(f"  [{i}/{len(cells)}] {sid} s{seed}: ERROR {type(e).__name__}: {str(e)[:120]}", flush=True)
        w.writerow(row); f.flush()
    f.close()
    final = 94 + npass
    print(f"DFAIL_DONE boost_newpass={npass}/{len(cells)} :: FINAL FULL/120 = {final}/120 = {100*final/120:.1f}%", flush=True)


if __name__ == "__main__":
    main()
