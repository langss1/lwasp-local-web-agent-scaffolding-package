"""Re-run 6 sel DVWA yang GAGAL di Full-extended (b8+5), seed 42 -- cek variance +
lihat respons agent. Config & seed IDENTIK run asli; bedanya cuma prefix dir (rr6-)
supaya hasil asli (dvext-, headline 33/39) TIDAK tertimpa.

Subprocess-isolated (crash 1 sel tak bunuh driver). Trace per sel di runs/rr6-<sid>-s42/.
Jalankan DI POD: .venv/bin/python eval/run_dvwa_rerun6.py
"""
import csv, json, os, shutil, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from eval.run_dvwa_ext import FULL_EXT, reset_dvwa_state, scenarios as all_scenarios  # noqa: E402

MODEL, SEED, PREFIX = "qwen3.5:latest", 42, "rr6"
CELL_TIMEOUT_S = 900
FAILED6 = ["sqli_medium", "sqli_high", "csrf_medium", "csrf_high", "js_high", "upload_high"]


def run_one(sid):
    from src.orchestrator import Orchestrator, Scenario, load_config
    s = next(x for x in all_scenarios() if str(x["id"]) == sid)
    scen = Scenario.from_dict(s)
    cfg = load_config(ROOT / "config.yaml")
    cfg["components"] = dict(FULL_EXT)
    cfg["bandit"] = {"store_path": f"data/bandit/{PREFIX}_dvwa.joblib"}
    cfg["model"]["name"] = MODEL
    cfg["model"]["seed"] = SEED
    reset_dvwa_state()
    Orchestrator(cfg, scen, run_id=f"{PREFIX}-{sid}-s{SEED}").run()


def main():
    scens = {str(s["id"]): s for s in all_scenarios()}
    print(f"DVWA RE-RUN 6-fail (b8+5, seed {SEED}) [subprocess-isolated]", flush=True)
    out_csv = ROOT / "results" / "dvwa_rerun6.csv"
    f = open(out_csv, "w", newline="", encoding="utf-8")
    w = csv.writer(f); w.writerow(["scenario", "orig", "rerun", "iters", "wall", "finish_reason"])
    ORIG = {"sqli_medium": 0, "sqli_high": 0, "csrf_medium": 0, "csrf_high": 0, "js_high": 0, "upload_high": 0}
    npass = 0
    for sid in FAILED6:
        rd = ROOT / "runs" / f"{PREFIX}-{sid}-s{SEED}"
        if rd.exists():
            shutil.rmtree(rd, ignore_errors=True)
        try:
            subprocess.run([sys.executable, str(Path(__file__).resolve()), "--one", sid],
                           cwd=str(ROOT), timeout=CELL_TIMEOUT_S, env={**os.environ})
        except subprocess.TimeoutExpired:
            print(f"  [{sid}] TIMEOUT", flush=True)
        except Exception as e:  # noqa: BLE001
            print(f"  [{sid}] SUBPROC_ERR {type(e).__name__}", flush=True)
        rep_path = rd / "report.json"
        if rep_path.exists():
            rep = json.loads(rep_path.read_text(encoding="utf-8"))
            ok = bool(rep.get("success")); npass += int(ok)
            flip = "SAMA-gagal" if not ok else ">>> BERHASIL (flip!)"
            w.writerow([sid, ORIG[sid], int(ok), rep.get("iterations_used"),
                        round(rep.get("wall_clock_s", 0)), rep.get("finish_reason", "")])
            print(f"  [{sid}] rerun_success={ok} it={rep.get('iterations_used')} "
                  f"wall={rep.get('wall_clock_s', 0):.0f}s  {flip}", flush=True)
        else:
            w.writerow([sid, ORIG[sid], "", "", "", "crash:no_report"])
            print(f"  [{sid}] CRASH no report.json", flush=True)
        f.flush()
    f.close()
    print(f"\nRERUN6_DONE: {npass}/6 flipped to success (orig 0/6). csv={out_csv}", flush=True)


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--one":
        run_one(sys.argv[2])
    else:
        main()
