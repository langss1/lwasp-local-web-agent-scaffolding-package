"""DVWA Full-EXTENDED (b8+5) matriks model x seed -- melengkapi headline q35/s42 (33/39).

Kombinasi (keputusan user 2026-11-09, scope penuh):
  qwen3.5 (q35) : seed 7, 123           (seed 42 sudah = dvext-<sid>-s42, headline 33/39)
  qwen2.5 (q25) : seed 42, 7, 123
= 5 run x 39 sel = 195 sel.

Base model FROZEN, oracle STRICT, config b8+5 IDENTIK run_dvwa_ext.FULL_EXT.
Subprocess-isolated (crash 1 sel tak bunuh driver), resume-safe via report.json,
CSV per kombinasi. rid = dvext-<mtag>-<sid>-s<seed> (TIDAK menimpa headline s42 q35).

Jalankan DI POD: .venv/bin/python eval/run_dvwa_matrix.py
"""
import csv, json, os, shutil, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from eval.run_dvwa_ext import FULL_EXT, reset_dvwa_state, scenarios as all_scenarios  # noqa: E402

CELL_TIMEOUT_S = 900
# (model_tag_ollama, mtag_short, seed)
COMBOS = [
    ("qwen3.5:latest", "q35", 7),
    ("qwen3.5:latest", "q35", 123),
    ("qwen2.5:latest", "q25", 42),
    ("qwen2.5:latest", "q25", 7),
    ("qwen2.5:latest", "q25", 123),
]


def run_one(model, mtag, seed, sid):
    from src.orchestrator import Orchestrator, Scenario, load_config
    s = next(x for x in all_scenarios() if str(x["id"]) == sid)
    scen = Scenario.from_dict(s)
    cfg = load_config(ROOT / "config.yaml")
    cfg["components"] = dict(FULL_EXT)
    cfg["bandit"] = {"store_path": f"data/bandit/dvext_{mtag}_dvwa.joblib"}
    cfg["model"]["name"] = model
    cfg["model"]["seed"] = int(seed)
    reset_dvwa_state()
    Orchestrator(cfg, scen, run_id=f"dvext-{mtag}-{sid}-s{seed}").run()


def run_combo(model, mtag, seed):
    scens = all_scenarios()
    print(f"\n### COMBO {mtag} seed {seed} ({model}) : {len(scens)} sel ###", flush=True)
    out_csv = ROOT / "results" / f"dvwa_ext_{mtag}_s{seed}.csv"
    f = open(out_csv, "w", newline="", encoding="utf-8")
    w = csv.writer(f)
    w.writerow(["scenario", "level", "success", "iters", "wall", "finish_reason"])
    npass = 0
    for s in scens:
        sid = str(s["id"]); level = s.get("level")
        rd = ROOT / "runs" / f"dvext-{mtag}-{sid}-s{seed}"
        rep_path = rd / "report.json"
        if rep_path.exists():
            try:
                rep = json.loads(rep_path.read_text(encoding="utf-8"))
                ok = bool(rep.get("success")); npass += int(ok)
                w.writerow([sid, level, int(ok), rep.get("iterations_used"),
                            round(rep.get("wall_clock_s", 0)), rep.get("finish_reason", "")])
                f.flush(); print(f"  SKIP {sid} (done, {ok})", flush=True); continue
            except Exception:
                shutil.rmtree(rd, ignore_errors=True)
        if rd.exists():
            shutil.rmtree(rd, ignore_errors=True)
        try:
            subprocess.run([sys.executable, str(Path(__file__).resolve()),
                            "--one", model, mtag, str(seed), sid],
                           cwd=str(ROOT), timeout=CELL_TIMEOUT_S, env={**os.environ})
        except subprocess.TimeoutExpired:
            print(f"  [{sid}] TIMEOUT", flush=True)
        except Exception as e:  # noqa: BLE001
            print(f"  [{sid}] SUBPROC_ERR {type(e).__name__}", flush=True)
        if rep_path.exists():
            try:
                rep = json.loads(rep_path.read_text(encoding="utf-8"))
                ok = bool(rep.get("success")); npass += int(ok)
                w.writerow([sid, level, int(ok), rep.get("iterations_used"),
                            round(rep.get("wall_clock_s", 0)), rep.get("finish_reason", "")])
                print(f"  [{sid}] success={ok} it={rep.get('iterations_used')} "
                      f"wall={rep.get('wall_clock_s',0):.0f}s", flush=True)
            except Exception as e:
                w.writerow([sid, level, 0, "", "", f"badjson:{type(e).__name__}"])
                print(f"  [{sid}] badjson", flush=True)
        else:
            w.writerow([sid, level, 0, "", "", "crash:no_report"])
            print(f"  [{sid}] CRASH no report.json", flush=True)
        f.flush()
    f.close()
    print(f"### COMBO_DONE {mtag} s{seed}: {npass}/{len(scens)} = {npass/len(scens):.0%} csv={out_csv}", flush=True)
    return npass, len(scens)


def main():
    print(f"DVWA MATRIX b8+5: {len(COMBOS)} kombinasi x 39 sel", flush=True)
    summary = []
    for model, mtag, seed in COMBOS:
        p, n = run_combo(model, mtag, seed)
        summary.append(f"{mtag}/s{seed}={p}/{n}")
    print(f"\nMATRIX_DONE :: " + " | ".join(summary), flush=True)


if __name__ == "__main__":
    if len(sys.argv) >= 6 and sys.argv[1] == "--one":
        run_one(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    else:
        main()
