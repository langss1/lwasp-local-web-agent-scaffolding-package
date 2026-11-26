"""FULL sweep (Qwen2.5): A (base/L1) & B (+sistem/L3) x 40 scenarios x 3 seeds.
Twin of run_full40_q35.py for the second model. Namespace 'f40-q25-'. Both
conditions share the qwen2.5 model so it loads once. Resume-safe.
Portable: ROOT derived from this file. Usage: python eval/run_full40_q25.py"""
import sys, subprocess, yaml, json
from pathlib import Path
from subprocess import TimeoutExpired

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
SEEDS = [42, 7, 123]
MODEL = "qwen2.5:latest"; MTAG = "q25"
COND = [("A", "L1"), ("B", "L3")]          # base, then +sistem


def scenarios():
    s = yaml.safe_load(open(ROOT / "eval" / "scenarios.yaml", encoding="utf-8"))["scenarios"]
    seen, out = set(), []
    for x in s:
        if x["id"] not in seen:
            seen.add(x["id"]); out.append(x["id"])
    return out


def main():
    sids = scenarios()
    total = len(sids) * len(SEEDS) * len(COND)
    print(f"FULL40 sweep (q25): {len(sids)} skenario x {len(SEEDS)} seed x {len(COND)} kondisi = {total} run", flush=True)
    done = 0
    for sid in sids:
        for sd in SEEDS:
            for cond, lvl in COND:
                rid = f"f40-{MTAG}-{sid}-{lvl}-s{sd}"
                done += 1
                if (ROOT / "runs" / rid / "report.json").exists():
                    print(f"[{done}/{total}] SKIP {cond} {sid} s{sd}", flush=True); continue
                print(f"[{done}/{total}] RUN {cond} {sid} s{sd} -> {rid}", flush=True)
                try:
                    subprocess.run([PY, str(ROOT / "eval" / "one_run_seed.py"),
                                    MTAG, MODEL, lvl, sid, str(sd), "f40"],
                                   cwd=str(ROOT), timeout=1800)
                except TimeoutExpired:
                    rd = ROOT / "runs" / rid; rd.mkdir(parents=True, exist_ok=True)
                    rep = rd / "report.json"
                    if not rep.exists():
                        rep.write_text(json.dumps({
                            "run_id": rid, "scenario_id": sid,
                            "success": False, "agent_finished_success": False,
                            "finish_reason": "timeout_killed",
                            "iterations_to_success": None, "iterations_used": None,
                            "wall_clock_s": 1800, "peak_vram_mb": 0, "peak_ram_mb": 0,
                            "tokens_used": 0, "components": {"pure_mode": lvl == "L1"},
                        }, indent=2), encoding="utf-8")
                    print("  TIMEOUT->not-success(written)", cond, sid, sd, flush=True)
                except Exception as e:
                    print("  ERR", cond, sid, sd, e, flush=True)
    print("FULL40 DONE", flush=True)


if __name__ == "__main__":
    main()
