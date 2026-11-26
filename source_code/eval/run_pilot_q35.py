"""PILOT for LAPORAN_N3_FULLSYSTEM (Qwen3.5). Small sample so user can review the
report FORMAT before the full 240-run sweep. Namespace 'pilot-' -> isolated from the
future full sweep (f40-) and from the old multiseed (ms-). FRESH each run.
Cells: D (L3, +sistem) x {sqli_medium, xss_reflected_high, cmdi_medium} + C (L1, base) x {sqli_medium}.
Usage: python eval/run_pilot_q35.py"""
import sys, subprocess
from pathlib import Path

ROOT = Path(r"C:\Spesial TA\pentest-agent"); PY = sys.executable
SEED = 42
MODEL = "qwen3.5:latest"; MTAG = "q35"
CELLS = [                                   # (cond, level, scenario)
    ("D", "L3", "sqli_medium"),
    ("D", "L3", "xss_reflected_high"),
    ("D", "L3", "cmdi_medium"),
    ("C", "L1", "sqli_medium"),
]


def main():
    for cond, lvl, sid in CELLS:
        rid = f"pilot-{MTAG}-{sid}-{lvl}-s{SEED}"
        if (ROOT / "runs" / rid / "report.json").exists():      # resume-safe: skip finished cell
            print(f"SKIP {cond} {sid} (sudah ada report.json)", flush=True); continue
        print(f"\n=== RUN {cond} ({lvl}) {sid} seed{SEED} -> {rid} ===", flush=True)
        try:
            subprocess.run([PY, str(ROOT / "eval" / "one_run_seed.py"),
                            MTAG, MODEL, lvl, sid, str(SEED), "pilot"],
                           cwd=str(ROOT), timeout=1200)
        except Exception as e:
            print("ERR", cond, sid, e, flush=True)
    print("\nPILOT DONE", flush=True)


if __name__ == "__main__":
    main()
