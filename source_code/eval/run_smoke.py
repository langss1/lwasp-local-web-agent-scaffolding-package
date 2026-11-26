"""M3 smoke-gate: run the FULL-ML agent (P1 eyes + C1/C2 controller) on the HARDEST
scenario per category at DVWA, using the matured N3 model. Cheap gate before full M4.
plan10 M3. Jelek -> balik M2; bagus -> M4. Usage: python eval/run_smoke.py"""
import sys, subprocess, json
from pathlib import Path

ROOT = Path(r"C:\Spesial TA\pentest-agent"); PY = sys.executable
# hardest / previously-failing per category
HARD = ["sqli_medium", "sqli_high", "blind_sqli_medium", "blind_sqli_high", "xss_reflected_high"]
OUT = ROOT / "report" / "SMOKE_M3.md"


def main():
    rows = ["# M3 Smoke-gate (full-ML agen: P1 eyes + C1/C2) di DVWA, kasus tersulit\n",
            "| Scenario | success | iter | holds |", "|---|---|---|---|"]
    succ = done = 0
    for sid in HARD:
        rid = f"mtx-{sid}-P1C2"   # reuse matrix runner cell = full-ML condition
        # force fresh (new N3 model): remove old if exists
        rd = ROOT / "runs" / rid
        if (rd / "report.json").exists():
            import shutil; shutil.rmtree(rd, ignore_errors=True)
        print("SMOKE", sid, flush=True)
        try:
            subprocess.run([PY, str(ROOT / "eval" / "one_run_matrix.py"), "P1", "C2", sid],
                           cwd=str(ROOT), timeout=1500)
        except Exception as e:
            print("ERR", sid, e)
        p = rd / "report.json"
        if p.exists():
            r = json.loads(p.read_text(encoding="utf-8")); done += 1; succ += int(bool(r["success"]))
            rows.append(f"| {sid} | {r['success']} | {r['iterations_used']} | {r.get('progress_holds',0)} |")
        else:
            rows.append(f"| {sid} | (no report) | - | - |")
        OUT.write_text("\n".join(rows + [f"\n**Smoke: {succ}/{done} berhasil.** "
                        "Gate: kalau >=2/5 di kasus tersulit -> lanjut M4 full; kalau <2 -> balik M2 + insight."]),
                       encoding="utf-8")
    print(f"SMOKE DONE {succ}/{done}")


if __name__ == "__main__":
    main()
