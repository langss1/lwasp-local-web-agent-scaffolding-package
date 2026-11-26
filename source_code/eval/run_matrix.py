"""Driver: 2x3 matrix (eyes P0/P1 x controller C0/C1/C2) over 9 DEV scenarios.
Reuses existing c0c1-* runs for P0C0/P0C1 (identical config); runs the 4 remaining
conditions fresh as mtx-*. Resumable; writes report/MATRIX_2x3.md incrementally.
plan9.md M5. Usage: python eval/run_matrix.py"""
import sys, subprocess, json
from pathlib import Path

ROOT = Path(r"C:\Spesial TA\pentest-agent")
PY = sys.executable
SCEN = ["blind_sqli_low", "blind_sqli_medium", "blind_sqli_high",
        "sqli_low", "sqli_medium", "sqli_high",
        "xss_reflected_low", "xss_reflected_medium", "xss_reflected_high"]
EYES = ["P0", "P1"]; CTRL = ["C0", "C1", "C2"]
# P0C0/P0C1 already computed under c0c1-*; map them, run the other 4 fresh.
REUSE = {("P0", "C0"): "c0c1-{sid}-C0", ("P0", "C1"): "c0c1-{sid}-C1"}
OUT = ROOT / "report" / "MATRIX_2x3.md"


def rid_for(eyes, ctrl, sid):
    if (eyes, ctrl) in REUSE:
        return REUSE[(eyes, ctrl)].format(sid=sid)
    return f"mtx-{sid}-{eyes}{ctrl}"


def load(rid):
    p = ROOT / "runs" / rid / "report.json"
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None
    except Exception:
        return None


def write_table():
    L = ["# Matriks 2x3 — eyes (P0/P1) x controller (C0/C1/C2), DEV DVWA\n",
         "Scaffolding identik; seed 42; N=1 (eksploratif). P0C0/P0C1 reuse dari c0c1-*. "
         "Sukses = terverifikasi (interpreter/browser). Metrik: success | iter | holds.\n",
         "| Scenario | " + " | ".join(f"{e}{c}" for e in EYES for c in CTRL) + " |",
         "|---|" + "---|" * 6]
    cells = {ec: [0, 0, 0.0] for ec in [(e, c) for e in EYES for c in CTRL]}  # [succ, done, it_sum]
    for sid in SCEN:
        row = [sid]
        for e in EYES:
            for c in CTRL:
                r = load(rid_for(e, c, sid))
                if not r:
                    row.append("-"); continue
                s = r["success"]; row.append(f"{'OK' if s else 'x'} it{r['iterations_used']}")
                cells[(e, c)][0] += int(bool(s)); cells[(e, c)][1] += 1
                cells[(e, c)][2] += r["iterations_used"]
        L.append("| " + " | ".join(row) + " |")
    L.append("\n**Agregat (success/done, avg iter):**\n| Kondisi | success | avg_iter |\n|---|---|---|")
    for e in EYES:
        for c in CTRL:
            s, d, it = cells[(e, c)]
            L.append(f"| {e}{c} | {s}/{d} | {(it/d):.1f} |" if d else f"| {e}{c} | - | - |")
    L.append("\nBaca: C1-C0=efek aturan progress-protection; C2-C1=efek learned promise; "
             "P1-P0=efek N3 ML eyes. N=1 eksploratif (bukan jaminan statistik).")
    OUT.write_text("\n".join(L), encoding="utf-8")


def main():
    for sid in SCEN:
        for e in EYES:
            for c in CTRL:
                if (e, c) in REUSE:
                    continue  # reuse existing c0c1 run
                rid = f"mtx-{sid}-{e}{c}"
                if (ROOT / "runs" / rid / "report.json").exists():
                    print("skip", rid); continue
                print("RUN", rid, flush=True)
                try:
                    subprocess.run([PY, str(ROOT / "eval" / "one_run_matrix.py"), e, c, sid],
                                   cwd=str(ROOT), timeout=1500)
                except Exception as ex:
                    print("ERR", rid, ex, flush=True)
                write_table()
    write_table()
    print("DONE -> report/MATRIX_2x3.md")


if __name__ == "__main__":
    main()
