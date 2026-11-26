"""N2 statistical validation: C0 vs C1 over 9 scenarios × 3 seeds (plan10 M-E, audit GPT:
N=1 tak cukup). Uses the FIXED semantic progress definition. Resumable; writes
report/C0C1_SEEDS.md incrementally with per-seed and mean±range aggregates.
Usage: python eval/run_c1_seeds.py"""
import sys, subprocess, json
from pathlib import Path

ROOT = Path(r"C:\Spesial TA\pentest-agent")
PY = sys.executable
SCEN = ["blind_sqli_low", "blind_sqli_medium", "blind_sqli_high",
        "sqli_low", "sqli_medium", "sqli_high",
        "xss_reflected_low", "xss_reflected_medium", "xss_reflected_high"]
CONDS = ["C0", "C1"]; SEEDS = [42, 43, 44]
OUT = ROOT / "report" / "C0C1_SEEDS.md"


def load(sid, c, s):
    p = ROOT / "runs" / f"c0c1-{sid}-{c}-s{s}" / "report.json"
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None
    except Exception:
        return None


def write_table():
    L = ["# N2 — C0 vs C1 across seeds (statistik, plan10 M-E)\n",
         "Progress def SEMANTIK (fixed). Scaffolding identik; beda tunggal = progress_protection. "
         "Sukses terverifikasi.\n",
         "| Kondisi | seed42 | seed43 | seed44 | **mean success/9** |", "|---|---|---|---|---|"]
    agg = {}
    for c in CONDS:
        cells = []
        per_seed_succ = []
        for s in SEEDS:
            got = [load(sid, c, s) for sid in SCEN]
            done = [r for r in got if r]
            succ = sum(1 for r in done if r["success"])
            per_seed_succ.append(succ if len(done) == len(SCEN) else None)
            cells.append(f"{succ}/{len(done)}" if done else "-")
        vals = [v for v in per_seed_succ if v is not None]
        mean = f"{sum(vals)/len(vals):.1f}" if vals else "-"
        rng = f" (min {min(vals)}, max {max(vals)})" if vals else ""
        agg[c] = (mean, rng)
        L.append(f"| {c} | {cells[0]} | {cells[1]} | {cells[2]} | **{mean}{rng}** |")
    L.append(f"\n**Ringkas:** C0 mean {agg['C0'][0]}{agg['C0'][1]} vs C1 mean {agg['C1'][0]}{agg['C1'][1]}. "
             "Kalau C1>C0 konsisten di 3 seed → N2-C1 naik ke 'didukung bukti'; kalau tumpang-tindih → "
             "'belum konklusif' (jujur). N=3 = pilot, bukan jaminan penuh.")
    OUT.write_text("\n".join(L), encoding="utf-8")


def main():
    for s in SEEDS:
        for sid in SCEN:
            for c in CONDS:
                rid = f"c0c1-{sid}-{c}-s{s}"
                if (ROOT / "runs" / rid / "report.json").exists():
                    print("skip", rid); continue
                print("RUN", rid, flush=True)
                try:
                    subprocess.run([PY, str(ROOT / "eval" / "one_run_c.py"), c, sid, str(s)],
                                   cwd=str(ROOT), timeout=1500)
                except Exception as e:
                    print("ERR", rid, e, flush=True)
                write_table()
    write_table()
    print("DONE -> report/C0C1_SEEDS.md")


if __name__ == "__main__":
    main()
