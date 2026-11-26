"""M3-clean: 3-level smoke (Pure / Scaffold / Full-ML) on hardest cases, FRESH runs,
no leak. plan10. Writes report/SMOKE3.md with the 3-level comparison.
Usage: python eval/run_smoke3.py"""
import sys, subprocess, json
from pathlib import Path

ROOT = Path(r"C:\Spesial TA\pentest-agent"); PY = sys.executable
HARD = ["sqli_medium", "sqli_high", "blind_sqli_medium", "blind_sqli_high", "xss_reflected_high"]
LVL = {"L1": "Pure", "L2": "Scaffold", "L3": "Full-ML"}
OUT = ROOT / "report" / "SMOKE3.md"


def load(sid, l):
    # L3 (Full-ML) reuses the already-run matrix cell (mtx-*-P1C2) -- no re-run.
    name = f"mtx-{sid}-P1C2" if l == "L3" else f"smk-{sid}-{l}"
    p = ROOT / "runs" / name / "report.json"
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None
    except Exception:
        return None


def write():
    rows = ["# M3 Smoke 3-level (FRESH, no-leak) — Pure vs Scaffold vs Full-ML\n",
            "Kasus tersulit; budget sama (10 iter); seed 42; LTM/web/skills OFF; tiap run fresh.\n",
            "| Kasus | Pure (L1) | Scaffold (L2) | Full-ML (L3) |", "|---|---|---|---|"]
    agg = {"L1": 0, "L2": 0, "L3": 0}; done = {"L1": 0, "L2": 0, "L3": 0}
    for sid in HARD:
        c = []
        for l in ("L1", "L2", "L3"):
            r = load(sid, l)
            if r:
                done[l] += 1; agg[l] += int(bool(r["success"]))
                c.append(f"{'OK' if r['success'] else 'x'} it{r['iterations_used']}")
            else:
                c.append("-")
        rows.append(f"| {sid} | {c[0]} | {c[1]} | {c[2]} |")
    rows.append(f"\n**Skor:** Pure {agg['L1']}/{done['L1']} | Scaffold {agg['L2']}/{done['L2']} | "
                f"Full-ML {agg['L3']}/{done['L3']}")
    OUT.write_text("\n".join(rows), encoding="utf-8")


def main():
    for sid in HARD:
        for l in ("L1", "L2"):          # L3 (Full-ML) reuses existing mtx-*-P1C2, no re-run
            print("RUN", sid, l, flush=True)
            try:
                subprocess.run([PY, str(ROOT / "eval" / "one_run_level.py"), l, sid],
                               cwd=str(ROOT), timeout=1200)
            except Exception as e:
                print("ERR", sid, l, e, flush=True)
            write()
    write(); print("DONE -> report/SMOKE3.md")


if __name__ == "__main__":
    main()
