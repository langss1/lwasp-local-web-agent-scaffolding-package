"""Driver: run C0 vs C1 over a small DEV scenario set, one subprocess per run
(memory released each time; resumable). Writes report/C0C1_COMPARE.md incrementally.
plan9.md M3 (N2 isolation, preliminary DEV validation). Usage: python eval/run_c0_c1.py"""
import sys, subprocess, json
from pathlib import Path

ROOT = Path(r"C:\Spesial TA\pentest-agent")
PY = sys.executable
SCENARIOS = ["blind_sqli_low", "blind_sqli_medium", "blind_sqli_high",
             "sqli_low", "sqli_medium", "sqli_high",
             "xss_reflected_low", "xss_reflected_medium", "xss_reflected_high"]
CONDS = ["C0", "C1"]
OUT = ROOT / "report" / "C0C1_COMPARE.md"


def load(rid):
    p = ROOT / "runs" / rid / "report.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def write_table():
    rows = ["# C0 vs C1 — validasi DEV progress-protection (N2)\n",
            "Scaffolding identik (state_graph+guardrail+rag+reflection+tools+sandbox ON; "
            "skills/web/ltm OFF); seed 42; satu-satunya beda = progress_protection.\n",
            "| Scenario | Cond | success | it_used | backtracks | holds | redirects | guardrail_blocks | wall_s |",
            "|---|---|---|---|---|---|---|---|---|"]
    for sid in SCENARIOS:
        for c in CONDS:
            r = load(f"c0c1-{sid}-{c}")
            if not r:
                rows.append(f"| {sid} | {c} | - | - | - | - | - | - | - |"); continue
            rows.append(f"| {sid} | {c} | {r['success']} | {r['iterations_used']} | {r['backtracks']} | "
                        f"{r.get('progress_holds',0)} | {r.get('progress_redirects',0)} | "
                        f"{r['guardrail_blocks']} | {round(r['wall_clock_s'])} |")
    # quick aggregate
    def agg(c):
        rs = [load(f"c0c1-{s}-{c}") for s in SCENARIOS]; rs = [x for x in rs if x]
        if not rs:
            return "-"
        succ = sum(1 for x in rs if x["success"]); it = sum(x["iterations_used"] for x in rs) / len(rs)
        return f"success {succ}/{len(rs)}, avg it {it:.1f}"
    rows += [f"\n**Agregat:** C0 = {agg('C0')} | C1 = {agg('C1')}\n",
             "Catatan: N=1, DEV only, preliminary; uji definitif = matriks 2x3 + holdout (M5)."]
    OUT.write_text("\n".join(rows), encoding="utf-8")


def main():
    for sid in SCENARIOS:
        for c in CONDS:
            rid = f"c0c1-{sid}-{c}"
            if (ROOT / "runs" / rid / "report.json").exists():
                print("skip", rid); continue
            print("RUN", rid, flush=True)
            try:
                subprocess.run([PY, str(ROOT / "eval" / "one_run_c.py"), c, sid],
                               cwd=str(ROOT), timeout=1200)
            except subprocess.TimeoutExpired:
                print("TIMEOUT", rid, flush=True)
            except Exception as e:
                print("ERR", rid, e, flush=True)
            write_table()   # incremental: partial progress always saved
    write_table()
    print("DONE -> report/C0C1_COMPARE.md")


if __name__ == "__main__":
    main()
