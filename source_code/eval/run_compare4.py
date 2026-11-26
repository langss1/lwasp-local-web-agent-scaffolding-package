"""4-condition pilot (plan11): A=q2.5 base, B=q2.5 full, C=q3.5 base, D=q3.5 full.
5 hardest DEV scenarios, equal budget/seed, FRESH all. Builds report/COMPARE4_QWEN.md
incrementally so partial results survive OOM/interrupt.
Usage: python eval/run_compare4.py            (all 20 runs)
       python eval/run_compare4.py <A|B|C|D>   (only that condition's 5 runs)"""
import sys, subprocess, json
from pathlib import Path

ROOT = Path(r"C:\Spesial TA\pentest-agent"); PY = sys.executable
HARD = ["sqli_medium", "sqli_high", "blind_sqli_medium", "blind_sqli_high", "xss_reflected_high"]
# cond -> (model_tag, ollama_model, level, label)
COND = {
    "A": ("q25", "qwen2.5:latest", "L1", "Qwen2.5 base"),
    "B": ("q25", "qwen2.5:latest", "L3", "Qwen2.5 +sistem"),
    "C": ("q35", "qwen3.5:latest", "L1", "Qwen3.5 base"),
    "D": ("q35", "qwen3.5:latest", "L3", "Qwen3.5 +sistem"),
}
OUT = ROOT / "report" / "COMPARE4_QWEN.md"


def _from_trace(rdir):
    """Fallback if report.json missing (process killed before clean write).
    objective_success = any interpreter observation success -- same measure the
    orchestrator itself records (success = success or objective_success)."""
    t = rdir / "trace.jsonl"
    if not t.exists():
        return None
    rows = []
    for ln in t.read_text(encoding="utf-8").strip().split("\n"):
        try:
            rows.append(json.loads(ln))
        except Exception:
            pass
    if not rows:
        return None
    succ = any(bool(r.get("observation", {}).get("success")) for r in rows)
    ts = [r.get("timestamp") for r in rows if r.get("timestamp")]
    wall = (max(ts) - min(ts)) if len(ts) >= 2 else 0
    return {"success": succ, "agent_finished_success": False, "finish_reason": "killed_no_report",
            "iterations_used": len(rows), "wall_clock_s": wall, "peak_vram_mb": 0,
            "peak_ram_mb": 0, "tokens_used": 0, "_from_trace": True}


def load(cond, sid):
    mtag, _, lvl, _ = COND[cond]
    rdir = ROOT / "runs" / f"cmp-{mtag}-{sid}-{lvl}"
    p = rdir / "report.json"
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            pass
    return _from_trace(rdir)


def write():
    L = ["# COMPARE4 — Qwen2.5 vs Qwen3.5 x (base vs sistem kita)\n",
         "5 kasus tersulit DEV; budget sama (10 iter, 900s); seed 42; LTM/web/skills OFF; fresh.\n",
         "base = LLM telanjang (0 komponen). sistem = 13 komponen penuh.\n"]
    # resource table
    L += ["## Feasibility / resource (rata-rata per run)\n",
          "| Kondisi | Model | Berhasil | wall(s) avg | VRAM peak MB | RAM peak MB | token avg | OOM/timeout |",
          "|---|---|---|---|---|---|---|---|"]
    for c in "ABCD":
        mtag, _, lvl, lab = COND[c]
        rs = [load(c, s) for s in HARD]; rs = [r for r in rs if r]
        if not rs:
            L.append(f"| {c} | {lab} | - | - | - | - | - | - |"); continue
        n = len(rs); ok = sum(int(bool(r["success"])) for r in rs)
        wall = sum(r.get("wall_clock_s", 0) for r in rs) / n
        vram = max(r.get("peak_vram_mb", 0) for r in rs)
        ram = max(r.get("peak_ram_mb", 0) for r in rs)
        tok = sum(r.get("tokens_used", 0) or 0 for r in rs) / n
        to = sum(1 for r in rs if r.get("finish_reason") in ("timeout", "oom", "wall_clock", "killed_no_report"))
        L.append(f"| {c} | {lab} | {ok}/{n} | {wall:.0f} | {vram:.0f} | {ram:.0f} | {tok:.0f} | {to} |")
    # per-scenario verified success
    L += ["\n## Per-skenario (success terverifikasi)\n",
          "| Kasus | A 2.5 base | B 2.5 sistem | C 3.5 base | D 3.5 sistem |",
          "|---|---|---|---|---|"]
    for s in HARD:
        cells = []
        for c in "ABCD":
            r = load(c, s)
            cells.append(f"{'OK' if r['success'] else 'x'} it{r['iterations_used']}" if r else "-")
        L.append(f"| {s} | {cells[0]} | {cells[1]} | {cells[2]} | {cells[3]} |")
    # agent-claimed vs verified (honesty check)
    L += ["\n## Klaim agen vs terverifikasi (false success?)\n",
          "| Kasus | A | B | C | D |  (v=verified, c=agent-claim-only)", "|---|---|---|---|---|---|"]
    for s in HARD:
        cells = []
        for c in "ABCD":
            r = load(c, s)
            if not r: cells.append("-"); continue
            v, ac = bool(r["success"]), bool(r.get("agent_finished_success"))
            cells.append("v" if v else ("c-only" if ac else "x"))
        L.append(f"| {s} | {cells[0]} | {cells[1]} | {cells[2]} | {cells[3]} | |")
    OUT.write_text("\n".join(L), encoding="utf-8")


def main():
    conds = [sys.argv[1].upper()] if len(sys.argv) > 1 else list("ABCD")
    for c in conds:
        mtag, mname, lvl, lab = COND[c]
        for s in HARD:
            print("RUN", c, lab, s, flush=True)
            try:
                subprocess.run([PY, str(ROOT / "eval" / "one_run_cmp.py"), mtag, mname, lvl, s],
                               cwd=str(ROOT), timeout=1200)
            except Exception as e:
                print("ERR", c, s, e, flush=True)
            write()
    write(); print("DONE ->", OUT)


if __name__ == "__main__":
    main()
