"""Multi-seed robustness sweep (plan11). 4 conditions x 5 scenarios x N seeds.
Pre-declared fixed seed list (reproducible) + varied (captures variance).
Condition-major ordering so each Ollama model loads once (q25 then q35).
Builds report/COMPARE4_MULTISEED.md incrementally; resumes by skipping done cells.
Usage: python eval/run_multiseed.py"""
import sys, subprocess, json
from pathlib import Path

ROOT = Path(r"C:\Spesial TA\pentest-agent"); PY = sys.executable
SEEDS = [42, 7, 123]                       # fixed list, pre-declared
HARD = ["sqli_medium", "sqli_high", "blind_sqli_medium", "blind_sqli_high", "xss_reflected_high"]
COND = {                                   # condition-major: q25 first (A,B), then q35 (C,D)
    "A": ("q25", "qwen2.5:latest", "L1", "Qwen2.5 base"),
    "B": ("q25", "qwen2.5:latest", "L3", "Qwen2.5 +sistem"),
    "C": ("q35", "qwen3.5:latest", "L1", "Qwen3.5 base"),
    "D": ("q35", "qwen3.5:latest", "L3", "Qwen3.5 +sistem"),
}
OUT = ROOT / "report" / "COMPARE4_MULTISEED.md"


def load(c, sid, seed):
    mtag, _, lvl, _ = COND[c]
    p = ROOT / "runs" / f"ms-{mtag}-{sid}-{lvl}-s{seed}" / "report.json"
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None
    except Exception:
        return None


def write():
    L = [f"# COMPARE4 MULTI-SEED — Qwen2.5 vs Qwen3.5 x (base vs sistem)\n",
         f"Seeds {SEEDS} (fixed, pre-declared). 5 kasus; budget 10 iter/900s; LTM/web/skills OFF; fresh.",
         "Stabil = sama di semua seed; flip = goyang (noise, tak bisa diklaim kuat).\n"]
    # per-scenario stability grid
    L += ["## Stabilitas per-skenario (✓/✗ tiap seed -> X/N)\n"]
    header = "| Kasus | " + " | ".join(f"{c}" for c in "ABCD") + " |"
    L += [header, "|---|" + "---|" * 4]
    cond_tot = {c: 0 for c in "ABCD"}; cond_cells = {c: 0 for c in "ABCD"}
    for sid in HARD:
        cells = []
        for c in "ABCD":
            marks = []
            for sd in SEEDS:
                r = load(c, sid, sd)
                marks.append(("O" if r["success"] else "x") if r else "-")
            ok = sum(1 for m in marks if m == "O")
            cond_tot[c] += ok; cond_cells[c] += sum(1 for m in marks if m in ("O", "x"))
            cells.append("".join(marks) + f" {ok}/{len([m for m in marks if m!='-']) or len(SEEDS)}")
        L.append(f"| {sid} | " + " | ".join(cells) + " |")
    # aggregate success-rate across all seeds*scenarios
    L += ["\n## Agregat (total berhasil / total run, lintas seed)\n",
          "| Kondisi | berhasil | success-rate |", "|---|---|---|"]
    for c in "ABCD":
        n = cond_cells[c] or 1
        L.append(f"| {COND[c][3]} | {cond_tot[c]}/{cond_cells[c]} | {100*cond_tot[c]/n:.0f}% |")
    # mean score per seed (comparable to single-run 'X/5')
    L += ["\n## Skor /5 per seed\n", "| Seed | " + " | ".join(COND[c][3] for c in "ABCD") + " |",
          "|---|" + "---|" * 4]
    for sd in SEEDS:
        row = []
        for c in "ABCD":
            sc = sum(1 for sid in HARD if (load(c, sid, sd) or {}).get("success"))
            done = sum(1 for sid in HARD if load(c, sid, sd))
            row.append(f"{sc}/{done}" if done else "-")
        L.append(f"| {sd} | " + " | ".join(row) + " |")
    OUT.write_text("\n".join(L), encoding="utf-8")


def main():
    for c in "ABCD":                       # condition-major -> model loads once per family
        mtag, mname, lvl, lab = COND[c]
        for sd in SEEDS:
            for sid in HARD:
                if (ROOT / "runs" / f"ms-{mtag}-{sid}-{lvl}-s{sd}" / "report.json").exists():
                    print("SKIP", c, sid, "s%d" % sd, flush=True); continue
                print("RUN", c, lab, sid, "seed", sd, flush=True)
                try:
                    subprocess.run([PY, str(ROOT / "eval" / "one_run_seed.py"),
                                    mtag, mname, lvl, sid, str(sd)], cwd=str(ROOT), timeout=1200)
                except Exception as e:
                    print("ERR", c, sid, sd, e, flush=True)
                write()
    write(); print("DONE ->", OUT)


if __name__ == "__main__":
    main()
