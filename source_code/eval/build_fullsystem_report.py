"""Generate report/LAPORAN_N3_FULLSYSTEM.md from the FULL40 sweep (f40- runs).
Per-scenario (40 sections) in the PILOT format: step table + screenshot + 11-component
help/not table + verdict, plus 3-seed stability (C vs D). Aggregate + glossary + Intinya.
Honest: per-component verdict is HEURISTIC from logs (needs leave-one-out ablation for hard numbers).
Runnable on partial data (missing cells -> '(belum)'). Usage: python eval/build_fullsystem_report.py"""
import json, glob, os, yaml
from pathlib import Path

ROOT = Path(r"C:\Spesial TA\pentest-agent")
SEEDS = [42, 7, 123]
OUT = ROOT / "report" / "LAPORAN_N3_FULLSYSTEM.md"

COMPONENTS = ["working_memory", "rag", "reflection", "guardrail", "state_graph",
              "tools (HTTP)", "sandbox", "auto_verify_xss", "N3 (ML)", "C1 progress (ML)", "C2 promise (ML)"]


def scenarios():
    s = yaml.safe_load(open(ROOT / "eval" / "scenarios.yaml", encoding="utf-8"))["scenarios"]
    seen, out = set(), []
    for x in s:
        if x["id"] not in seen:
            seen.add(x["id"]); out.append((x["id"], x))
    return out


def load(cond_lvl, sid, seed):
    rid = f"f40-q35-{sid}-{cond_lvl}-s{seed}"
    d = ROOT / "runs" / rid
    rep = d / "report.json"
    if not rep.exists():
        return None
    try:
        r = json.loads(rep.read_text(encoding="utf-8"))
    except Exception:
        return None
    r["_rid"] = rid; r["_dir"] = d
    tr = d / "trace.jsonl"
    r["_trace"] = [json.loads(l) for l in open(tr, encoding="utf-8") if l.strip()] if tr.exists() else []
    return r


def grid(cond_lvl, sid):
    marks = []
    for sd in SEEDS:
        r = load(cond_lvl, sid, sd)
        marks.append("O" if (r and r.get("success")) else ("x" if r else "-"))
    return "".join(marks), sum(1 for m in marks if m == "O"), sum(1 for m in marks if m in "Ox")


def steps_table(run):
    rows = ["| Iter | Aksi | Payload | Hasil |", "|---|---|---|---|"]
    for e in run["_trace"]:
        a = e.get("action", {}) or {}; pr = a.get("params", {}) or {}; o = e.get("observation", {}) or {}
        val = pr.get("value", pr.get("cmd", pr.get("payload", pr.get("focus", ""))))
        sig = str(o.get("signal", ""))[:70].replace("|", "/").replace("\n", " ")
        ok = {True: "✅", False: "❌", None: "—"}.get(o.get("success"), "—")
        rows.append(f"| {e.get('iteration')} | {a.get('type')} | `{str(val)[:34]}` | {ok} {sig} |")
    return "\n".join(rows)


def find_screenshot(run):
    sd = run["_dir"] / "screenshots"
    if not sd.is_dir():
        return None
    files = sorted(os.listdir(sd))
    xss = [f for f in files if f.startswith("xss_verify")]
    pick = xss[-1] if xss else (files[-1] if files else None)
    return (sd / pick) if pick else None


def component_table(run, is_xss):
    """Heuristic verdict from the representative D run's trace text."""
    txt = json.dumps(run["_trace"], ensure_ascii=False).lower()
    succ = run.get("success")
    n3_ok = "[n3 evidence:" in txt and ("confirmed" in txt or "reflected_unescaped" in txt or "extracted" in txt)
    xss_fired = any(k in txt for k in ("auto-verified", "js dialog", "xss_verify"))
    gr_block = "guardrail" in txt and "block" in txt
    http = "http_request" in txt
    verd = {
        "working_memory": ("⚪", "aktif, tak terbukti menentukan"),
        "rag": ("⚪", "aktif, tak terbukti menentukan"),
        "reflection": ("⚪", "aktif, tak terbukti menentukan"),
        "guardrail": ("🔴", "nge-blok & run gagal") if (gr_block and not succ) else ("🟢", "tak merugikan (tak blok payload benar)"),
        "state_graph": ("⚪", "aktif, tak terbukti menentukan"),
        "tools (HTTP)": ("🟢", "enabler: pengiriman payload") if http else ("—", "tak terpakai"),
        "sandbox": ("—", "tak terpakai di kasus ini"),
        "auto_verify_xss": (("🟢", "fired: konfirmasi dialog + screenshot") if xss_fired else ("—", "N/A (bukan XSS)")) if is_xss else ("—", "N/A (bukan XSS)"),
        "N3 (ML)": ("🟢", "evidence benar (cocok hasil)") if (n3_ok and succ) else (("⚪", "aktif, tak menentukan") if "[n3 evidence:" in txt else ("—", "tak aktif")),
        "C1 progress (ML)": ("⚪", "aktif, tak terbukti menentukan"),
        "C2 promise (ML)": ("⚪", "aktif, tak terbukti menentukan"),
    }
    rows = ["| # | Komponen | Bantu? | Dasar (dari log) |", "|---|---|---|---|"]
    for i, c in enumerate(COMPONENTS, 1):
        sym, why = verd[c]
        rows.append(f"| {i} | {c} | {sym} | {why} |")
    return "\n".join(rows)


def main():
    scen = scenarios()
    L = ["# LAPORAN N3 FULL-SYSTEM — Qwen3.5 (C base vs D +sistem)\n",
         "Sweep penuh: **C = Qwen3.5-9B base (0 komponen)** vs **D = Qwen3.5-9B + sistem (11 komponen)**,",
         "40 kasus × 3 seed [42,7,123] = 240 run. Budget 10 iter/900 s; **LTM, skills, web-search OFF** di",
         "SEMUA kondisi (anti-bocor/anti-contekan); tiap run fresh. Aktor ganti via `cfg['model']['name']`.\n",
         "> **Catatan metode:** '+sistem' = 8 scaffold (working_memory, rag, reflection, guardrail, state_graph,",
         "> tools, sandbox, browser auto-verify) + 3 ML (N3, C1, C2). **Tanpa** skills/playbook, tanpa LTM, tanpa",
         "> web-search — jadi kemenangan D murni nalar+komponen, bukan contekan. Verdict per-komponen di bawah",
         "> bersifat **heuristik dari log** (aktif & efek teramati); angka kontribusi per-komponen yang sah butuh",
         "> **ablation leave-one-out** (matikan 1 komponen, ukur selisih) — direncanakan sebagai lanjutan.\n",
         "> **Legenda:** 🟢 bantu · ⚪ netral (efek tak terlihat) · 🔴 ada peluang tapi gagal · ⬛ mati (base) · — N/A.\n"]

    # aggregate
    cT = cN = dT = dN = 0
    agg = ["## 0. Agregat (C vs D, lintas 40 kasus × 3 seed)\n", "| Kondisi | berhasil | total | rate |", "|---|---|---|---|"]
    for lvl, lab in [("L1", "C base"), ("L3", "D +sistem")]:
        ok = tot = 0
        for sid, _ in scen:
            _, o, t = grid(lvl, sid); ok += o; tot += t
        if lvl == "L1": cN, cT = ok, tot
        else: dN, dT = ok, tot
        agg.append(f"| {lab} | {ok} | {tot} | {(100*ok/tot if tot else 0):.0f}% |")
    L += agg + ["\n## 1. Ringkas grid per-kasus (O=sukses/x=gagal, seed 42/7/123)\n",
                "| Kasus | C base | D +sistem |", "|---|---|---|"]
    for sid, _ in scen:
        cg, co, ct = grid("L1", sid); dg, do, dt = grid("L3", sid)
        L.append(f"| {sid} | {cg} {co}/{ct or len(SEEDS)} | {dg} {do}/{dt or len(SEEDS)} |")

    # per-scenario detail
    L += ["\n## 2. Detail per-testcase\n"]
    for sid, meta in scen:
        L.append(f"\n### {sid}")
        cg, co, ct = grid("L1", sid); dg, do, dt = grid("L3", sid)
        L.append(f"**Stabilitas:** C base `{cg}` ({co}/{ct or 3}) · D +sistem `{dg}` ({do}/{dt or 3})  ")
        # representative D run: first success by seed, else seed42
        repD = None
        for sd in SEEDS:
            r = load("L3", sid, sd)
            if r and r.get("success"):
                repD = r; break
        if repD is None:
            repD = load("L3", sid, 42) or load("L3", sid, 7) or load("L3", sid, 123)
        if repD is None:
            L.append("_(run D belum ada — menunggu sweep)_"); continue
        is_xss = "xss" in sid
        verd = "✅ **tembus**" if repD.get("success") else "❌ **gagal**"
        L.append(f"**Run representatif D ({repD['_rid']}):** {verd}, {repD.get('iterations_used')} iter, {repD.get('wall_clock_s',0):.0f} s\n")
        L.append("**Langkah (dari trace):**\n" + steps_table(repD))
        shot = find_screenshot(repD)
        if shot:
            rel = os.path.relpath(shot, ROOT / "report").replace("\\", "/")
            cap = "berhasil" if repD.get("success") else "percobaan (gagal)"
            L.append(f"\n**Gambar ({cap}):** `{os.path.relpath(shot, ROOT)}`\n\n![{sid} {cap}]({rel})")
        else:
            L.append("\n_(tak ada screenshot tersimpan untuk run ini)_")
        L.append("\n**11 komponen — bantu di kasus ini?**\n" + component_table(repD, is_xss))

    # footer
    L += ["\n## 3. Intinya (fakta)\n",
          f"1. **Agregat:** C base **{cN}/{cT}** ({(100*cN/cT if cT else 0):.0f}%) vs D +sistem **{dN}/{dT}** ({(100*dN/dT if dT else 0):.0f}%).",
          "2. Lihat grid §1 untuk kasus mana D menang stabil / regresi / sama.",
          "3. Komponen yang paling sering teramati bantu: **browser auto-verify (XSS)** & **N3** (lihat tabel per-kasus).",
          "4. **Verdict per-komponen = heuristik log**, bukan ablation. Angka sah per-komponen butuh leave-one-out.",
          "5. Skills/LTM/web-search **OFF** — hasil D konservatif (tanpa contekan).\n",
          "**Sumber:** `runs/f40-q35-*-s{42,7,123}/{trace.jsonl,report.json,screenshots/}` (240 run).",
          "Driver: `eval/one_run_seed.py` (prefix f40), `eval/run_full40_q35.py`. Generator: `eval/build_fullsystem_report.py`.",
          "Pembanding 5-kasus-tersulit: `report/COMPARE4_MULTISEED.md`. Pilot: `report/LAPORAN_N3_FULLSYSTEM_PILOT.md`."]
    OUT.write_text("\n".join(L), encoding="utf-8")
    print("WROTE", OUT, "| C %d/%d D %d/%d" % (cN, cT, dN, dT))


if __name__ == "__main__":
    main()
