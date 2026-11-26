"""Analyse the bWAPP external-validity sweep (plan14.md P6).

Reads results/bwapp_sweep.csv and reports whether the scaffolding effect
(Full > Base) seen on DVWA replicates on bWAPP:
  - OSR per condition (overall, per class, per level)
  - Base-vs-Full paired by (scenario, seed): McNemar exact (binomial) on
    discordant pairs, plus an aggregate 2x2 odds ratio
  - side-by-side with the DVWA headline (OR 2.94, 57.5% -> 80.3% on 9B)

Writes report/EXTERNAL_VALIDITY_BWAPP.md. Pure stdlib (no scipy needed):
McNemar exact p = 2 * sum_{k<=b} C(n,k) 0.5^n over the discordant pairs.

Usage:  python eval/analyze_bwapp.py [results/bwapp_sweep.csv]
"""
import sys, csv
from math import comb
from pathlib import Path
from collections import defaultdict

ROOT = Path(__file__).resolve().parent.parent
DVWA_REF = {"base_osr": 0.575, "full_osr": 0.803, "or": 2.94}  # 9B headline


def mcnemar_exact_p(b: int, c: int) -> float:
    """Two-sided exact McNemar on discordant counts b (Base-only win) and
    c (Full-only win). p = 2 * P(X <= min(b,c)) with X~Bin(b+c, 0.5), capped at 1."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(comb(n, i) for i in range(0, k + 1)) * (0.5 ** n)
    return min(1.0, 2 * tail)


def odds_ratio(fp, ff, bp, bf):
    """OR of success for Full vs Base from 2x2 (pass/fail each). Haldane +0.5."""
    fp, ff, bp, bf = fp + 0.5, ff + 0.5, bp + 0.5, bf + 0.5
    return (fp / ff) / (bp / bf)


def main():
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "results" / "bwapp_sweep.csv"
    rows = list(csv.DictReader(open(src, encoding="utf-8")))
    if not rows:
        print(f"[!] no rows in {src}"); return

    def cls_of(sid):  # bw_sqli_low -> sqli ; bw_blind_sqli_high -> sqli_blind ...
        base = sid[3:] if sid.startswith("bw_") else sid
        for lvl in ("_low", "_medium", "_high"):
            if base.endswith(lvl):
                base = base[: -len(lvl)]
        return base

    osr = defaultdict(lambda: [0, 0])        # cond -> [pass, total]
    by_class = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    by_level = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    cell = {}                                 # (cond, scenario, seed) -> success
    for r in rows:
        cond = r["config"]; sid = r["scenario"]; lvl = r.get("level", "")
        ok = int(r["success"]) if str(r["success"]).strip() in ("0", "1") else 0
        osr[cond][0] += ok; osr[cond][1] += 1
        by_class[cls_of(sid)][cond][0] += ok; by_class[cls_of(sid)][cond][1] += 1
        by_level[lvl][cond][0] += ok; by_level[lvl][cond][1] += 1
        cell[(cond, sid, r["seed"])] = ok

    have_base = osr["Base"][1] > 0
    have_full = osr["Full"][1] > 0

    L = []
    def pct(p, t): return f"{p}/{t} ({100*p/t:.1f}%)" if t else "-"
    L.append("# Validitas Eksternal - Replikasi di bWAPP (plan14.md)\n")
    L.append(f"> Sumber: `{src.name}`, {len(rows)} run. Oracle-verified, non-boost, 9B, "
             "lingkungan pod Kali identik dengan sweep DVWA (hanya target app yang berubah).\n")

    L.append("## 1. OSR per kondisi (keseluruhan)\n")
    L.append("| Kondisi | OSR |")
    L.append("|---|---|")
    for cond in ("Base", "Full"):
        if osr[cond][1]:
            L.append(f"| {cond} | {pct(*osr[cond])} |")
    L.append("")

    L.append("## 2. OSR per kelas kerentanan\n")
    conds = [c for c in ("Base", "Full") if osr[c][1]]
    L.append("| Kelas | " + " | ".join(conds) + " |")
    L.append("|---|" + "---|" * len(conds))
    for cl in sorted(by_class):
        L.append(f"| {cl} | " + " | ".join(pct(*by_class[cl][c]) for c in conds) + " |")
    L.append("")

    L.append("## 3. OSR per level\n")
    L.append("| Level | " + " | ".join(conds) + " |")
    L.append("|---|" + "---|" * len(conds))
    for lvl in ("low", "medium", "high"):
        if lvl in by_level:
            L.append(f"| {lvl} | " + " | ".join(pct(*by_level[lvl][c]) for c in conds) + " |")
    L.append("")

    if have_base and have_full:
        # paired McNemar on (scenario, seed)
        b = c = both = neither = 0
        keys = {(s, sd) for (cond, s, sd) in cell}
        for (s, sd) in keys:
            bv = cell.get(("Base", s, sd)); fv = cell.get(("Full", s, sd))
            if bv is None or fv is None:
                continue
            if fv and not bv: c += 1
            elif bv and not fv: b += 1
            elif bv and fv: both += 1
            else: neither += 1
        p = mcnemar_exact_p(b, c)
        fp, ff = osr["Full"]; bp, bf = osr["Base"]
        orr = odds_ratio(fp, ff - fp, bp, bf - bp)
        L.append("## 4. Efek scaffolding (Base vs Full)\n")
        L.append(f"- Pasangan diskordan: Full-menang-saja = **{c}**, Base-menang-saja = **{b}** "
                 f"(keduanya sukses={both}, keduanya gagal={neither}).")
        L.append(f"- **McNemar exact p = {p:.4f}** ({'signifikan' if p < 0.05 else 'tidak signifikan'} pada alfa=0,05).")
        L.append(f"- Odds Ratio agregat (Full vs Base) = **{orr:.2f}x**.")
        L.append("")
        L.append("## 5. Perbandingan arah efek dengan DVWA (headline 9B)\n")
        L.append("| Metrik | DVWA | bWAPP |")
        L.append("|---|---|---|")
        L.append(f"| OSR Base | {DVWA_REF['base_osr']*100:.1f}% | {100*bp/bf:.1f}% |")
        L.append(f"| OSR Full | {DVWA_REF['full_osr']*100:.1f}% | {100*fp/ff:.1f}% |")
        L.append(f"| OR (Full/Base) | {DVWA_REF['or']:.2f}x | {orr:.2f}x |")
        L.append("")
        same_dir = orr > 1 and (fp/ff) > (bp/bf)
        L.append(f"**Observasi:** arah efek {'SAMA' if same_dir else 'BERBEDA'} dengan DVWA "
                 f"(Full {'>' if (fp/ff)>(bp/bf) else '<='} Base). "
                 "Interpretasi (tafsir, bukan observasi): " +
                 ("efek scaffolding tereplikasi di aplikasi independen."
                  if same_dir else
                  "efek scaffolding TIDAK tereplikasi di sini — kemungkinan spesifik-konteks; "
                  "dilaporkan jujur sebagai temuan, bukan disembunyikan."))
    else:
        L.append("## 4. Efek scaffolding\n")
        L.append("_Hanya satu kondisi dijalankan (tahap-1). Ini mengukur kelayakan + "
                 "success-rate, BELUM efek scaffolding; perlu Base+Full (tahap-2)._")
    L.append("")

    out = ROOT / "report" / "EXTERNAL_VALIDITY_BWAPP.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(L), encoding="utf-8")
    print("\n".join(L))
    print(f"\n[written] {out}")


if __name__ == "__main__":
    main()
