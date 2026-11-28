"""q25 2x2 RAG x Guardrail interaction from authoritative per-cell `success`
(same oracle outcome used across K1/confirmatory). Self-contained: exact binomial
McNemar (math.comb), scenario-clustered bootstrap CI. Also a sensitivity run with
XSS families dropped (addresses R1-A crediting debate). No fabrication: reads the
CSV rows written by report.json. Usage: python -I q25_interaction.py <csv>"""
import csv, sys, random, json, statistics
from math import comb
from collections import defaultdict

CSV = sys.argv[1] if len(sys.argv) > 1 else "k2b_q25.csv"
random.seed(12345)
# cell_map: config -> (RAG, Guardrail)
CFG = {"FULL": ("RG", 1, 1), "L-RAG": ("RG", 0, 1), "I-RG10": ("RG", 1, 0), "I-RG00": ("RG", 0, 0)}
XSS = ("xss_dom", "xss_reflected", "xss_stored")

def load(path):
    rows = []
    for r in csv.DictReader(open(path, encoding="utf-8")):
        rows.append(r)
    return rows

def truthy(v):
    return str(v).strip().lower() in ("true", "1", "yes")

def osr(cells):
    # cells: list of bool
    n = len(cells); s = sum(cells)
    return (s / n if n else float("nan")), s, n

def mcnemar_exact(pairs_hi, pairs_lo, keys):
    b = c = 0
    for k in keys:
        hi, lo = pairs_hi[k], pairs_lo[k]
        if hi and not lo: b += 1
        elif (not hi) and lo: c += 1
    n = b + c
    if n == 0: return b, c, None
    k = min(b, c)
    tail = sum(comb(n, i) for i in range(0, k + 1)) / (2 ** n)
    return b, c, min(1.0, 2 * tail)

def analyze(rows, label, drop_xss=False):
    # per config: (scenario,seed)->success ; also per cell pooled
    by = {cfg: {} for cfg in CFG}
    scen_set = set()
    for r in rows:
        cfg = r["config"]
        if cfg not in CFG: continue
        scen = r["scenario"]
        if drop_xss and any(scen.startswith(x) for x in XSS):
            continue
        key = (scen, r["seed"])
        by[cfg][key] = truthy(r["success"])
        scen_set.add(scen)
    # pooled OSR per cell
    O = {}
    for cfg in CFG:
        vals = list(by[cfg].values())
        O[cfg] = osr(vals)
    o11 = O["FULL"][0]; o01 = O["L-RAG"][0]; o10 = O["I-RG10"][0]; o00 = O["I-RG00"][0]
    inter = (o11 - o01) - (o10 - o00)
    rag_main = ((o11 + o10) - (o01 + o00)) / 2.0
    grd_main = ((o11 + o01) - (o10 + o00)) / 2.0

    # scenario-clustered bootstrap CI for interaction
    scen_list = sorted(scen_set)
    seeds = sorted({k[1] for k in by["FULL"]})
    def inter_from(sample_scens):
        acc = {cfg: [] for cfg in CFG}
        for sc in sample_scens:
            for cfg in CFG:
                for sd in seeds:
                    v = by[cfg].get((sc, sd))
                    if v is not None: acc[cfg].append(v)
        f = lambda c: (sum(acc[c]) / len(acc[c])) if acc[c] else float("nan")
        return (f("FULL") - f("L-RAG")) - (f("I-RG10") - f("I-RG00"))
    boots = []
    for _ in range(5000):
        samp = [random.choice(scen_list) for _ in scen_list]
        boots.append(inter_from(samp))
    boots.sort()
    ci = (boots[int(0.025 * len(boots))], boots[int(0.975 * len(boots))])

    # McNemar: RAG effect | guardrail on  (FULL vs L-RAG)
    kFL = sorted(set(by["FULL"]) & set(by["L-RAG"]))
    bFL, cFL, pFL = mcnemar_exact(by["FULL"], by["L-RAG"], kFL)
    # RAG effect | guardrail off (I-RG10 vs I-RG00)
    k10_00 = sorted(set(by["I-RG10"]) & set(by["I-RG00"]))
    b2, c2, p2 = mcnemar_exact(by["I-RG10"], by["I-RG00"], k10_00)
    # Guardrail effect | RAG on (FULL vs I-RG10)
    kF10 = sorted(set(by["FULL"]) & set(by["I-RG10"]))
    bG, cG, pG = mcnemar_exact(by["FULL"], by["I-RG10"], kF10)

    out = {
        "label": label, "drop_xss": drop_xss,
        "n_scenarios": len(scen_list), "n_seeds": len(seeds),
        "OSR": {k: {"osr": round(O[k][0], 4), "succ": O[k][1], "n": O[k][2]} for k in CFG},
        "interaction_pp": round(100 * inter, 2),
        "interaction_CI95_pp": [round(100 * ci[0], 2), round(100 * ci[1], 2)],
        "rag_main_pp": round(100 * rag_main, 2),
        "guardrail_main_pp": round(100 * grd_main, 2),
        "mcnemar_rag_given_grdON_FULLvsLRAG": {"b": bFL, "c": cFL, "p": (round(pFL,4) if pFL is not None else None), "n": len(kFL)},
        "mcnemar_rag_given_grdOFF_IRG10vsIRG00": {"b": b2, "c": c2, "p": (round(p2,4) if p2 is not None else None), "n": len(k10_00)},
        "mcnemar_guardrail_given_ragON_FULLvsIRG10": {"b": bG, "c": cG, "p": (round(pG,4) if pG is not None else None), "n": len(kF10)},
    }
    return out

def main():
    rows = load(CSV)
    print("rows:", len(rows))
    res_all = analyze(rows, "ALL_CELLS", drop_xss=False)
    res_noxss = analyze(rows, "XSS_EXCLUDED", drop_xss=True)
    both = {"all": res_all, "sensitivity_no_xss": res_noxss}
    print(json.dumps(both, indent=2))
    json.dump(both, open("q25_interaction_result.json", "w", encoding="utf-8"), indent=2)
    # human table
    def tbl(r):
        o = r["OSR"]
        print(f"\n[{r['label']}] scen={r['n_scenarios']} seeds={r['n_seeds']}")
        print(f"            guardrail_ON   guardrail_OFF")
        print(f"  RAG_ON    FULL {100*o['FULL']['osr']:.1f}% ({o['FULL']['succ']}/{o['FULL']['n']})   I-RG10 {100*o['I-RG10']['osr']:.1f}% ({o['I-RG10']['succ']}/{o['I-RG10']['n']})")
        print(f"  RAG_OFF   L-RAG {100*o['L-RAG']['osr']:.1f}% ({o['L-RAG']['succ']}/{o['L-RAG']['n']})  I-RG00 {100*o['I-RG00']['osr']:.1f}% ({o['I-RG00']['succ']}/{o['I-RG00']['n']})")
        print(f"  interaction = {r['interaction_pp']}pp  CI95 {r['interaction_CI95_pp']}")
        print(f"  RAG main = {r['rag_main_pp']}pp | guardrail main = {r['guardrail_main_pp']}pp")
        print(f"  McNemar RAG|grdON  (FULL vs L-RAG): b={r['mcnemar_rag_given_grdON_FULLvsLRAG']['b']} c={r['mcnemar_rag_given_grdON_FULLvsLRAG']['c']} p={r['mcnemar_rag_given_grdON_FULLvsLRAG']['p']}")
        print(f"  McNemar RAG|grdOFF (I-RG10 vs I-RG00): b={r['mcnemar_rag_given_grdOFF_IRG10vsIRG00']['b']} c={r['mcnemar_rag_given_grdOFF_IRG10vsIRG00']['c']} p={r['mcnemar_rag_given_grdOFF_IRG10vsIRG00']['p']}")
        print(f"  McNemar guardrail|ragON (FULL vs I-RG10): b={r['mcnemar_guardrail_given_ragON_FULLvsIRG10']['b']} c={r['mcnemar_guardrail_given_ragON_FULLvsIRG10']['c']} p={r['mcnemar_guardrail_given_ragON_FULLvsIRG10']['p']}")
    tbl(res_all); tbl(res_noxss)

if __name__ == "__main__":
    main()
