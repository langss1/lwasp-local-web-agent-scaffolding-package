import json, glob, re, statistics as st
from collections import defaultdict
rows=defaultdict(list)  # (sid,cfg) -> list of reports
for rep in glob.glob(r"runs\abl-*\report.json"):
    m=re.search(r"abl-(.+)-(B\d)-\d\d", rep.replace("/","\\"))
    if not m: continue
    sid,cfg=m.group(1),m.group(2)
    try: r=json.load(open(rep))
    except: continue
    rows[(sid,cfg)].append(r)
scen=sorted({k[0] for k in rows}); cfgs=["B0","B1","B2","B3","B4","B5"]
out={"configurations":{}}
print("%-20s %-4s | n  succ_rate  mean_iters  mean_blocks  mean_backtracks"%("scenario","cfg"))
print("-"*78)
for s in scen:
    for c in cfgs:
        rs=rows.get((s,c),[])
        if not rs: continue
        n=len(rs); sr=sum(1 for r in rs if r.get("success"))/n
        its=[r["iterations_to_success"] for r in rs if r.get("success") and r.get("iterations_to_success")]
        mi=(st.mean(its) if its else None)
        mb=st.mean([r.get("guardrail_blocks",0) for r in rs]); mbt=st.mean([r.get("backtracks",0) for r in rs])
        out["configurations"].setdefault(s,{})[c]={"n":n,"success_rate":round(sr,2),"mean_iters":round(mi,1) if mi else None,"mean_blocks":round(mb,2),"mean_backtracks":round(mbt,2)}
        print("%-20s %-4s | %-2d %-9.2f %-11s %-12.2f %-.2f"%(s,c,n,sr,(round(mi,1) if mi else "-"),mb,mbt))
json.dump(out, open(r"runs\ablation_full_summary.json","w"), indent=2)
print("\nTotal runs:", sum(len(v) for v in rows.values()), "/ 180")
