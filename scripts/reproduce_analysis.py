"""Reproduce archival contrasts from paired CSVs; no live targets, ML training or APIs.
Usage: python scripts/reproduce_analysis.py [--check]
Dependencies: Python 3.10+ and NumPy. The original environment is documented separately.
"""
from pathlib import Path
from collections import defaultdict
import csv,json,sys
import numpy as np

BASE=Path(__file__).resolve().parents[1];A=BASE/'analysis';SEED=20261105;N=20000
def read(name):return list(csv.DictReader((A/name).open(encoding='utf-8-sig')))
def summary(rows):
    by=defaultdict(list)
    for r in rows:by[r['scenario']].append(100*(int(r['treatment'])-int(r['reference'])))
    x=np.array([np.mean(by[k]) for k in sorted(by)])
    z=np.random.default_rng(SEED).integers(len(x),size=(N,len(x)))
    return {'n_pairs':len(rows),'n_scenarios':len(x),'base_success':sum(int(r['reference']) for r in rows),
            'full_success':sum(int(r['treatment']) for r in rows),'difference_pp':float(x.mean()),
            'ci_pp':list(map(float,np.percentile(x[z].mean(axis=1),[2.5,97.5])))}
main=read('primary_paired_outcomes.csv');external=read('external_paired_outcomes.csv')
out={'primary':{m:summary([r for r in main if r['model']==m]) for m in ['q25','q35']},
     'pooled':summary(main),'external':{t:summary([r for r in external if r['comparison']==t]) for t in ['juiceshop','bwapp']}}
old=json.loads((A/'analysis_summary.json').read_text(encoding='utf-8'))
for m in ['q25','q35']:
    ref=next(x for x in old['primary'] if x['comparison']==m)
    assert np.allclose(out['primary'][m]['ci_pp'],ref['scenario_cluster_ci_pp'])
assert out['pooled']['base_success']==144 and out['pooled']['full_success']==207
assert out['external']['bwapp']['n_pairs']==27 and out['external']['bwapp']['full_success']==23
assert np.allclose(out['external']['bwapp']['ci_pp'],old['bwapp']['matched']['scenario_cluster_ci_pp'])
for group in ['primary_paired_outcomes.csv','ablation_paired_outcomes.csv','external_paired_outcomes.csv']:
    rows=read(group)
    keys=[(r['comparison'],r.get('model',''),r['scenario'],r['seed']) for r in rows]
    assert len(keys)==len(set(keys)),f'duplicate pairing keys in {group}'
link=read('cumulative_coverage_linkage.csv');assert len(link)==120
assert sum(int(r['cumulative_coverage']) for r in link)==116
assert sum(r['initial_status']=='no_report' for r in link)==3
ret=read('retry_cohorts.csv');assert len(ret)==25 and len(set(r['run_id'] for r in ret))==25
assert sum(r['cohort']=='f40fix' and r['success']=='1' for r in ret)==12
artifact_ids={r['canonical_probe_run_id'] for r in link if r['canonical_probe_run_id']}
assert not artifact_ids.intersection(r['run_id'] for r in ret)
print(json.dumps(out,indent=2))
print('PASS: numerical reconstruction, unique pairing keys, 116/120 linkage and retry counts.')
if '--check' not in sys.argv:(A/'reproduced_statistics.json').write_text(json.dumps(out,indent=2),encoding='utf-8')
