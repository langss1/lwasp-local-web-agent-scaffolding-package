"""One ablation run as its own process (memory fully released on exit).
Resumable: skips if the run's report.json already exists. Varies the seed per
index so the N runs are genuinely different samples (not identical)."""
import sys, os, copy, yaml
sys.path.insert(0, r"C:\Spesial TA\pentest-agent")
from src.orchestrator import Orchestrator, Scenario, load_config
cfg_id, sid, idx = sys.argv[1], sys.argv[2], int(sys.argv[3])
rid = f"abl-{sid}-{cfg_id}-{idx:02d}"
if os.path.exists(rf"runs\{rid}\report.json"):
    print("skip", rid); sys.exit(0)
base = load_config(r"C:\Spesial TA\pentest-agent\config.yaml")
abl = yaml.safe_load(open(r"C:\Spesial TA\pentest-agent\eval\ablation.yaml", encoding="utf-8"))
conf = next(c for c in abl["configurations"] if c["id"] == cfg_id)
comp = conf["components"]
# Clean scenarios (goal-only, NO technique hints) for ALL ablation configs, so the
# task framing is identical across B0-B10 and only scaffolding differs (chat 2026-10-16).
scen = next(Scenario.from_dict(s) for s in yaml.safe_load(open(r"C:\Spesial TA\pentest-agent\pure_baseline\pure_scenarios.yaml", encoding="utf-8"))["scenarios"] if s["id"] == sid)
cfg = copy.deepcopy(base)
cfg["components"] = comp
cfg["model"]["seed"] = 42 + idx
# Per-config iteration budget: B0 (base model) is a single shot; others iterate.
cfg["run"]["max_iterations"] = conf.get("max_iterations", 6)
cfg["run"]["max_wall_clock_s"] = conf.get("max_wall_clock_s", 240)
# BUG-2 fix (plan2.md SS1.2 / plan3.md SS4.1): long_term_memory's store_dir/chroma_dir
# default to one global path shared by every run. Without scoping, a config that
# enables long_term_memory (B5, B10) would read lessons written by a DIFFERENT
# config's runs (e.g. B10 leaking into/from B5), and lessons would also accumulate
# across this config's own N repeats of the SAME scenario -- contaminating the
# i.i.d.-repeat assumption behind success-rate/CI stats. Isolating per config_id
# (one lessons store per Bn) keeps cross-config leakage impossible while staying
# resumable (no deletion needed -- same store_dir is just reused across idx 0..N-1
# for that config, which is the intended "cross-session, same system variant"
# accumulation long_term_memory is meant to model).
cfg["long_term_memory"] = dict(cfg.get("long_term_memory", {}))
cfg["long_term_memory"]["store_dir"] = f"knowledge/long_term/{cfg_id}"
cfg["long_term_memory"]["chroma_dir"] = f"knowledge/long_term/{cfg_id}/chroma"
rep = Orchestrator(cfg, scen, run_id=rid).run()
print(rid, "success=%s it=%s" % (rep["success"], rep["iterations_to_success"]))
