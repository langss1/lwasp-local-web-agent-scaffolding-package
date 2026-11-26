"""One N1-ablation-level run, FRESH & isolated (no leak/poison). plan10 M3-clean.
Levels: L1=pure LLM, L2=+scaffolding (no new ML), L3=+ML (full). Equal budget.
Anti-leak: long_term_memory OFF, web OFF, skills OFF, tools scoped to knowledge/ (fixed),
fresh run_id, seed fixed. Usage: python eval/one_run_level.py <L1|L2|L3> <scenario_id>"""
import sys, os, shutil, yaml
sys.path.insert(0, r"C:\Spesial TA\pentest-agent")
from src.orchestrator import Orchestrator, Scenario, load_config

lvl, sid = sys.argv[1], sys.argv[2]
rid = f"smk-{sid}-{lvl}"
rd = rf"C:\Spesial TA\pentest-agent\runs\{rid}"
if os.path.exists(rd):
    shutil.rmtree(rd, ignore_errors=True)   # FRESH every time (user: pakai data baru)

cfg = load_config(r"C:\Spesial TA\pentest-agent\config.yaml")
scen = next(Scenario.from_dict(s) for s in yaml.safe_load(
    open(r"C:\Spesial TA\pentest-agent\eval\scenarios.yaml", encoding="utf-8"))["scenarios"] if s["id"] == sid)

SCAFF = {"working_memory": True, "rag": True, "reflection": True, "guardrail": True,
         "state_graph": True, "tools_mcp": True, "sandbox": True, "auto_verify_xss": True}
OFF = {"long_term_memory": False, "web_search": False, "web_search_fallback": False, "skills": False}
if lvl == "L1":        # pure LLM
    comp = {"pure_mode": True, **{k: False for k in SCAFF}, **OFF,
            "eyes_ml": False, "progress_protection": False, "use_promise": False}
elif lvl == "L2":      # + scaffolding, NO new ML
    comp = {"pure_mode": False, **SCAFF, **OFF,
            "eyes_ml": False, "progress_protection": False, "use_promise": False}
else:                  # L3 = + ML (full)
    comp = {"pure_mode": False, **SCAFF, **OFF,
            "eyes_ml": True, "progress_protection": True, "use_promise": True}
cfg["components"] = comp
cfg["model"]["seed"] = 42
cfg["run"]["max_iterations"] = 10          # EQUAL budget all levels (fair)
cfg["run"]["max_wall_clock_s"] = 900
rep = Orchestrator(cfg, scen, run_id=rid).run()
print(rid, "success=%s it=%s" % (rep["success"], rep["iterations_used"]))
