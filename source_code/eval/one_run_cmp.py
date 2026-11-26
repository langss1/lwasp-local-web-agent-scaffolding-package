"""One comparison run (4-condition pilot, plan11). FRESH & isolated (no leak).
Parameterizes the ACTOR model so runs across models never overwrite each other.
Levels: L1=base (pure LLM, no scaffold), L3=full (all 13 components).
Equal budget/seed for every condition (fair). LTM/web/skills OFF.
Usage: python eval/one_run_cmp.py <model_tag> <ollama_model> <L1|L3> <scenario_id>
  e.g. python eval/one_run_cmp.py q35 qwen3.5:latest L3 sqli_medium"""
import sys, os, shutil, yaml
sys.path.insert(0, r"C:\Spesial TA\pentest-agent")
from src.orchestrator import Orchestrator, Scenario, load_config

mtag, mname, lvl, sid = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
rid = f"cmp-{mtag}-{sid}-{lvl}"                 # model tag in id -> no cross-model overwrite
rd = rf"C:\Spesial TA\pentest-agent\runs\{rid}"
if os.path.exists(rd):
    shutil.rmtree(rd, ignore_errors=True)       # FRESH every time

cfg = load_config(r"C:\Spesial TA\pentest-agent\config.yaml")
scen = next(Scenario.from_dict(s) for s in yaml.safe_load(
    open(r"C:\Spesial TA\pentest-agent\eval\scenarios.yaml", encoding="utf-8"))["scenarios"] if s["id"] == sid)

SCAFF = {"working_memory": True, "rag": True, "reflection": True, "guardrail": True,
         "state_graph": True, "tools_mcp": True, "sandbox": True, "auto_verify_xss": True}
OFF = {"long_term_memory": False, "web_search": False, "web_search_fallback": False, "skills": False}
if lvl == "L1":        # base = pure LLM (none of the 13 components)
    comp = {"pure_mode": True, **{k: False for k in SCAFF}, **OFF,
            "eyes_ml": False, "progress_protection": False, "use_promise": False}
else:                  # L3 = full system (all components)
    comp = {"pure_mode": False, **SCAFF, **OFF,
            "eyes_ml": True, "progress_protection": True, "use_promise": True}
cfg["components"] = comp
cfg["model"]["name"] = mname                    # <-- swap the actor
cfg["model"]["seed"] = 42
cfg["run"]["max_iterations"] = 10               # EQUAL budget (fair, both models)
cfg["run"]["max_wall_clock_s"] = 900
rep = Orchestrator(cfg, scen, run_id=rid).run()
print(rid, "success=%s agent_claim=%s it=%s wall=%.0fs vram=%.0fMB tok=%s" % (
    rep["success"], rep.get("agent_finished_success"), rep["iterations_used"],
    rep.get("wall_clock_s", 0), rep.get("peak_vram_mb", 0), rep.get("tokens_used")))
