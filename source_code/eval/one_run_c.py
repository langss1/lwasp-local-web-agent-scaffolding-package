"""Single C0/C1 run in its own process (memory released on exit). plan9.md M3.
Usage: python eval/one_run_c.py <C0|C1> <scenario_id>
Fixed scaffolding (state_graph+guardrail+rag+reflection+tools+sandbox ON; skills/
web/ltm OFF) so the ONLY difference between C0 and C1 is progress_protection."""
import sys, os, json, yaml
sys.path.insert(0, r"C:\Spesial TA\pentest-agent")
from src.orchestrator import Orchestrator, Scenario, load_config

cond, sid = sys.argv[1], sys.argv[2]
seed = int(sys.argv[3]) if len(sys.argv) > 3 else 42
rid = f"c0c1-{sid}-{cond}-s{seed}"
if os.path.exists(rf"C:\Spesial TA\pentest-agent\runs\{rid}\report.json"):
    print("skip", rid); sys.exit(0)

cfg = load_config(r"C:\Spesial TA\pentest-agent\config.yaml")
scen = next(Scenario.from_dict(s) for s in yaml.safe_load(
    open(r"C:\Spesial TA\pentest-agent\eval\scenarios.yaml", encoding="utf-8"))["scenarios"] if s["id"] == sid)
cfg["components"] = {
    "pure_mode": False, "working_memory": True, "rag": True, "reflection": True,
    "guardrail": True, "state_graph": True, "tools_mcp": True, "sandbox": True,
    "long_term_memory": False, "web_search": False, "web_search_fallback": False,
    "skills": False, "auto_verify_xss": True,
    "progress_protection": (cond == "C1"),
}
cfg["model"]["seed"] = seed
rep = Orchestrator(cfg, scen, run_id=rid).run()
print(rid, "success=%s it=%s backtracks=%s holds=%s" % (
    rep["success"], rep["iterations_used"], rep["backtracks"], rep.get("progress_holds")))
