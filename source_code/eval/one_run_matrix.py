"""One matrix cell run (own process). plan9.md M5 matriks 2x3.
Usage: python eval/one_run_matrix.py <P0|P1> <C0|C1|C2> <scenario_id>
Scaffolding fixed; only eyes (P0/P1=N3 ML) and controller (C0/C1/C2) vary."""
import sys, os, yaml
sys.path.insert(0, r"C:\Spesial TA\pentest-agent")
from src.orchestrator import Orchestrator, Scenario, load_config

eyes, ctrl, sid = sys.argv[1], sys.argv[2], sys.argv[3]
rid = f"mtx-{sid}-{eyes}{ctrl}"
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
    "eyes_ml": (eyes == "P1"),
    "progress_protection": (ctrl in ("C1", "C2")),
    "use_promise": (ctrl == "C2"),
}
cfg["model"]["seed"] = 42
rep = Orchestrator(cfg, scen, run_id=rid).run()
print(rid, "success=%s it=%s holds=%s" % (rep["success"], rep["iterations_used"], rep.get("progress_holds")))
