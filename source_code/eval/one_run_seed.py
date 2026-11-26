"""One seeded comparison run (multi-seed robustness, plan11). FRESH & isolated.
Seed is parameterized AND baked into run_id so seeds never overwrite each other.
Levels: L1=base (pure LLM), L3=full (11 components). Equal budget per cell.
Portable: ROOT derived from this file so it runs on Windows (laptop) and the
Kali pod identically. Budget (max_iterations / max_wall_clock_s) comes from
config.yaml -- a single authoritative knob, raised to 15/1500 on 2026-11-01.
Usage: python eval/one_run_seed.py <model_tag> <ollama_model> <L1|L3> <scenario_id> <seed> [prefix]
  e.g. python eval/one_run_seed.py q35 qwen3.5:latest L3 sqli_medium 7 f40"""
import os, sys, shutil, subprocess, yaml
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from src.orchestrator import Orchestrator, Scenario, load_config


def reset_dvwa_state():
    """POLLUTION GUARD (2026-11-02): a prior run's CSRF / password-change scenario
    can mutate admin's password in the shared DVWA DB, which then breaks login for
    EVERY subsequent run -- turning real exploits into silent `exhausted` failures
    (this cost ~130 runs on 2026-11-01). Restore admin creds before each run so
    every run starts from a clean, loggable baseline. Best-effort: a failure here
    (e.g. mariadb not on PATH on a non-pod host) must never fail the run itself."""
    try:
        subprocess.run(
            ["mariadb", "-uroot", "-e",
             "USE dvwa; UPDATE users SET password=md5('password') WHERE user='admin';"],
            timeout=15, check=False,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

mtag, mname, lvl, sid, seed = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])
prefix = sys.argv[6] if len(sys.argv) > 6 else "ms"  # run_id namespace (ms=multiseed, pilot/f40=full sweep)
rid = f"{prefix}-{mtag}-{sid}-{lvl}-s{seed}"          # seed+prefix in id -> no cross-run overwrite
rd = ROOT / "runs" / rid
if rd.exists():
    shutil.rmtree(rd, ignore_errors=True)

cfg = load_config(ROOT / "config.yaml")
scen = next(Scenario.from_dict(s) for s in yaml.safe_load(
    open(ROOT / "eval" / "scenarios.yaml", encoding="utf-8"))["scenarios"] if s["id"] == sid)

SCAFF = {"working_memory": True, "rag": True, "reflection": True, "guardrail": True,
         "state_graph": True, "tools_mcp": True, "sandbox": True, "auto_verify_xss": True}
OFF = {"long_term_memory": False, "web_search": False, "web_search_fallback": False, "skills": False}
if lvl == "L1":
    comp = {"pure_mode": True, **{k: False for k in SCAFF}, **OFF,
            "eyes_ml": False, "progress_protection": False, "use_promise": False}
else:
    comp = {"pure_mode": False, **SCAFF, **OFF,
            "eyes_ml": True, "progress_protection": True, "use_promise": True}
cfg["components"] = comp
cfg["model"]["name"] = mname
cfg["model"]["seed"] = seed
# plan13 fix-retry: enable the 5 anti-waste fixes ONLY when PA_FIX_RETRY=1 (the
# retry batch sets it). Original sweep runs leave it unset -> behaviour unchanged.
cfg.setdefault("run", {})["fix_retry"] = os.environ.get("PA_FIX_RETRY") == "1"
# Budget (max_iterations / max_wall_clock_s) is NOT overridden here -- it comes
# from config.yaml (15/1500) so both conditions share one authoritative value.
reset_dvwa_state()   # pollution guard: clean login baseline before every run
rep = Orchestrator(cfg, scen, run_id=rid).run()
print(rid, "success=%s it=%s wall=%.0fs" % (rep["success"], rep["iterations_used"], rep.get("wall_clock_s", 0)))
