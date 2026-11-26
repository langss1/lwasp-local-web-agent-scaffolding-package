"""One full-system run as its own process (memory fully released on exit).

Unlike eval/one_run.py (the ablation harness), this does NOT override
components or the run budget -- it uses config.yaml exactly as written
(rag+reflection+guardrail+state_graph+long_term_memory all ON, 10 iterations /
900s wall-clock). Purpose: "can the full agent do this test case at all",
not component isolation. See plan5.md for the full rationale.

Resumable: skips if the run's report.json already exists. seed = 42 + idx so
the 3 iterations per scenario are genuinely different stochastic samples.
"""
import sys, os, copy, subprocess
sys.path.insert(0, r"C:\Spesial TA\pentest-agent")
from src.orchestrator import Orchestrator, Scenario, load_config, load_scenarios

sid, idx = sys.argv[1], int(sys.argv[2])
rid = f"fs3-{sid}-{idx:02d}"
if os.path.exists(rf"runs\{rid}\report.json"):
    print("skip", rid)
    sys.exit(0)

# ROOT-CAUSE FIX (2026-10-14): reset DVWA admin password before EVERY run. A CSRF
# test earlier in a session could change admin's password; once wrong, login
# fails and every request returns the login page -- surfacing as fake "mechanic
# failures" (weak_session/upload/js/xss_dom). Resetting here makes login reliable
# regardless of what a prior run did. See TRAINING_LOG.md / plan6.md.
try:
    subprocess.run(
        [r"C:/xampp/mysql/bin/mysql.exe", "-u", "root", "dvwa", "-e",
         "UPDATE users SET password=MD5('password') WHERE user='admin';"],
        timeout=20, capture_output=True)
except Exception as _e:
    print("warn: dvwa password reset failed:", _e)

cfg = load_config(r"C:\Spesial TA\pentest-agent\config.yaml")
scen = next(s for s in load_scenarios() if s.id == sid)
cfg = copy.deepcopy(cfg)
cfg["model"]["seed"] = 42 + idx

rep = Orchestrator(cfg, scen, run_id=rid).run()
print(rid, "success=%s it=%s wall=%.1f" % (rep["success"], rep["iterations_to_success"], rep["wall_clock_s"]))
