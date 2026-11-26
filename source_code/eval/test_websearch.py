"""One-off METHODOLOGY test: force the agent to use WEB_SEARCH and RUN_SCRIPT
through the full runtime, to prove those two action paths actually fire end-to-end
(not just the modules in isolation). web_searches=0 across all 39 training runs
because the 7B model never *chose* WEB_SEARCH on its own -- here we direct it via
the scenario DESCRIPTION only. Base config / system prompt / skills are untouched,
so this does not change any training condition; it is a separate probe.

Target underneath: real DVWA sqli_low (reliable, has a mapped web section). Success
of the exploit is secondary -- the point is whether WEB_SEARCH and RUN_SCRIPT execute
through the agent loop (web_searches>0, script_runs>0, and the trace shows them).

Usage: python eval/test_websearch.py
"""
import sys, os, copy, json, subprocess
sys.path.insert(0, r"C:\Spesial TA\pentest-agent")
from dataclasses import replace
from src.orchestrator import Orchestrator, load_config, load_scenarios

RID = "websearch_test-00"

# reset DVWA admin password (same discipline as one_run_fullsystem.py)
try:
    subprocess.run([r"C:/xampp/mysql/bin/mysql.exe", "-u", "root", "dvwa", "-e",
                    "UPDATE users SET password=MD5('password') WHERE user='admin';"],
                   timeout=20, capture_output=True)
except Exception as e:
    print("warn: dvwa reset failed:", e)

cfg = copy.deepcopy(load_config(r"C:\Spesial TA\pentest-agent\config.yaml"))
cfg["model"]["seed"] = 42

base = next(s for s in load_scenarios() if s.id == "sqli_low")

# Override ONLY id + description to mandate the web-search-then-script workflow.
mandate = (
    "METHODOLOGY TEST (you must follow this exact order):\n"
    "This is DVWA SQL Injection, security level low, on the 'id' parameter. You already "
    "know how to exploit it, but for this run you must demonstrate your knowledge-gathering "
    "and scripting tools.\n"
    "STEP 1 (MANDATORY, do this FIRST): issue a WEB_SEARCH action with a query about "
    "SQL injection authentication-bypass / UNION payloads to pull real-world techniques "
    "from the public knowledge base. Do NOT send any HTTP_REQUEST before you have run "
    "WEB_SEARCH at least once.\n"
    "STEP 2 (MANDATORY, do this SECOND): issue a RUN_SCRIPT action containing short Python "
    "that builds the exact injection string programmatically and prints it "
    "(e.g. print(\"' OR '1'='1' -- \")). Use the printed value as your payload.\n"
    "STEP 3: only now send the HTTP_REQUEST to the 'id' parameter with that payload to "
    "extract the user list, then VERIFY and FINISH.\n"
    "If you skip STEP 1 or STEP 2 the test is invalid -- always WEB_SEARCH then RUN_SCRIPT "
    "before exploiting."
)
scen = replace(base, id="websearch_script_test", description=mandate)

rep = Orchestrator(cfg, scen, run_id=RID).run()

# Summarise whether the two paths fired.
trace = []
tp = rf"runs\{RID}\trace.jsonl"
if os.path.exists(tp):
    for line in open(tp, encoding="utf-8"):
        line = line.strip()
        if line:
            try: trace.append(json.loads(line))
            except json.JSONDecodeError: pass

ws = [r for r in trace if r.get("action", {}).get("type") == "WEB_SEARCH"]
rs = [r for r in trace if r.get("action", {}).get("type") == "RUN_SCRIPT"]
print("\n========== WEB_SEARCH / RUN_SCRIPT PROBE ==========")
print(f"success={rep['success']} iterations={len(trace)} "
      f"web_searches={rep.get('web_searches')} script_runs={rep.get('script_runs')}")
print(f"component_contrib.web_search={rep.get('component_contrib',{}).get('web_search')} "
      f"component_contrib.script={rep.get('component_contrib',{}).get('script')}")
print(f"\nWEB_SEARCH actions fired: {len(ws)}")
for r in ws:
    q = r["action"].get("params", {}).get("query") or r["action"].get("params", {}).get("value")
    sig = str(r.get("observation", {}).get("signal", ""))[:220].replace("\n", " ")
    print(f"  it{r.get('iteration')} query={q!r}\n    -> {sig}")
print(f"\nRUN_SCRIPT actions fired: {len(rs)}")
for r in rs:
    code = str(r["action"].get("params", {}).get("code", ""))[:120].replace("\n", " ; ")
    sig = str(r.get("observation", {}).get("signal", r.get("observation", {}).get("stdout", "")))[:160].replace("\n", " ")
    print(f"  it{r.get('iteration')} code={code!r}\n    -> {sig}")
print("===================================================")
