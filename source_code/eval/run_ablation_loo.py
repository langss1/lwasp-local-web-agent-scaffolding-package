"""Leave-one-out component ablation (plan_ablation.md). Qwen3.5 / seed 42 / 39 scenarios.

Each config = Full (L3) with EXACTLY ONE component removed (leave-one-out); all other
components stay ON. The sweep's Full (f40-q35-*-L3-s42) is the reference and is NOT
re-run here. captcha_* is excluded (reCAPTCHA out-of-scope).

Run termination is UNCHANGED from the sweep: early-stop on oracle-verified success,
cap 15 iterations / 1500 s. Guardrail is left to work fully; its effect is MEASURED via
logged guardrail_blocks + delta-iterations, never by halting the run when it fires.

Touches no sweep file. Writes report.json per run under prefix 'abl' + aggregate
ablation_loo.csv. Prints ABL_ALLDONE at the end.

Usage (on pod, in venv):  python eval/run_ablation_loo.py
"""
import os, sys, csv, shutil, subprocess, yaml
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from src.orchestrator import Orchestrator, Scenario, load_config

MTAG, MODEL, SEED, PREFIX = "q35", "qwen3.5:latest", 42, "abl"

# Full (L3) baseline toggles -- identical to eval/one_run_seed.py L3 branch.
FULL = {"pure_mode": False,
        "working_memory": True, "rag": True, "reflection": True, "guardrail": True,
        "state_graph": True, "tools_mcp": True, "sandbox": True, "auto_verify_xss": True,
        "long_term_memory": False, "web_search": False, "web_search_fallback": False,
        "skills": False, "eyes_ml": True, "progress_protection": True, "use_promise": True}

# Each config = FULL with the listed keys overridden. Leave-one-out: remove exactly one
# component, keep the rest. L-SG removes the whole backtracking subsystem (state_graph +
# C1 + C2); L-C2 removes only the ML promise scorer (C2), keeping state_graph + C1 (rule).
CONFIGS = [
    ("L-RAG", {"rag": False}),
    ("L-REF", {"reflection": False}),
    ("L-GRD", {"guardrail": False}),
    ("L-TLS", {"tools_mcp": False}),
    ("L-N3",  {"eyes_ml": False}),
    ("L-SG",  {"state_graph": False, "progress_protection": False, "use_promise": False}),
    ("L-C2",  {"use_promise": False}),
]

# PINNED to the EXACT 39 scenarios the main sweep ran for q35/L3/seed42 (non-captcha),
# so Full@q35@s42 = 32/39 stays the valid paired reference. scenarios.yaml on the pod
# has extra entries not in the sweep; those must NOT be included.
SWEEP_SCENARIOS = {
    "blind_sqli_high", "blind_sqli_low", "blind_sqli_medium",
    "brute_high", "brute_low", "brute_medium",
    "cmdi_high", "cmdi_low", "cmdi_medium",
    "csrf_high", "csrf_low", "csrf_medium",
    "fi_high", "fi_low", "fi_medium",
    "js_high", "js_low", "js_medium",
    "open_redirect_high", "open_redirect_low", "open_redirect_medium",
    "sqli_high", "sqli_low", "sqli_medium",
    "upload_high", "upload_low", "upload_medium",
    "weak_session_high", "weak_session_low", "weak_session_medium",
    "xss_dom_high", "xss_dom_low", "xss_dom_medium",
    "xss_reflected_high", "xss_reflected_low", "xss_reflected_medium",
    "xss_stored_high", "xss_stored_low", "xss_stored_medium",
}


def reset_dvwa_state():
    """Pollution guard (same as one_run_seed.py): restore admin creds before each run."""
    try:
        subprocess.run(
            ["mariadb", "-uroot", "-e",
             "USE dvwa; UPDATE users SET password=md5('password') WHERE user='admin';"],
            timeout=15, check=False,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def scenarios():
    data = yaml.safe_load(open(ROOT / "eval" / "scenarios.yaml", encoding="utf-8"))["scenarios"]
    # Dedup by id keeping the FIRST occurrence -- same as the sweep's one_run_seed.py
    # `next(... if s["id"]==sid)`. scenarios.yaml has duplicate entries for a couple of
    # ids (same mechanics, different hint wording); the sweep used the first.
    seen, sc = set(), []
    for s in data:
        sid = str(s["id"])
        if sid in SWEEP_SCENARIOS and sid not in seen:
            seen.add(sid)
            sc.append(s)
    missing = SWEEP_SCENARIOS - seen
    assert not missing, f"scenarios.yaml missing sweep scenarios: {sorted(missing)}"
    assert len(sc) == 39, f"expected 39 pinned scenarios, got {len(sc)}"
    return sc


def main():
    scens = scenarios()
    total = len(CONFIGS) * len(scens)
    print(f"ABLATION leave-one-out: {len(CONFIGS)} configs x {len(scens)} scenarios "
          f"x 1 seed({SEED}) x 1 model({MTAG}) = {total} runs", flush=True)
    for cname, ov in CONFIGS:
        print(f"    - {cname}: remove {ov}", flush=True)

    out_csv = ROOT / "ablation_loo.csv"
    newfile = not out_csv.exists()

    # RESUME: skip (config, scenario) pairs already recorded, so a mid-batch crash can be
    # relaunched without redoing finished runs.
    done_pairs = set()
    if not newfile:
        with open(out_csv, newline="", encoding="utf-8") as rf:
            for row in csv.reader(rf):
                if len(row) >= 2 and row[0] != "config":
                    done_pairs.add((row[0], row[1]))
    print(f"RESUME: {len(done_pairs)} runs already recorded -> skipped", flush=True)

    f = open(out_csv, "a", newline="", encoding="utf-8")
    w = csv.writer(f)
    if newfile:
        w.writerow(["config", "scenario", "success", "iters", "wall",
                    "guardrail_blocks", "backtracks", "tokens", "peak_vram_mb", "finish_reason"])

    done = len(done_pairs)
    errors = 0
    for cname, override in CONFIGS:
        comp = dict(FULL)
        comp.update(override)
        print(f"=== CONFIG {cname} (comp override={override}) ===", flush=True)
        for s in scens:
            sid = s["id"]
            if (cname, sid) in done_pairs:
                continue
            rid = f"{PREFIX}-{cname}-{MTAG}-{sid}-s{SEED}"
            rd = ROOT / "runs" / rid
            if rd.exists():
                shutil.rmtree(rd, ignore_errors=True)
            try:
                scen = Scenario.from_dict(s)
                cfg = load_config(ROOT / "config.yaml")
                cfg["components"] = comp
                cfg["model"]["name"] = MODEL
                cfg["model"]["seed"] = SEED
                cfg.setdefault("run", {})["fix_retry"] = False   # ablation = base behaviour
                reset_dvwa_state()
                rep = Orchestrator(cfg, scen, run_id=rid).run()
                row = [cname, sid, int(bool(rep.get("success"))),
                       rep.get("iterations_used"), round(rep.get("wall_clock_s", 0)),
                       rep.get("guardrail_blocks", ""), rep.get("backtracks", ""),
                       rep.get("tokens_used", ""), rep.get("peak_vram_mb", ""),
                       rep.get("finish_reason", "")]
                msg = (f"success={rep.get('success')} it={rep.get('iterations_used')} "
                       f"wall={rep.get('wall_clock_s', 0):.0f}s gblk={rep.get('guardrail_blocks')} "
                       f"bt={rep.get('backtracks')}")
            except Exception as e:
                # One run's failure (e.g. a transient localhost ReadTimeout) must NOT abort the
                # whole batch. Record it as a failed run and keep going. The sweep got this
                # resilience from per-run subprocess isolation; this in-process runner needs it
                # explicitly.
                errors += 1
                row = [cname, sid, 0, "", "", "", "", "", "", f"error:{type(e).__name__}"]
                msg = f"ERROR {type(e).__name__}: {str(e)[:80]} -> recorded success=0, continuing"
            w.writerow(row)
            f.flush()
            done += 1
            print(f"  [{done}/{total}] {cname} {sid} {msg}", flush=True)
    f.close()
    print(f"ABL_ALLDONE (errors={errors})", flush=True)


if __name__ == "__main__":
    main()
