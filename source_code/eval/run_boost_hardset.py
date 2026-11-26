"""Boosted hard-set re-run (plan_boost_full.md). Qwen3.5 / seed 42.

Goal: test whether, with the F1-F5 fixes turned ON and each GATED to its owning
component (run.boost=True), the full system becomes net-best:
    (G1) absolute success rises vs the no-fix baseline, and
    (G2) Full > every leave-one-out (Full-1).

Only the HARD-SET of testcases is re-run -- the TCs that every condition already
solved are at the ceiling (Full == LOO there) and add nothing to the ranking.
Hard-set = union of every TC that FAILED or ERRORED in any config (incl. Full)
during the no-fix ablation (ablation_loo.csv + Full@L3 baseline).

CONFIGS = Full (no removal) + the same 7 leave-one-out configs as the ablation,
all with run.boost=True. 16 TC x 8 configs = 128 runs. Same budget/protocol as the
sweep (early-stop on oracle success, 15 iters / 1500 s). Per-run try/except so one
transient localhost error cannot abort the batch; RESUME skips finished pairs.

Writes ablation_boost.csv + report.json per run (prefix 'bst'). Prints BST_ALLDONE.

Usage (on pod, in venv):  python eval/run_boost_hardset.py
"""
import os, sys, csv, shutil, subprocess
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from src.orchestrator import Orchestrator, Scenario, load_config

MTAG, MODEL, SEED, PREFIX = "q35", "qwen3.5:latest", 42, "bst"

# Full (L3) baseline toggles -- identical to eval/run_ablation_loo.py / one_run_seed.py L3.
FULL = {"pure_mode": False,
        "working_memory": True, "rag": True, "reflection": True, "guardrail": True,
        "state_graph": True, "tools_mcp": True, "sandbox": True, "auto_verify_xss": True,
        "long_term_memory": False, "web_search": False, "web_search_fallback": False,
        "skills": False, "eyes_ml": True, "progress_protection": True, "use_promise": True}

# Full first (the reference we want to be best), then the 7 leave-one-out configs.
CONFIGS = [
    ("FULL",  {}),
    ("L-RAG", {"rag": False}),
    ("L-REF", {"reflection": False}),
    ("L-GRD", {"guardrail": False}),
    ("L-TLS", {"tools_mcp": False}),
    ("L-N3",  {"eyes_ml": False}),
    ("L-SG",  {"state_graph": False, "progress_protection": False, "use_promise": False}),
    ("L-C2",  {"use_promise": False}),
]

# Hard-set: union of every TC that failed OR errored in any config during the no-fix
# ablation (incl. Full's own 7 fails). Ceiling TCs are intentionally excluded.
HARD_SET = [
    "sqli_medium", "sqli_high", "blind_sqli_high",
    "csrf_low", "csrf_medium", "csrf_high",
    "xss_dom_high", "xss_stored_high",
    "js_medium", "js_high",
    "upload_high",
    "open_redirect_low", "open_redirect_high",
    "cmdi_low", "brute_low", "brute_high",
]  # 16 TC


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
    want = set(HARD_SET)
    seen, sc = set(), []
    for s in data:
        sid = str(s["id"])
        if sid in want and sid not in seen:
            seen.add(sid)
            sc.append(s)
    missing = want - seen
    assert not missing, f"scenarios.yaml missing hard-set TCs: {sorted(missing)}"
    assert len(sc) == len(HARD_SET), f"expected {len(HARD_SET)} TCs, got {len(sc)}"
    return sc


def main():
    scens = scenarios()
    total = len(CONFIGS) * len(scens)
    print(f"BOOST hard-set: {len(CONFIGS)} configs x {len(scens)} TC x 1 seed({SEED}) "
          f"x 1 model({MTAG}) = {total} runs  [run.boost=True]", flush=True)

    out_csv = ROOT / "ablation_boost.csv"
    newfile = not out_csv.exists()
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

    done, errors = len(done_pairs), 0
    for cname, override in CONFIGS:
        comp = dict(FULL)
        comp.update(override)
        print(f"=== CONFIG {cname} (override={override}) ===", flush=True)
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
                cfg.setdefault("run", {})["fix_retry"] = False   # keep global flag off
                cfg["run"]["boost"] = True                       # per-component-gated fixes ON
                reset_dvwa_state()
                rep = Orchestrator(cfg, scen, run_id=rid).run()
                row = [cname, sid, int(bool(rep.get("success"))),
                       rep.get("iterations_used"), round(rep.get("wall_clock_s", 0)),
                       rep.get("guardrail_blocks", ""), rep.get("backtracks", ""),
                       rep.get("tokens_used", ""), rep.get("peak_vram_mb", ""),
                       rep.get("finish_reason", "")]
                msg = (f"success={rep.get('success')} it={rep.get('iterations_used')} "
                       f"wall={rep.get('wall_clock_s', 0):.0f}s")
            except Exception as e:
                errors += 1
                row = [cname, sid, 0, "", "", "", "", "", "", f"error:{type(e).__name__}"]
                msg = f"ERROR {type(e).__name__}: {str(e)[:80]} -> recorded success=0, continuing"
            w.writerow(row); f.flush()
            done += 1
            print(f"  [{done}/{total}] {cname} {sid} {msg}", flush=True)
    f.close()
    print(f"BST_ALLDONE (errors={errors})", flush=True)


if __name__ == "__main__":
    main()
