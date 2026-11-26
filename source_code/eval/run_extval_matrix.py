"""External-validity MULTI-SEED matrix for bWAPP & Juice Shop.

Runs {Base(pure ReAct), Full(b8+5)} x seeds {42,7,123} on the CURATED IN-SCOPE
cells (DVWA-counterpart classes) of each target. Purpose: firm up the Base-vs-Full
odds ratio with proper n (previously 1 seed) and give a seed-stable in-scope SR.

Base model qwen3.5 FROZEN. Oracle STRICT. Components:
  Base = run_base_extval.BASE          (pure_mode, every component OFF)
  Full = run_dvwa_ext.FULL_EXT         (b8+5; oracle_universal ON, web_search App#4-only)
Markers/oracle per target IDENTICAL to the Full smoke path (run_smoke_plan16):
  bWAPP uses set_sqli_row_markers/set_blind_markers; Juice uses the universal oracle.

Robustness (same as the DVWA matrix): each cell runs in its OWN subprocess (a hard
crash -- ReadTimeout/segfault/chromium -- kills only that cell), resume-safe via
report.json, CSV rebuilt from report.json each run. Uses the PATCHED http_client
(base_url path-scoping fix). Fresh rid namespace so it never overwrites old data:
    rid = extm-<target>-<cfg>-<cell>-s<seed>

Run on pod (targets must be up):
    .venv/bin/python eval/run_extval_matrix.py --target bwapp
    .venv/bin/python eval/run_extval_matrix.py --target juiceshop
    .venv/bin/python eval/run_extval_matrix.py               # both, bwapp then juiceshop
"""
import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import requests
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from src.orchestrator import (Orchestrator, Scenario, load_config,          # noqa: E402
                              set_sqli_row_markers, set_blind_markers)
from eval.run_dvwa_ext import FULL_EXT                                      # noqa: E402
from eval.run_base_extval import BASE                                       # noqa: E402

MODEL = "qwen3.5:latest"
SEEDS = [42, 7, 123]
CONFIGS = {"base": BASE, "full": FULL_EXT}
CELL_TIMEOUT_S = 900

# Curated IN-SCOPE cells (DVWA-counterpart classes) -- IDENTICAL to
# run_smoke_plan16.TARGETS[target]["tc"]. Kept inline so this runner is
# self-contained and the in-scope set is auditable at a glance.
TARGETS = {
    "bwapp": {
        "base_url": "http://localhost/bWAPP", "app": "bwapp",
        "user": "bee", "pass": "bug",
        "scenarios": ROOT / "eval" / "scenarios_bwapp.yaml",
        "sqli_markers": ['<tr height="30">'],
        "blind_exists": ["imdb.com/title/"], "blind_missing": ["No movies were found"],
        "tc": ["bw_sqli_low", "bw_blind_sqli_low", "bw_xss_reflected_low",
               "bw_xss_reflected_medium", "bw_xss_stored_low", "bw_xss_stored_medium",
               "bw_cmdi_low", "bw_cmdi_medium", "bw_fi_low", "bw_htmli_low"],
    },
    "juiceshop": {
        "base_url": "http://127.0.0.1:3000/", "app": "juiceshop",
        "user": "", "pass": "",
        "scenarios": ROOT / "eval" / "scenarios_juiceshop.yaml",
        "sqli_markers": None, "blind_exists": None, "blind_missing": None,
        "tc": ["js_login_sqli", "js_login_sqli_user2", "js_sqli_search_union",
               "js_access_products_rest", "js_xss_reflected_track"],
    },
}


def _apply_markers(spec):
    if spec["sqli_markers"]:
        set_sqli_row_markers(spec["sqli_markers"])
    if spec["blind_exists"] or spec["blind_missing"]:
        set_blind_markers(exists=spec["blind_exists"], missing=spec["blind_missing"])


def load_inscope(target):
    spec = TARGETS[target]
    want = set(spec["tc"])
    data = yaml.safe_load(open(spec["scenarios"], encoding="utf-8"))["scenarios"]
    out, seen = [], set()
    for s in data:
        sid = str(s["id"])
        if sid in want and sid not in seen:
            seen.add(sid); out.append(s)
    missing = want - seen
    if missing:
        print(f"  WARN: in-scope ids not found in yaml: {sorted(missing)}", flush=True)
    return out


def reachable(url, timeout=4.0):
    try:
        requests.get(url, timeout=timeout); return True
    except Exception:
        return False


def rid_for(target, cfg, sid, seed):
    return f"extm-{target}-{cfg}-{sid}-s{seed}"


def run_one(target, cfg, seed, sid):
    """One cell in an isolated subprocess. Markers set here (global orchestrator
    state, so clean per-subprocess)."""
    spec = TARGETS[target]
    _apply_markers(spec)
    s = next(x for x in load_inscope(target) if str(x["id"]) == sid)
    scen = Scenario.from_dict(s)
    cfg_dict = load_config(ROOT / "config.yaml")
    cfg_dict["components"] = dict(CONFIGS[cfg])
    cfg_dict["bandit"] = {"store_path": f"data/bandit/extm_{cfg}_{target}.joblib"}
    cfg_dict["model"]["name"] = MODEL
    cfg_dict["model"]["seed"] = int(seed)
    cfg_dict["target"]["base_url"] = spec["base_url"]
    cfg_dict["target"]["app"] = spec["app"]
    cfg_dict["target"]["login_user"] = spec["user"]
    cfg_dict["target"]["login_pass"] = spec["pass"]
    Orchestrator(cfg_dict, scen, run_id=rid_for(target, cfg, sid, seed)).run()


def _cell(target, cfg, seed, sid, level, w, f):
    rd = ROOT / "runs" / rid_for(target, cfg, sid, seed)
    rep = rd / "report.json"
    if rep.exists():
        try:
            r = json.loads(rep.read_text(encoding="utf-8"))
            ok = bool(r.get("success"))
            w.writerow([target, cfg, seed, sid, level, int(ok), r.get("iterations_used"),
                        round(r.get("wall_clock_s", 0)), r.get("finish_reason", "")])
            f.flush(); print(f"  SKIP {cfg}/{sid}/s{seed} (done, {ok})", flush=True)
            return int(ok)
        except Exception:
            shutil.rmtree(rd, ignore_errors=True)
    if rd.exists():
        shutil.rmtree(rd, ignore_errors=True)
    try:
        subprocess.run([sys.executable, str(Path(__file__).resolve()),
                        "--one", target, cfg, str(seed), sid],
                       cwd=str(ROOT), timeout=CELL_TIMEOUT_S, env={**os.environ})
    except subprocess.TimeoutExpired:
        print(f"  [{cfg}/{sid}/s{seed}] TIMEOUT", flush=True)
    except Exception as e:  # noqa: BLE001
        print(f"  [{cfg}/{sid}/s{seed}] SUBPROC_ERR {type(e).__name__}", flush=True)
    if rep.exists():
        try:
            r = json.loads(rep.read_text(encoding="utf-8"))
            ok = bool(r.get("success"))
            w.writerow([target, cfg, seed, sid, level, int(ok), r.get("iterations_used"),
                        round(r.get("wall_clock_s", 0)), r.get("finish_reason", "")])
            print(f"  [{cfg}/{sid}/s{seed}] success={ok} it={r.get('iterations_used')}", flush=True)
            f.flush(); return int(ok)
        except Exception:
            w.writerow([target, cfg, seed, sid, level, 0, "", "", "badjson"]); f.flush()
            return 0
    w.writerow([target, cfg, seed, sid, level, 0, "", "", "crash:no_report"]); f.flush()
    print(f"  [{cfg}/{sid}/s{seed}] CRASH no report.json", flush=True)
    return 0


def run_target(target):
    spec = TARGETS[target]
    if not reachable(spec["base_url"]):
        print(f"PRE-FLIGHT FAIL: {spec['base_url']} unreachable -- deploy {target} first. Skip.",
              flush=True)
        return None
    scens = load_inscope(target)
    print(f"\n### EXTVAL {target}: {len(scens)} in-scope cells x {len(CONFIGS)} cfg x "
          f"{len(SEEDS)} seeds = {len(scens)*len(CONFIGS)*len(SEEDS)} cells ###", flush=True)
    out_csv = ROOT / "results" / f"extval_{target}.csv"
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    f = open(out_csv, "w", newline="", encoding="utf-8")
    w = csv.writer(f)
    w.writerow(["target", "cfg", "seed", "scenario", "level", "success", "iters", "wall", "finish_reason"])
    tally = {("base", s): 0 for s in SEEDS}
    tally.update({("full", s): 0 for s in SEEDS})
    for cfg in ("base", "full"):
        for seed in SEEDS:
            for s in scens:
                tally[(cfg, seed)] += _cell(target, cfg, seed, str(s["id"]), s.get("level"), w, f)
    f.close()
    n = len(scens)
    print(f"\n### EXTVAL_DONE {target} (n={n}/seed):", flush=True)
    for cfg in ("base", "full"):
        parts = " ".join(f"s{s}={tally[(cfg,s)]}/{n}" for s in SEEDS)
        tot = sum(tally[(cfg, s)] for s in SEEDS); tn = n * len(SEEDS)
        print(f"    {cfg:4s}: {parts}  | pooled {tot}/{tn} = {tot/tn:.0%}", flush=True)
    return tally, n


def main(targets):
    print(f"EXTVAL MATRIX multi-seed :: model={MODEL} seeds={SEEDS}", flush=True)
    summary = []
    for t in targets:
        res = run_target(t)
        if res:
            tally, n = res
            bt = sum(tally[("base", s)] for s in SEEDS); ft = sum(tally[("full", s)] for s in SEEDS)
            tn = n * len(SEEDS)
            summary.append(f"{t}: Base {bt}/{tn} -> Full {ft}/{tn}")
    print("\nEXTVAL_MATRIX_DONE :: " + " | ".join(summary), flush=True)


if __name__ == "__main__":
    if len(sys.argv) >= 6 and sys.argv[1] == "--one":
        run_one(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    else:
        ap = argparse.ArgumentParser()
        ap.add_argument("--target", choices=["bwapp", "juiceshop"],
                        help="omit to run both (bwapp then juiceshop)")
        a = ap.parse_args()
        main([a.target] if a.target else ["bwapp", "juiceshop"])
