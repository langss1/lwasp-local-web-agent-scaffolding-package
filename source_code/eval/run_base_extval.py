"""Base (pure ReAct, 0 komponen) untuk bWAPP & Juice Shop -- external-validity pairing.

Tujuan: sediakan sel Base yang dipasangkan dengan Full (sweep16) untuk menghitung OR
per target (apakah efek scaffold yang terlihat di DVWA replikasi di app lain).

Base dict = IDENTIK dgn Base faktorial DVWA & run_bwapp_sweep (pure_mode, semua
komponen OFF). Oracle & marker per-target = SAMA PERSIS dgn jalur Full (run_smoke_plan16)
supaya perbandingan Base vs Full adil. Model qwen3.5 FROZEN, seed 42.

Catatan data (keputusan user 2026-11-09):
  - bWAPP Base SUDAH ADA di results/bwapp_sweep.csv (Base+Full x 3 seed) -> runner bWAPP
    ini disediakan untuk swap/verifikasi, TIDAK wajib dijalankan.
  - Juice Base BELUM pernah -> ini yang dijalankan (9 sel, seed 42).

Robust/unattended (sama dgn run_dvwa_ext): tiap sel di SUBPROCESS sendiri (crash keras
spt ReadTimeout/segfault hanya membunuh 1 sel), resume-safe via report.json, CSV
dibangun ulang dari report.json tiap run.

Jalankan DI POD, venv (target harus sudah up):
    .venv/bin/python eval/run_base_extval.py --target juiceshop
    .venv/bin/python eval/run_base_extval.py --target bwapp
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
from src.orchestrator import (Orchestrator, Scenario, load_config,      # noqa: E402
                              set_sqli_row_markers, set_blind_markers)

MODEL, SEED, MTAG = "qwen3.5:latest", 42, "q35"
CELL_TIMEOUT_S = 900

# Base = L1 pure ReAct, 0 komponen. IDENTIK run_bwapp_sweep.BASE & Base faktorial DVWA.
BASE = {
    "pure_mode": True,
    "working_memory": False, "rag": False, "reflection": False, "guardrail": False,
    "state_graph": False, "tools_mcp": False, "sandbox": False, "auto_verify_xss": False,
    "long_term_memory": False, "web_search": False, "web_search_fallback": False,
    "web_search_app4_only": False, "skills": False,
    "eyes_ml": False, "progress_protection": False, "use_promise": False,
    "recon": False, "oracle_universal": False, "oast": False,
    "context_summarizer": False, "bandit": False,
}

# Spec per target = SAMA dgn run_smoke_plan16.TARGETS (url/app/login + marker oracle).
TARGETS = {
    "bwapp": {
        "base_url": "http://localhost/bWAPP", "app": "bwapp",
        "user": "bee", "pass": "bug",
        "scenarios": ROOT / "eval" / "scenarios_bwapp.yaml",
        "sqli_markers": ['<tr height="30">'],
        "blind_exists": ["imdb.com/title/"], "blind_missing": ["No movies were found"],
    },
    "juiceshop": {
        "base_url": "http://127.0.0.1:3000/", "app": "juiceshop",
        "user": "", "pass": "",
        "scenarios": ROOT / "eval" / "scenarios_juiceshop.yaml",
        # universal oracle (K7) -> tak perlu marker; biarkan None
        "sqli_markers": None, "blind_exists": None, "blind_missing": None,
    },
}


def load_scenarios(target):
    spec = TARGETS[target]
    data = yaml.safe_load(open(spec["scenarios"], encoding="utf-8"))["scenarios"]
    seen, out = set(), []
    for s in data:                    # SEMUA sel (pair dgn Full sweep16: bWAPP 19 / Juice 9)
        sid = str(s["id"])
        if sid not in seen:
            seen.add(sid); out.append(s)
    return out


def reachable(url, timeout=4.0):
    try:
        requests.get(url, timeout=timeout); return True
    except Exception:
        return False


def _apply_markers(spec):
    if spec["sqli_markers"]:
        set_sqli_row_markers(spec["sqli_markers"])
    if spec["blind_exists"] or spec["blind_missing"]:
        set_blind_markers(exists=spec["blind_exists"], missing=spec["blind_missing"])


def rid_for(target, sid):
    return f"baseext-{target}-{sid}-s{SEED}"


def run_one(target, sid):
    """Satu sel di subprocess terisolasi. Marker diset DI SINI (state global orchestrator,
    jadi bersih per-subprocess). Orchestrator menulis runs/<rid>/report.json."""
    spec = TARGETS[target]
    _apply_markers(spec)
    s = next(x for x in load_scenarios(target) if str(x["id"]) == sid)
    scen = Scenario.from_dict(s)
    cfg = load_config(ROOT / "config.yaml")
    cfg["components"] = dict(BASE)
    cfg["bandit"] = {"store_path": f"data/bandit/base_{target}.joblib"}  # bandit OFF; path harmless
    cfg["model"]["name"] = MODEL
    cfg["model"]["seed"] = SEED
    cfg["target"]["base_url"] = spec["base_url"]
    cfg["target"]["app"] = spec["app"]
    cfg["target"]["login_user"] = spec["user"]
    cfg["target"]["login_pass"] = spec["pass"]
    Orchestrator(cfg, scen, run_id=rid_for(target, sid)).run()


def _row(sid, level, rep):
    ok = bool(rep.get("success"))
    return ok, [sid, level, int(ok), rep.get("iterations_used"),
                round(rep.get("wall_clock_s", 0)), rep.get("tokens_used", ""),
                rep.get("finish_reason", "")]


def main(target):
    spec = TARGETS[target]
    scens = load_scenarios(target)
    print(f"Base ({target}) pure-ReAct: {len(scens)} scenarios x seed {SEED} ({MTAG}) "
          f"[subprocess-isolated]", flush=True)

    if not reachable(spec["base_url"]):
        print(f"  PRE-FLIGHT FAIL: {spec['base_url']} tak terjangkau -- deploy target dulu "
              f"(bWAPP via Apache / Juice Shop container). Abort.", flush=True)
        sys.exit(2)
    print(f"  pre-flight OK: {spec['base_url']} reachable", flush=True)

    out_csv = ROOT / "results" / f"base_{target}.csv"
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    f = open(out_csv, "w", newline="", encoding="utf-8")
    w = csv.writer(f)
    w.writerow(["scenario", "level", "success", "iters", "wall", "tokens", "finish_reason"])

    npass = 0
    for s in scens:
        sid = str(s["id"]); level = s.get("level")
        rd = ROOT / "runs" / rid_for(target, sid)
        rep_path = rd / "report.json"

        if rep_path.exists():
            try:
                ok, row = _row(sid, level, json.loads(rep_path.read_text(encoding="utf-8")))
                w.writerow(row); f.flush(); npass += int(ok)
                print(f"  SKIP {sid} (done, success={ok})", flush=True); continue
            except Exception as e:
                print(f"  {sid}: report.json unreadable ({e}); re-run", flush=True)
                shutil.rmtree(rd, ignore_errors=True)
        if rd.exists():
            shutil.rmtree(rd, ignore_errors=True)

        try:
            subprocess.run([sys.executable, str(Path(__file__).resolve()), "--one", target, sid],
                           cwd=str(ROOT), timeout=CELL_TIMEOUT_S, env={**os.environ})
        except subprocess.TimeoutExpired:
            print(f"  [{sid}] TIMEOUT (subprocess killed @ {CELL_TIMEOUT_S}s)", flush=True)
        except Exception as e:  # noqa: BLE001
            print(f"  [{sid}] SUBPROC_ERR {type(e).__name__}: {str(e)[:80]}", flush=True)

        if rep_path.exists():
            try:
                ok, row = _row(sid, level, json.loads(rep_path.read_text(encoding="utf-8")))
            except Exception as e:
                w.writerow([sid, level, 0, "", "", "", f"badjson:{type(e).__name__}"]); f.flush()
                print(f"  [{sid}] report.json corrupt: {e}", flush=True); continue
            w.writerow(row); f.flush(); npass += int(ok)
            print(f"  [{sid}] success={ok} it={row[3]} wall={row[4]}s", flush=True)
        else:
            w.writerow([sid, level, 0, "", "", "", "crash:no_report"]); f.flush()
            print(f"  [{sid}] CRASH no report.json (subprocess died hard)", flush=True)

    f.close()
    print(f"\nBASE_{target.upper()}_DONE: {npass}/{len(scens)} = {npass/len(scens):.0%} "
          f"csv={out_csv}", flush=True)


if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "--one":
        run_one(sys.argv[2], sys.argv[3])
    else:
        ap = argparse.ArgumentParser()
        ap.add_argument("--target", required=True, choices=["bwapp", "juiceshop"])
        a = ap.parse_args()
        main(a.target)
