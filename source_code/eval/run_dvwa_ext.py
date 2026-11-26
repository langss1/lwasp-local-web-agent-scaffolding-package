"""DVWA Full-EXTENDED run (b8 + 5 komponen plan16) -- 39 scenarios, seed 42, qwen3.5.

Tujuan tunggal: apakah 5 komponen baru (K4 recon, K7 oracle-universal, K8 OAST,
K12 context-summarizer, K14 bandit) MENOLONG di DVWA dibanding scaffold paper (b8).
Pembanding (sudah ada, tidak di-run ulang): Full-paper q35/L3/seed42 = 32/39.

Beda dari paper Full HANYA +5 komponen (web_search tetap OFF di DVWA karena
web_search_app4_only). Base model FROZEN. Oracle STRICT. fix_retry = default config
(samakan dengan faktorial L3), bukan dimatikan seperti ablation.

Robust/unattended: tiap sel dijalankan di SUBPROCESS sendiri (`--one <sid>`) supaya
crash keras yang tak bisa ditangkap try/except (mis. segfault chromium/playwright saat
VERIFY, yang pernah membunuh driver di tengah run) hanya membunuh subprocess sel itu --
driver mencatat 'crash:no_report' dan lanjut ke sel berikutnya.

Resume-safe: sel yang report.json-nya sudah ada dilewati TAPI tetap dibaca ulang ke CSV
(jadi CSV selalu lengkap 39 baris walau di-restart). report.json ditulis orchestrator
untuk sukses MAUPUN gagal/exhausted; hanya crash keras yang tak menghasilkannya.

Jalankan DI POD, venv:  .venv/bin/python eval/run_dvwa_ext.py
"""
import csv
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

MTAG, MODEL, SEED, PREFIX = "q35", "qwen3.5:latest", 42, "dvext"
CELL_TIMEOUT_S = 900  # hard cap per sel; sqli exhaust ~190s, VERIFY+browser << ini

# Full-EXTENDED = paper Full (b8) + 5 komponen plan16. IDENTIK dgn run_smoke_plan16.FULL.
FULL_EXT = {
    "pure_mode": False,
    "working_memory": True, "rag": True, "reflection": True, "guardrail": True,
    "state_graph": True, "tools_mcp": True, "sandbox": True, "auto_verify_xss": True,
    "long_term_memory": False, "web_search": True, "web_search_fallback": False,
    "web_search_app4_only": True, "skills": False,
    "eyes_ml": True, "progress_protection": True, "use_promise": True,
    # +5 komponen baru
    "recon": True, "oracle_universal": True, "oast": True,
    "context_summarizer": True, "bandit": True,
}

# 39 scenario PERSIS seperti faktorial q35/L3/seed42 (non-captcha), biar paired-comparable
# ke Full-paper 32/39. Sama dgn SWEEP_SCENARIOS di eval/run_ablation_loo.py.
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
    """Pollution guard: restore admin creds before each run (same as ablation runner)."""
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
    seen, sc = set(), []
    for s in data:
        sid = str(s["id"])
        if sid in SWEEP_SCENARIOS and sid not in seen:   # first occurrence, like the sweep
            seen.add(sid)
            sc.append(s)
    missing = SWEEP_SCENARIOS - seen
    assert not missing, f"scenarios.yaml missing: {sorted(missing)}"
    assert len(sc) == 39, f"expected 39, got {len(sc)}"
    return sc


def _row_from_report(sid, level, rep):
    ok = bool(rep.get("success"))
    return ok, [sid, level, int(ok), rep.get("iterations_used"),
                round(rep.get("wall_clock_s", 0)), rep.get("tokens_used", ""),
                rep.get("peak_vram_mb", ""), rep.get("finish_reason", "")]


def run_one(sid):
    """Jalankan SATU skenario (dipanggil sebagai subprocess terisolasi). Orchestrator
    menulis runs/<rid>/report.json di akhir .run(); kita tidak perlu return apa pun."""
    from src.orchestrator import Orchestrator, Scenario, load_config
    s = next(x for x in scenarios() if str(x["id"]) == sid)
    rid = f"{PREFIX}-{sid}-s{SEED}"
    scen = Scenario.from_dict(s)
    cfg = load_config(ROOT / "config.yaml")
    cfg["components"] = dict(FULL_EXT)
    cfg["bandit"] = {"store_path": f"data/bandit/{PREFIX}_dvwa.joblib"}
    cfg["model"]["name"] = MODEL
    cfg["model"]["seed"] = SEED
    reset_dvwa_state()
    Orchestrator(cfg, scen, run_id=rid).run()


def main():
    scens = scenarios()
    print(f"DVWA Full-EXTENDED: 1 config x {len(scens)} scenarios x seed {SEED} "
          f"({MTAG}) = {len(scens)} runs [subprocess-isolated]", flush=True)

    out_csv = ROOT / "results" / "dvwa_ext.csv"
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    f = open(out_csv, "w", newline="", encoding="utf-8")
    w = csv.writer(f)
    w.writerow(["scenario", "level", "success", "iters", "wall", "tokens",
                "peak_vram_mb", "finish_reason"])

    npass = 0
    for s in scens:
        sid = str(s["id"])
        level = s.get("level")
        rid = f"{PREFIX}-{sid}-s{SEED}"
        rd = ROOT / "runs" / rid
        rep_path = rd / "report.json"

        if rep_path.exists():
            # sudah jadi (sukses/gagal) -> baca ulang ke CSV, jangan run lagi
            try:
                ok, row = _row_from_report(sid, level, json.loads(rep_path.read_text(encoding="utf-8")))
                w.writerow(row); f.flush()
                npass += int(ok)
                print(f"  SKIP {sid} (done, success={ok})", flush=True)
                continue
            except Exception as e:  # report.json korup -> jalankan ulang
                print(f"  {sid}: report.json unreadable ({e}); re-running", flush=True)
                shutil.rmtree(rd, ignore_errors=True)

        # partial dir (crash sebelumnya, tanpa report.json) -> bersihkan dulu
        if rd.exists():
            shutil.rmtree(rd, ignore_errors=True)

        # jalankan sel di subprocess terisolasi
        try:
            subprocess.run([sys.executable, str(Path(__file__).resolve()), "--one", sid],
                           cwd=str(ROOT), timeout=CELL_TIMEOUT_S,
                           env={**os.environ})
        except subprocess.TimeoutExpired:
            print(f"  [{sid}] TIMEOUT (subprocess killed @ {CELL_TIMEOUT_S}s)", flush=True)
        except Exception as e:  # noqa: BLE001
            print(f"  [{sid}] SUBPROC_ERR {type(e).__name__}: {str(e)[:80]}", flush=True)

        # baca hasil dari report.json (subprocess crash keras -> tak ada file)
        if rep_path.exists():
            try:
                ok, row = _row_from_report(sid, level, json.loads(rep_path.read_text(encoding="utf-8")))
            except Exception as e:
                w.writerow([sid, level, 0, "", "", "", "", f"badjson:{type(e).__name__}"]); f.flush()
                print(f"  [{sid}] report.json corrupt: {e}", flush=True)
                continue
            w.writerow(row); f.flush()
            npass += int(ok)
            print(f"  [{sid}] success={ok} it={row[3]} wall={row[4]}s", flush=True)
        else:
            w.writerow([sid, level, 0, "", "", "", "", "crash:no_report"]); f.flush()
            print(f"  [{sid}] CRASH no report.json (subprocess died hard)", flush=True)

    f.close()
    print(f"\nDVWA_EXT_DONE: {npass}/{len(scens)} = {npass/len(scens):.0%} "
          f"(ref Full-paper q35 s42 = 32/39 = 82%). csv={out_csv}", flush=True)


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--one":
        run_one(sys.argv[2])
    else:
        main()
