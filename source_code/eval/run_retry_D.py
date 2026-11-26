"""plan13 FIX-RETRY runner (D condition only). Run this ONLY after the q25 sweep
finishes. It re-runs each FAILED D run (q35 / L3 / system) WITH the 5 anti-waste
fixes enabled (PA_FIX_RETRY=1), under a DISTINCT run_id prefix so the original
failing report is preserved for comparison. captcha_* is excluded (reCAPTCHA is
out-of-scope / unsolvable). A canary sample of currently-PASSING D runs is also
re-run with the fixes on, to detect any NEW regression the shared-loop changes
might introduce.

  retry  -> prefix "f40fix"     (the 20 failures, fix ON)
  canary -> prefix "f40fixcan"  (sample of passers, fix ON -- must still pass)

Usage (on the pod, inside the venv):  python eval/run_retry_D.py
Nothing here touches the original f40-* runs."""
import os, sys, subprocess, glob, json, random
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNS = ROOT / "runs"
PY = sys.executable
MODEL = "qwen3.5:latest"
MTAG = "q35"
CANARY_N = 5
random.seed(0)


def d_reports():
    rows = []
    for p in glob.glob(str(RUNS / "f40-q35-*-L3-*" / "report.json")):
        try:
            d = json.load(open(p))
        except Exception:
            continue
        b = Path(p).parent.name                       # f40-q35-<scn>-L3-s<seed>
        scn = b.split("f40-q35-")[1].rsplit("-L3-", 1)[0]
        seed = b.rsplit("-s", 1)[1]
        rows.append((scn, seed, bool(d.get("success"))))
    return rows


def run_one(scn, seed, prefix, env):
    print(f"  [{prefix}] {scn} s{seed}", flush=True)
    subprocess.run([PY, str(ROOT / "eval" / "one_run_seed.py"),
                    MTAG, MODEL, "L3", scn, str(seed), prefix], env=env)


def main():
    rows = d_reports()
    fails = sorted((s, sd) for s, sd, ok in rows if (not ok) and not s.startswith("captcha"))
    passes = sorted((s, sd) for s, sd, ok in rows if ok)
    canary = sorted(random.sample(passes, min(CANARY_N, len(passes)))) if passes else []

    print(f"RETRY targets (fix ON): {len(fails)} failed D (captcha excluded)")
    for s, sd in fails:
        print(f"    - {s} s{sd}")
    print(f"CANARY (regression check, fix ON): {len(canary)} passing D")

    env = dict(os.environ)
    env["PA_FIX_RETRY"] = "1"

    for scn, seed in fails:
        run_one(scn, seed, "f40fix", env)
    for scn, seed in canary:
        run_one(scn, seed, "f40fixcan", env)

    print("RETRY_DONE")


if __name__ == "__main__":
    main()
