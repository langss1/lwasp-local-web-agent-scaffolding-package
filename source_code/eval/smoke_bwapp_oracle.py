"""P4 oracle smoke for bWAPP (plan14.md) -- validate the PORTED HTTP oracles
before spending any agent runs.

For each HTTP-marker vuln class (sqli, sqli_blind, cmdi, fi) it sends, via the
real BwappClient, a canonical EXPLOIT payload and a BENIGN value, then runs the
SAME interpret_* oracle the orchestrator uses, and checks:
    exploit -> success=True   AND   benign -> success=False
Any mismatch means a wrong endpoint / field / marker (a TODO-confirm) -- fix
those in scenarios_bwapp.yaml / bwapp_client.py / run_bwapp_sweep.py before the
sweep. XSS is browser-verified (app-agnostic) and is exercised in the real run,
so it is not part of this HTTP-level smoke.

Run ON the pod (venv), AFTER bWAPP is deployed:
    python eval/smoke_bwapp_oracle.py
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from src.action.bwapp_client import BwappClient
from src.orchestrator import (interpret_sqli_response, interpret_blind_sqli_response,
                              interpret_cmdi_response, interpret_fi_response,
                              set_sqli_row_markers, set_blind_markers)
from eval.run_bwapp_sweep import (BWAPP_BASE_URL, BWAPP_USER, BWAPP_PASS,
                                  BWAPP_SQLI_ROW_MARKERS, BWAPP_BLIND_EXISTS,
                                  BWAPP_BLIND_MISSING)

ALLOW = ["localhost", "127.0.0.1"]

# (class, endpoint, param, method, extra, exploit_value, benign_value)
PROBES = [
    ("sqli",       "sqli_1.php", "title", "GET",  {"action": "search"}, "' OR '1'='1' -- ", "Iron Man"),
    ("cmdi",       "commandi.php", "target", "POST", {"form": "submit"}, "127.0.0.1; id", "127.0.0.1"),
    ("fi",         "rlfi.php",   "language", "GET", {"action": "go"}, "/etc/passwd", "en"),
]


def client(level="low"):
    c = BwappClient(base_url=BWAPP_BASE_URL, allowlist=ALLOW,
                    username=BWAPP_USER, password=BWAPP_PASS, security_level=level)
    c.login()
    return c


def run_inband():
    set_sqli_row_markers(BWAPP_SQLI_ROW_MARKERS)
    ok_all = True
    c = client("low")
    for cls, ep, param, method, extra, eploit, benign in PROBES:
        er = c.send_param(method, ep, param, eploit, extra_params=extra)
        br = c.send_param(method, ep, param, benign, extra_params=extra)
        if cls == "sqli":
            ev = interpret_sqli_response(er.body)["success"]; bv = interpret_sqli_response(br.body)["success"]
        elif cls == "cmdi":
            ev = interpret_cmdi_response(er.body)["success"]; bv = interpret_cmdi_response(br.body)["success"]
        elif cls == "fi":
            ev = interpret_fi_response(er.body)["success"]; bv = interpret_fi_response(br.body)["success"]
        good = ev and not bv
        ok_all &= good
        print(f"  [{cls:11}] exploit_success={ev}  benign_success={bv}  -> "
              f"{'OK' if good else 'FAIL (check endpoint/marker/field)'}  "
              f"(http {er.status_code}/{br.status_code})")
    return ok_all


def run_blind():
    # boolean-blind: TRUE condition vs FALSE condition should differ
    set_blind_markers(exists=BWAPP_BLIND_EXISTS, missing=BWAPP_BLIND_MISSING)
    c = client("low")
    # sqli_6.php is POST; the %...% LIKE wrapper is closed with '#'. TRUE matches a
    # real movie (rows + IMDb link) vs FALSE (no rows -> "No movies were found!").
    pt = "Iron%' AND '1'='1'#"
    pf = "Iron%' AND '1'='2'#"
    t = c.send_param("POST", "sqli_6.php", "title", pt, extra_params={"action": "search"})
    f = c.send_param("POST", "sqli_6.php", "title", pf, extra_params={"action": "search"})
    v = interpret_blind_sqli_response(t.body, pt)
    differ = t.body != f.body
    print(f"  [sqli_blind ] true!=false_response={differ}  oracle_signal={v.get('success')}  "
          f"(http {t.status_code}/{f.status_code})")
    return differ


def main():
    print("== bWAPP oracle smoke ==")
    try:
        ok = run_inband()
    except Exception as e:
        print(f"  in-band probes ERROR: {type(e).__name__}: {e}"); ok = False
    try:
        ok &= run_blind()
    except Exception as e:
        print(f"  blind probe ERROR: {type(e).__name__}: {e}"); ok = False
    print("SMOKE_RESULT:", "ALL_OK" if ok else "NEEDS_FIX (adjust TODO-confirm items, re-run)")


if __name__ == "__main__":
    main()
