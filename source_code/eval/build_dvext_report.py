"""Build report/DVWA_EXTENDED.html (self-contained, screenshots base64-embedded) dari
dvext-<sid>-s42 runs (DVWA Full-EXTENDED, 1 seed). Format = report DVWA lama (per-sel:
tabel langkah + screenshot + verdict) + KOLOM BANDING per-skenario vs Full-paper
(f40-q35-<sid>-L3-s42): menolong / merugikan / sama. Agregat Full-ext X/39 vs 32/39.

Jujur: oracle STRICT (tak disentuh), base FROZEN. K7 oracle-universal bagian paket
scaffold-baru; oracle DVWA tetap pakai interpret bawaan + universal sbg sinyal kuat.
Usage (lokal, setelah scp hasil): python eval/build_dvext_report.py
"""
import base64
import html
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SEED = 42
RUNS = ROOT / "runs"
OUT_HTML = ROOT / "report" / "DVWA_EXTENDED.html"
OUT_MD = ROOT / "report" / "DVWA_EXTENDED.md"

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


def _ordered_scenarios():
    data = yaml.safe_load(open(ROOT / "eval" / "scenarios.yaml", encoding="utf-8"))["scenarios"]
    seen, out = set(), []
    for s in data:
        sid = str(s["id"])
        if sid in SWEEP_SCENARIOS and sid not in seen:
            seen.add(sid)
            out.append((sid, s.get("level")))
    return out


def load_run(rid):
    d = RUNS / rid
    rep = d / "report.json"
    if not rep.exists():
        return None
    try:
        r = json.loads(rep.read_text(encoding="utf-8"))
    except Exception:
        return None
    tr = d / "trace.jsonl"
    r["_trace"] = [json.loads(l) for l in open(tr, encoding="utf-8") if l.strip()] if tr.exists() else []
    ss = d / "screenshots"
    r["_ss"] = sorted(str(p) for p in ss.glob("*.png")) if ss.exists() else []
    return r


def baseline_success(sid):
    """Full-paper q35/L3/seed42 outcome for the paired comparison. None if run absent."""
    r = load_run(f"f40-q35-{sid}-L3-s{SEED}")
    if r is None:
        return None
    return bool(r.get("success"))


def b64img(path, cap=600_000):
    try:
        data = Path(path).read_bytes()
        if len(data) > cap:
            return None
        return "data:image/png;base64," + base64.b64encode(data).decode()
    except Exception:
        return None


def esc(x):
    return html.escape(str(x))


def winning_signal(trace):
    for e in reversed(trace):
        o = e.get("observation", {}) or {}
        if o.get("success"):
            return str(o.get("signal", ""))[:300]
    return ""


def cmp_mark(ext_ok, base_ok):
    if base_ok is None:
        return ("?", "baseline absen")
    if ext_ok and not base_ok:
        return ("MENOLONG", "ext PASS, paper FAIL")
    if not ext_ok and base_ok:
        return ("MERUGIKAN", "ext FAIL, paper PASS")
    return ("sama", "PASS=PASS" if ext_ok else "FAIL=FAIL")


def main():
    scen = _ordered_scenarios()
    cells = []
    ext_pass = base_pass = 0
    help_n = hurt_n = same_n = unk_n = 0
    for sid, lvl in scen:
        r = load_run(f"dvext-{sid}-s{SEED}")
        ext_ok = bool(r and r.get("success"))
        base_ok = baseline_success(sid)
        ext_pass += int(ext_ok)
        base_pass += int(bool(base_ok))
        mark, why = cmp_mark(ext_ok, base_ok)
        help_n += mark == "MENOLONG"
        hurt_n += mark == "MERUGIKAN"
        same_n += mark == "sama"
        unk_n += mark == "?"
        cells.append((sid, lvl, ext_ok, base_ok, mark, why, r))

    n = len(scen)

    # ---- markdown ----
    md = [f"# DVWA Full-EXTENDED (b8+5) vs Full-paper (b8) — seed {SEED}, qwen3.5", "",
          f"- Full-EXTENDED: **{ext_pass}/{n} = {ext_pass/n:.0%}**",
          f"- Full-paper (baseline): **{base_pass}/{n} = {base_pass/n:.0%}**",
          f"- Per-skenario: ✅menolong **{help_n}** · ❌merugikan **{hurt_n}** · ➖sama **{same_n}** · ?baseline-absen **{unk_n}**",
          "", "| skenario | lvl | ext | paper | verdikt |", "|---|---|---|---|---|"]
    for sid, lvl, e, b, mark, why, r in cells:
        md.append(f"| {sid} | {lvl} | {'PASS' if e else 'FAIL'} | "
                  f"{'PASS' if b else ('FAIL' if b is not None else '?')} | {mark} |")
    OUT_MD.write_text("\n".join(md), encoding="utf-8")

    # ---- HTML ----
    H = ["<!doctype html><html><head><meta charset='utf-8'><title>DVWA Extended</title>",
         "<style>body{font:14px/1.5 system-ui,Segoe UI,Arial;margin:24px;max-width:1000px;color:#1a1a1a}"
         "h1{font-size:22px}h2{font-size:16px;margin-top:26px;border-top:1px solid #ddd;padding-top:12px}"
         "table{border-collapse:collapse;width:100%;margin:8px 0}th,td{border:1px solid #ccc;padding:4px 7px;"
         "font-size:12.5px;text-align:left;vertical-align:top}th{background:#f3f3f3}"
         ".pass{color:#0a7f28;font-weight:700}.fail{color:#b00020;font-weight:700}"
         ".help{color:#0a7f28;font-weight:700}.hurt{color:#b00020;font-weight:700}.same{color:#555}"
         "img{max-width:520px;border:1px solid #bbb;border-radius:4px;margin:6px 0}"
         "code{background:#f3f3f3;padding:1px 4px;border-radius:3px}</style></head><body>"]
    H.append("<h1>DVWA Full-EXTENDED (b8+5) vs Full-paper (b8)</h1>")
    H.append(f"<p>Scaffold diperluas (b8 + K4/K7/K8/K12/K14), <b>seed {SEED}</b>, qwen3.5 (9B). "
             "Base model FROZEN. Oracle STRICT (interpret bawaan DVWA, tak dilonggarkan). "
             "web_search OFF di DVWA (gated App#4). Pembanding = Full-paper f40-q35-*-L3-s42.</p>")
    H.append("<h2>Agregat</h2><table><tr><th>Kondisi</th><th>OSR</th></tr>"
             f"<tr><td>Full-EXTENDED (b8+5)</td><td class='{'pass' if ext_pass>=base_pass else 'fail'}'>"
             f"{ext_pass}/{n} = {ext_pass/n:.0%}</td></tr>"
             f"<tr><td>Full-paper (b8)</td><td>{base_pass}/{n} = {base_pass/n:.0%}</td></tr></table>")
    H.append(f"<p>Per-skenario: <span class='help'>menolong {help_n}</span> · "
             f"<span class='hurt'>merugikan {hurt_n}</span> · <span class='same'>sama {same_n}</span> · "
             f"?baseline-absen {unk_n}. "
             "<b>Kesimpulan \"menolong\"</b>: Full-EXTENDED &ge; Full-paper &amp; menolong&gt;merugikan.</p>")

    # comparison table
    H.append("<h2>Tabel banding per-skenario</h2><table><tr><th>skenario</th><th>lvl</th>"
             "<th>ext</th><th>paper</th><th>verdikt</th></tr>")
    for sid, lvl, e, b, mark, why, r in cells:
        cls = {"MENOLONG": "help", "MERUGIKAN": "hurt"}.get(mark, "same")
        H.append(f"<tr><td>{esc(sid)}</td><td>{esc(lvl)}</td>"
                 f"<td class='{'pass' if e else 'fail'}'>{'PASS' if e else 'FAIL'}</td>"
                 f"<td>{'PASS' if b else ('FAIL' if b is not None else '?')}</td>"
                 f"<td class='{cls}'>{mark} <span style='color:#888;font-weight:400'>({why})</span></td></tr>")
    H.append("</table>")

    # per-scenario detail
    for sid, lvl, e, b, mark, why, r in cells:
        cls = "pass" if e else "fail"
        H.append(f"<h2>{esc(sid)} <span class='{cls}'>[{'PASS' if e else 'FAIL'}]</span> "
                 f"<span style='font-weight:400;color:#777'>({esc(lvl)}) · vs paper: {mark}</span></h2>")
        if not r:
            H.append("<p>(no run data)</p>")
            continue
        H.append(f"<p>iters={esc(r.get('iterations_used'))} &middot; "
                 f"wall={r.get('wall_clock_s', 0):.0f}s &middot; reason={esc(r.get('finish_reason'))} &middot; "
                 f"tokens={esc(r.get('tokens_used'))}</p>")
        win = winning_signal(r["_trace"])
        if win:
            H.append(f"<p><b>Winning signal:</b> <code>{esc(win)}</code></p>")
        H.append("<table><tr><th>it</th><th>aksi</th><th>endpoint / payload / tool</th><th>hasil</th></tr>")
        for ev in r["_trace"]:
            a = ev.get("action", {}) or {}
            p = a.get("params", {}) or {}
            o = ev.get("observation", {}) or {}
            tgt = f"{p.get('endpoint','') or ''} {p.get('value') or p.get('tool') or ''}".strip()
            res = ("<span class='pass'>OK</span> " if o.get("success") else "") + esc(str(o.get("signal", ""))[:80])
            H.append(f"<tr><td>{esc(ev.get('iteration',''))}</td><td>{esc(a.get('type',''))}</td>"
                     f"<td><code>{esc(tgt[:90])}</code></td><td>{res}</td></tr>")
        H.append("</table>")
        if r["_ss"]:
            uri = b64img(r["_ss"][-1])
            H.append(f"<p style='font-size:12px;color:#777'>screenshots: {len(r['_ss'])} (last shown)</p>")
            if uri:
                H.append(f"<img src='{uri}' alt='{esc(sid)}'>")
    H.append("</body></html>")
    OUT_HTML.write_text("\n".join(H), encoding="utf-8")
    print(f"WROTE {OUT_HTML}")
    print(f"  Full-EXT {ext_pass}/{n}={ext_pass/n:.0%} | Full-paper {base_pass}/{n}={base_pass/n:.0%} "
          f"| help {help_n} hurt {hurt_n} same {same_n} unk {unk_n}")


if __name__ == "__main__":
    main()
