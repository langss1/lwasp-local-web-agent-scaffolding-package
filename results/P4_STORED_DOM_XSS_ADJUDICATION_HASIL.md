# P4 — Stored/DOM XSS Evidence Adjudication by Isolated Replay (R1-A / R1-E)

**Goal (R1-A):** the headline XSS gain concentrates in stored/DOM classes; their credited successes must be verified with an **agent-independent oracle** so they are not crediting artifacts. Reflected XSS was already adjudicated in K1 (`k1_xss_adjudicated.csv`); this covers stored + DOM.

**Method:** for each q25 credited stored/DOM XSS run, the agent's recorded payload (endpoint/param/value from the run trace) is **replayed through `BrowserVerifier.verify_xss`** on an **isolated DVWA** instance (`dvwa_iso`, own database, distinct from the campaign DB `dvwa`). The guestbook is **truncated before every case** so no case inherits another's stored payload (R1-E). Each case records the independent verdict + a screenshot artifact. Labelled *controlled replay — separate measurement*, NOT pooled with online OSR.
Artifacts: `results/k1_stored_dom_adjudicated.csv`, `results/p4_stored_dom_summary.json`, screenshots in `results/p4_artifacts/` (on pod).

## Table — independent re-verification

| Class | Reconfirmed | Rate |
|---|---|---|
| DOM XSS (xss_dom) | 22/27 | 81% |
| Stored XSS (xss_stored) | 18/24 | 75% |
| **Total** | **40/51** | **78%** |

Per scenario: xss_dom_high 6/6, xss_dom_medium 9/10, xss_dom_low 7/11, xss_stored_high 7/10, xss_stored_low 6/8, xss_stored_medium 5/6.

## Findings
1. **78% of credited stored/DOM XSS successes independently reproduce** (real JS execution, screenshot evidence) on a clean isolated instance → the XSS-concentrated gains are **substantially genuine, not crediting artifacts** (R1-A).
2. Combined with the K1 reflected-XSS re-adjudication (base 0→4/6, simple 5/6, full 6/6 under a uniform oracle), XSS crediting is now validated across all three families (reflected + stored + DOM).

## Honest limitations
- The replayed payload is the **last XSS-endpoint payload in each run trace** (a heuristic for the "winning" payload); for the **11 non-reproduced cases** the credited online payload may differ from the one replayed, so these are marked **uncertain** (conservatively NOT counted as confirmed) rather than declared false. This is a lower bound on the true reproduction rate.
- This is a controlled replay (separate measurement); it is reported alongside, not merged into, the online OSR numbers.
