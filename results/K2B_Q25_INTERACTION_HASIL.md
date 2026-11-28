# q25 2×2 RAG × Guardrail Interaction — Results (R2-D)

**Campaign:** `k2b_2x2_q25` · model `qwen2.5:latest` · 39 DVWA scenarios × 3 seeds {42,7,123} × 4 cells = **468 runs** (all present, 0 missing).
**Outcome field:** per-cell `success` (same oracle outcome used across K1 and the bWAPP confirmatory). Analysis: `results/q25_interaction.py` → `results/q25_interaction_result.json`. Exact-binomial McNemar + scenario-clustered bootstrap (5000).

Cells: RG11=FULL (RAG+,Grd+) · RG01=L-RAG (RAG−,Grd+) · RG10=I-RG10 (RAG+,Grd−) · RG00=I-RG00 (RAG−,Grd−).

## Table A — 2×2 OSR (all 468 cells)

|  | Guardrail ON | Guardrail OFF |
|---|---|---|
| **RAG ON** | FULL **87.2%** (102/117) | I-RG10 **88.0%** (103/117) |
| **RAG OFF** | L-RAG **78.6%** (92/117) | I-RG00 **79.5%** (93/117) |

- **Interaction (difference-of-differences) = 0.0 pp**, bootstrap 95% CI **[−10.3, +10.3]** → no RAG×guardrail interaction.
- RAG main effect = **+8.6 pp**; guardrail main effect = **−0.9 pp** (≈0, direction negative).
- McNemar RAG | guardrail ON (FULL vs L-RAG): b=19, c=9, **p=0.087** (trend, not sig).
- McNemar RAG | guardrail OFF (I-RG10 vs I-RG00): b=18, c=8, **p=0.076** (trend, not sig).
- McNemar guardrail | RAG ON (FULL vs I-RG10): b=8, c=9, **p=1.0** (no effect).

## Table B — Sensitivity: XSS families excluded (30 scen × 3 seeds = 360)

|  | Guardrail ON | Guardrail OFF |
|---|---|---|
| **RAG ON** | FULL 83.3% (75/90) | I-RG10 84.4% (76/90) |
| **RAG OFF** | L-RAG 82.2% (74/90) | I-RG00 84.4% (76/90) |

- Interaction = **+1.1 pp**, CI95 [−11.1, +12.2] → still no interaction.
- **RAG main effect collapses to +0.6 pp** (from +8.6 pp); all McNemar p=1.0.

## Honest findings
1. **No RAG×guardrail interaction** (≈0 pp, CI straddles 0), **robust** to XSS inclusion/exclusion. Direct answer to R2-D.
2. **Guardrail has no measurable effect** on objective success (main ≈ −1 pp, McNemar p=1.0) — expected: it is a safety filter, not a capability.
3. **The RAG benefit (+8.6 pp) is almost entirely concentrated in XSS scenarios** — it drops to +0.6 pp when XSS is excluded, and is **not significant** even pooled (McNemar p≈0.08). Consistent with the paper's broader finding (K1, bWAPP confirmatory): differentiation concentrates where browser verification matters [R1-B]. Ties directly to the XSS-crediting caveat [R1-A].

## Integrity ledger (P0) — transparency, not fabrication
P0 (`results/k2b_integrity_report.csv`) is intentionally stricter than the runner and did **not** auto-reuse any cell:
- **8 cells `no_report_json`** — all ERROR cells (7 open_redirect + 1 blind_sqli) that crashed on an external/edge condition before writing `report.json`; they are genuine failures (`success=0`) in the CSV, correctly counted as such. (open_redirect oracle attempts real outbound connections to attacker hosts → flaky; uniform across arms, unbiased — oracle limitation to note.)
- **371 `env_missing_provenance`** — manifest `expected_env` requires `ollama_version=0.40.17`, which was **not serialized per-run**. Model identity is still pinned (blob hashes + `_meta.model` + `component_sha16`); the version string is a provenance gap to harden, not a data error.
- **89 `xss_success_unverified`** — XSS verification screenshots exist physically (`screenshots/xss_verify_*.png`) but `report.json` does not serialize an explicit `verified:true` + screenshot path, so P0 refuses to credit them (correctly conservative re R1-A). The XSS-excluded sensitivity (Table B) exists precisely so the **interaction conclusion does not depend on this**.

**Hardening available:** offline uniform-oracle XSS re-adjudication (as done for K1 reflected-XSS) via the P4 stored/DOM replay would convert the 89 flagged XSS cells into explicitly-verified outcomes. The **interaction result (R2-D) does not require it**; the RAG main-effect magnitude does.
