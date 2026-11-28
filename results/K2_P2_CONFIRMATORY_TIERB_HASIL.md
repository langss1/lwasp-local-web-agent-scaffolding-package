# P2 — Strict Confirmatory on bWAPP (R2-B / R1-E / R1-B) — Results

**Protocol (rigorous):** pre-registration FROZEN before any scoring (`freeze_sha=b80a1a5828d08d9f`), interleaved identical-state design (per unit: reset bWAPP to clean snapshot → run all 3 arms back-to-back on the SAME snapshot, rotating arm order), crash-isolated per-cell subprocess, matched stopping contract (15 iter / 1500 s, identical for every arm). Independent app: Full was never tuned on bWAPP.
**Scope:** 9 scenarios (low+medium across sqli/cmdi/fi/xss, chosen for differentiation room) × model q25 × seeds {42,7,123} × 3 arms = **81 cells, all valid (0 invalid, 0 missing)**.
Artifacts: `results/confirmatory_tierB_result.json`, `prereg_confirmatory_tierB.json`, `confirmatory_tierB_reset_log.csv`.

> Validity note — a first P2 attempt (held-out medium/high tier) returned an all-zero floor; root-caused to a config bug (`target.app` defaulted to `dvwa`, so bWAPP URLs were driven with DVWA app-logic/oracle). Fixed (`app=bwapp`), re-validated across families via 12 smoke cells (sqli_low ✓, cmdi_medium ✓, xss_reflected_low ✓ verify 2.6 s, xss_stored_low ✓ verify 11 s), then this tier re-run clean. The medium/high tier is retained separately as a generalization-ceiling probe (uniform floor: q25 cannot exploit the harder unseen variants at any scaffolding level).

## Table — OSR per arm (objective-success, oracle-verified)

| Arm | OSR | n |
|---|---|---|
| base (HTTP-only) | **33.3%** | 9/27 |
| simple_tooled (tools+browser, orchestration OFF) | **59.3%** | 16/27 |
| full (all scaffolding ON) | **63.0%** | 17/27 |

## Table — Paired contrasts (McNemar exact, scenario-clustered 95% CI, Holm for orchestration family)

| Contrast | Δ OSR | discordant (b/c) | McNemar p | Holm p | 95% CI (pp) |
|---|---|---|---|---|---|
| base → simple_tooled (**access/opportunity**) | +25.9 pp | 1 / 8 | 0.039 | **0.078** | [−3.7, 55.6] |
| simple_tooled → full (**orchestration, opportunity-matched**) | +3.7 pp | 0 / 1 | **1.0** | 1.0 | [0.0, 11.1] |
| base → full (**total package**) | +29.6 pp | 1 / 9 | **0.0215** | — | [0.0, 59.3] |

## Honest findings
1. **The total package beats the bare baseline**: base→full +29.6 pp, McNemar p = 0.0215 (raw).
2. **The lever is tool/browser access, not orchestration**: base→simple_tooled is +25.9 pp (large), while simple_tooled→full is only +3.7 pp with p = 1.0 — orchestration adds essentially nothing once access is matched.
3. **After multiple-comparison correction the access contrast is marginal** (Holm p = 0.078), and **orchestration is firmly non-significant** (Holm p = 1.0). At this power the rigorous protocol **does not confirm an orchestration benefit**.
4. **Opportunity parity (R1-B):** for browser-evidence classes (xss_*), `base` (HTTP-only) cannot run the verifier and so cannot be credited — the differentiation is concentrated there. The orchestration claim is therefore read only from simple_tooled→full (identical evidence opportunity); base→full is reported as the total-package contrast, not as orchestration.

## Consistency with the rest of the paper
Reproduces, under a pre-registered + interleaved protocol, the same honest headline as the K1 interleaved run (full vs simple not significant), the cross-app confirm3 (access p=0.016 sig, orchestration p=0.375 n.s.), and the q25 2×2 interaction (RAG benefit concentrated in XSS, not significant). The consistent message: **capability/tool-access is the bottleneck; scaffolding orchestration is not confirmed to lift objective success at this scale.**
