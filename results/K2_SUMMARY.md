# K2 Summary (R2-4 ablation + R2-5 retry) — honest, no overclaim

> Source of truth = per-cell `runs/<rid>/report.json` (deduped), NOT the raw
> `k2_ablation.csv` (which contains duplicate rows the resume-safe runner re-appended
> for already-finished cells). Dedup file: `k2_ablation_dedup.csv` (699 unique cells).
> q35 (qwen3.5), 39 sweep scenarios × 3 seeds {42,7,123}. OSR = objective-success rate.

## 1. Ablation OSR (deduped)

| config | removed | OSR | ΔSR vs FULL |
|---|---|---|---|
| FULL | — (b8+5) | 100/117 = **85.5%** | — |
| L-RAG | rag off | 100/117 = **85.5%** | +0.0pp |
| L-TLS | tools_mcp off | 90/116 = **77.6%** | **−7.9pp** |
| L-K8 | oast off | 99/116 = **85.3%** | −0.1pp |
| I-RG10 | guardrail off (rag on) | 106/117 = **90.6%** | +5.1pp |
| I-RG00 | rag off + guardrail off | 56/116 = **48.3%** | −37.2pp* |

(116 vs 117 = 1 cell lost to a recurring `xss_dom` `NoneType` crash per config — a code
bug, documented as a limitation, not patched mid-campaign to preserve consistency.)

### Clean, mutually-comparable finding (same pre-resume environment)
FULL, L-RAG, L-TLS, L-K8, I-RG10 all completed BEFORE the pod stopped (consistent ollama
build). Among these:
- **tools_mcp (L-TLS) is the largest single-component drop (−7.9pp), but DESCRIPTIVE only:**
  paired McNemar on the K2 data (116 pairs, FULL 99 / L-TLS 90, discordant 20/11) gives
  **p=0.1496, scenario-cluster CI [−20.51, +3.42] pp — CI crosses zero, not significant.**
  rag (L-RAG) and oast (L-K8) are individually neutral; removing the guardrail alone (I-RG10)
  *raised* OSR by +5.1pp (slightly over-conservative here).
- All point estimates; **no "clear winner" claimed**. (The earlier p=0.754 was the OLD archive
  LOO, not this K2 data — do not use it.)

## 2. 2×2 interaction (rag × guardrail) — CONFOUNDED (old run); RERUN in progress

The first 2×2 run is confounded and is NOT used: I-RG00 ran AFTER a pod restart on a freshly
reinstalled ollama build (canary below shows drift), AND the browser verifier crashed on XSS
cells (missing Playwright libs post-resume → `verify_xss` TargetClosedError → XSS false-fails).
**Both issues fixed; the whole 2×2 is being RE-RUN from scratch** (4 cells × 39 scenarios ×
3 seeds = 468) in ONE consistent environment (ollama 0.40.17 pinned + Playwright libs restored,
verified). **The interaction value is HELD until the clean rerun finishes and is verified — not
claimed here.** The old −42.3pp naive figure is discarded.

## 3. Retry R2-5 (paired fix-retry OFF vs ON, on 10 K1-FULL failures)

| metric | value |
|---|---|
| fix OFF success | 0/10 |
| fix ON success | 0/10 |
| recovered (OFF 0 → ON 1) | **0** |
| F-rule fired (fix ON) | 0/10 |

Honest negative: the fix-retry mechanism recovered none of the 10 hard K1-FULL failures,
and its repair rules never fired. (Also run post-resume → same drift caveat applies; the
0/10-vs-0/10 comparison is itself under drift.)

## 4. Canary (12 K1-FULL successes re-run with fix ON — regression check)

**2/10 valid verdicts stayed successful; 2 of the 12 are MISSING** (xss_dom `NoneType` crash,
no verdict). "2/12" is a sensitivity figure treating the 2 missing as failures. Canary selection:
`random.sample` seed 0 over the sorted K1-FULL successes.
The drop is an **observation, not proof of a specific cause** — it is CONSISTENT with environment
drift after the ollama reinstall (seed=42, temp=0.2 set, but cross-build determinism not
guaranteed), but could also reflect noise or the fix-ON path; it is not isolated. Reviewer does
NOT require ON/OFF pairing on the canary (only on the retry cohort).

## Bottom line (for the manuscript)
- Report the **clean single-component ablation** (FULL/L-RAG/L-TLS/L-K8/I-RG10): tools_mcp is
  the main positive single component; rag/oast neutral; guardrail slightly conservative.
- **Do NOT report the 2×2 interaction or I-RG00** until re-run in a consistent environment.
- Report retry as an honest **null result** (no recovery), with the drift caveat.
- Disclose the mid-experiment environment change and the `xss_dom` crash as limitations.

Held items (need a clean same-environment GPU run): I-RG00 + FULL reference re-run; optional
re-run of the full 2×2 and retry cohort in one environment.
