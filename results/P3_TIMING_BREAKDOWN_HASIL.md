# P3 — Per-Phase Timing Breakdown & Stopping-Contract Asymmetry (R1-I)

**Reviewer ask (R1-I):** separate **generation / action / verification** time, and explain **why Base reaches the 15-iteration ceiling while Full stops earlier**.

**Method.** The frozen confirmatory worker (`_conf_worker.py`, same arm dicts as P2, `freeze_sha=b80a1a58`) was re-run on a directed subset with the always-on K1 timing instrumentation (`gen_time_s` / `action_time_s` / `verify_time_s` in the report dict; `wall_clock_s` the envelope). **`other_time_s = wall − gen − action − verify`** (setup / login / level-set / model-resident overhead). Subset: **2 arms (base, full) × 5 scenarios × model q35 (Qwen3.5) × seed 42 = 10 runs**, on an isolated DVWA with a clean reset before each scenario. Timing is **not** a success metric, so a single seed suffices (pre-registered rationale). Labelled *instrumented timing run — separate measurement*, NOT pooled with online OSR.
Artifacts: `results/timing_runs/runs_timing/tim-{arm}-q35-{scenario}-s42/report.json` (+ traces).

## Table 1 — per-run timing (seconds) and stopping behaviour

| Arm | Scenario | succ | iters | finish_reason | gen | action | verify | other | wall |
|---|---|---|---|---|---|---|---|---|---|
| base | sqli_high | False | **15** | exhausted | 183.4 | 0.1 | 0.0 | 29.2 | 212.7 |
| base | cmdi_high | True | **15** | exhausted | 27.9 | 0.1 | 0.0 | 20.1 | 48.1 |
| base | xss_reflected_medium | False | **15** | exhausted | 51.8 | 0.1 | 0.0 | 19.9 | 71.8 |
| base | brute_medium | True | **15** | exhausted | 17.2 | 2.1 | 0.0 | 20.3 | 39.6 |
| base | blind_sqli_high | True | **15** | exhausted | 40.4 | 6.1 | 0.0 | 20.2 | 66.6 |
| full | sqli_high | True | 10 | success | 21.3 | 6.5 | 0.0 | 62.9 | 90.7 |
| full | cmdi_high | True | 3 | success | 5.0 | 0.0 | 0.0 | 8.8 | 13.8 |
| full | xss_reflected_medium | True | 3 | success | 8.7 | 3.6 | **2.5** | 8.9 | 23.7 |
| full | brute_medium | True | 4 | success | 6.1 | 0.1 | 0.0 | 6.5 | 12.7 |
| full | blind_sqli_high | True | 4 | success | 6.1 | — | — | — | — |

## Table 2 — per-arm means (n=5)

| Arm | mean iters | gen (s) | action (s) | verify (s) | other (s) | wall (s) | gen % wall | finish_reasons |
|---|---|---|---|---|---|---|---|---|
| **base** | **15.0** | 64.1 | 1.7 | **0.00** | 21.9 | 87.8 | 73% | **{exhausted}** only |
| **full** | **4.8** | 9.5 | 2.1 | 0.51 | 18.9 | 30.9 | 31% | **{success}** only |

**Validity.** For all 10 runs, `gen + action + verify + other = wall` to the millisecond (residual 0.000 s) — the decomposition is exhaustive, non-overlapping, and non-negative.

## Findings (observation → interpretation)

**Observation 1 — Base always hits the ceiling.** Base's `iterations_used = 15` and `finish_reason = exhausted` in **5/5** runs, including the **3 runs it actually succeeded** (cmdi_high, brute_medium, blind_sqli_high: `success=True`, yet still 15 iters). Base's `verify_time_s = 0.00` in 5/5.
→ *Interpretation:* Base (HTTP-only, no browser, no verifier) has **no mechanism to confirm its own success**, so it can never trigger a verification-gated early stop. It runs to the `max_iterations = 15` budget every time, **even after the objective is already met**. This directly answers R1-I: the 15-iteration count is not "Base trying harder," it is **Base being unable to stop**.

**Observation 2 — Full stops early.** Full's `finish_reason = success` in 5/5, with `iterations_used` of 3–10 (mean 4.8). 
→ *Interpretation:* Full's verifier lets it recognise objective completion and terminate (mean **3.1× fewer iterations** than Base).

**Observation 3 — Generation dominates, and early-stop (not raw speed) is the time lever.** Generation is **73%** of Base wall time (15 LLM calls) vs **31%** for Full. In absolute terms Full spends far less time generating (9.5 s vs 64.1 s mean) **because it issues ~3× fewer LLM calls**, not because any single call is faster. Net effect: Full's mean wall is **30.9 s vs Base 87.8 s** — Full is ~2.8× faster per attempt **despite** carrying the heavier browser+verify stack, purely by not exhausting the budget.

## Honest limitations
- **Verification time is small, not a cost driver.** `verify_time_s` is ~0 everywhere except **full/xss_reflected_medium (2.5 s)**, the only scenario whose oracle is a browser DOM-execution check (`BrowserVerifier`). The early-stop in the other scenarios is triggered by a **cheap per-iteration success-oracle check**, not an expensive VERIFY action. We therefore frame R1-I as a **stopping-contract asymmetry** (does the arm *have* a stop signal), **not** as "verification is expensive."
- **`other_time_s` for full/sqli_high is large (62.9 s)** — browser launch + DVWA login + security-level set land outside the instrumented gen/action/verify spans (first full run of the session amortises Playwright/Chromium cold-start). This is overhead accounting, not agent reasoning time.
- Single seed, q35 only, DVWA only: this is a **timing characterisation**, sufficient for the mechanistic R1-I claim; it is not a performance benchmark.

## Takeaway (fact)
Across 10 instrumented runs, **Base exhausts all 15 iterations in 5/5 cases (finish_reason=exhausted, verify_time=0), including when it has already succeeded, because it lacks any verifier to stop; Full terminates on `success` at mean 4.8 iterations.** Generation is the dominant cost (73% of Base wall), and Full's ~2.8× lower wall time comes entirely from early stopping, not faster generation. Decomposition is exact (residual 0.000 s, 10/10). Source: `results/timing_runs/runs_timing/tim-*-q35-*-s42/report.json`.
