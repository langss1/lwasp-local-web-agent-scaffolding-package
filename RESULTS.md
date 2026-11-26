# Results at a glance — what each number means and where it comes from

Every number below is recomputed by `python scripts/reproduce_analysis.py --check`
from the shipped CSVs (no GPU/network). Success = **Objective Success Rate (OSR)**:
the fraction of valid runs an **independent deterministic oracle** credits from recorded
target effects (SQLi row extraction, headless-browser XSS execution, state-change markers)
— never the agent's own "FINISH" claim.

Three packages:
- **Base** — HTTP requests only (no tools, no browser, no verifier).
- **Simple-Tooled** — Base **+ Action/Verify Layer** (tools, sandbox, browser XSS verifier,
  recon, OAST, universal oracle); **all orchestration OFF**. This is the *access-parity* control.
- **Full (LWASP)** — Simple-Tooled **+ the orchestration bundle** (RAG, guardrail, state-graph,
  progress monitor, backtrack scorer, reflection, working-memory, summarizer, bandit, N3).

The exact flag that each package turns on is in **`analysis/arm_capability_matrix.csv`**
(6 access capabilities vs the orchestration bundle). Use it to read "access vs orchestration".

---

## 1. Headline: the package works on both local models (DVWA)

| Model | Base → Full | Gain | Source |
|---|---|---|---|
| Qwen2.5-7B | 64.1% (75/117) → 88.9% (104/117) | +24.8 pp | `primary_paired_outcomes.csv` |
| Qwen3.5-9B | 59.0% (69/117) → 88.0% (103/117) | +29.1 pp | " |
| **Pooled** | **61.5% (144/234) → 88.5% (207/234)** | **+26.9 pp** | " |

39 matched DVWA scenarios × 3 seeds. Fisher p < 0.001; scenario-clustered bootstrap CIs
exclude zero on both models.

## 2. What drives the gain? Access vs orchestration is **application-dependent**

Decomposing Base → **Simple-Tooled** → **Full** on two testbeds gives *opposite* pictures —
this is a key honest finding, not a single "access wins" story:

| Testbed | Base → Simple (**access**) | Simple → Full (**orchestration**) | Source |
|---|---|---|---|
| **DVWA** (13 med. scen. × 3 seeds × 2 models) | 66.7% → 70.5% (**+3.8 pp, n.s.**) | 70.5% → **87.2% (+16.7 pp)**, McNemar p≈0.065–0.070 | `k1_dvwa_3arm_osr.csv`, `k1_dvwa_3arm_mcnemar.csv` |
| **bWAPP** (9 scen. × 3 seeds, 7B) | 33.3% → **59.3% (+25.9 pp)**, p=0.039 (Holm 0.078) | 59.3% → 63.0% (**+3.7 pp, n.s.**) | `confirm3_bwapp.csv` |

**Reading:** on **DVWA the orchestration bundle carries the lift** (access adds ~nothing);
on **bWAPP tool/browser access carries it** (orchestration adds nothing significant).
The full package is strong everywhere; *which sub-layer dominates depends on the app.*
No single orchestration module is individually necessary — see §4.

## 3. External transfer (two applications, package effect)

| App | Base → Full | OR (Haldane) | Fisher p | Source |
|---|---|---|---|---|
| OWASP Juice Shop | 0/15 → 10/15 (66.7%) | 59.2 | 0.0002 | `external_paired_outcomes.csv` |
| bWAPP (archival sweep) | 14/27 → 23/30 (76.7%) | 2.92 | 0.059 | `external_scenario_outcomes.csv` |

Both positive. Juice Shop is 2-arm (package transfer); bWAPP additionally has the clean
3-arm decomposition in §2. External tests are supplementary run-level summaries — read with
the scenario-clustered CIs, not as full-pentest claims.

## 4. Component ablation — no single module is required

12-component leave-one-out on Full (Qwen3.5-9B, seed 42; `ablation_paired_outcomes.csv`):
removing any single module keeps OSR within noise (all McNemar p ≥ 0.375). Removing some
(passive-recon, backtrack-scorer, N3, state-graph) even *raises* single-seed OSR — flagged as
candidates for simplification. Multi-seed (699 runs) + a 2×2 RAG×guardrail design
(interaction ≈ 0.0 pp) confirm no single orchestration module is standalone-necessary.
The **Neural Evidence Classifier (N3)** is **auxiliary**: on held-out XVWA it scores
Macro-F1 0.157 vs the deterministic oracle's 0.684 (`n3_independent.csv`) — it never credits
success alone.

## 5. Targeted recovery — reported separately, **not** a validated fix effect

Flagged retries recover 12/20 failed cells (`retry_cohorts.csv`), but under **matched pairing**
(flagged vs unchanged, same snapshot/budget) the rule **did not fire and recovered 0/10**
(`k2_retry_paired.csv`); a canary check reproduced only 2/12 previously-successful cells
(`k2_canary.csv`). So the 116/120 cumulative coverage (`cumulative_coverage_linkage.csv`) is
reported as **coverage under repeated attempts, not a remediation-fix effect.**

## 6. Operational cost (`historical_cost_contract.csv`)

Full reaches higher OSR with **shorter** mean wall-clock (early VERIFY/FINISH stopping) but
more tokens; Base lacks early-stopping and exhausts all 15 iterations. Whole-device VRAM
peaks ≈ 12.9 GiB on a 32 GB-class server.

---

## File index (analysis/)

| File | What it holds |
|---|---|
| `primary_paired_outcomes.csv` | DVWA Base-vs-Full per scenario/model/seed (Table 4) |
| `k1_dvwa_3arm_osr.csv` | **DVWA 3-arm** base/simple_tooled/full per run (§2) |
| `k1_dvwa_3arm_mcnemar.csv` | DVWA 3-arm pairwise McNemar + clustered CIs |
| `confirm3_bwapp.csv` | **bWAPP 3-arm** base/simple_tooled/full (§2) |
| `arm_capability_matrix.csv` | which flags each arm turns on (access vs orchestration map) |
| `external_paired_outcomes.csv`, `external_scenario_outcomes.csv` | Juice Shop + bWAPP transfer (§3) |
| `ablation_paired_outcomes.csv`, `ablation_statistics.csv` | 12-component LOO + multi-seed (§4) |
| `n3_independent.csv`, `n3_class_counts.csv`, `n3_split_manifest.csv` | N3 auxiliary eval + splits (§4) |
| `k2_retry_paired.csv`, `k2_canary.csv`, `retry_cohorts.csv`, `cumulative_coverage_linkage.csv` | recovery + 116/120 linkage (§5) |
| `run_ledger.csv` | master per-run ledger (config, scenario, seed, verdict, hashes, timing) |
| `resolved_model_digests.csv` | full model manifest + weight-layer digests (see `REPRODUCE.md`) |
| `oracle_matrix.csv` | per-scenario oracle spec (target effect, evidence, auth, reset) |
| `c2_reconstructed_fold_membership.csv` | C2 grouped-fold composition (exploratory) |
