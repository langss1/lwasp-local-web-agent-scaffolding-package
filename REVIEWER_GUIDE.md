# Reviewer Guide — where every claim's evidence lives

IJIES 20267726 — *Scaffolding Effects on Local Large Language Model Web Penetration
Testing Agents via Factorial Evaluation and Component Ablation.*

This guide maps **every reviewer comment and every headline number in the manuscript/response
letter to the exact file in this repository**, so each claim can be checked without guesswork.
All paths are relative to the repository root. Numbers are recomputed by
`python scripts/reproduce_analysis.py --check` (no GPU, no network).

> **Two evidence folders, by design:**
> - **`analysis/`** — canonical machine-readable ledgers and paired-outcome CSVs. The offline
>   reproduction script reads these.
> - **`results/`** — the frozen per-experiment write-ups (`*_HASIL.md`), pre-registration files,
>   and the `repro_artifact/` snapshot, **named exactly as cited in the Response Letter's
>   "Location and evidence" lines**. The same canonical CSVs also appear under
>   `results/repro_artifact/` as the sealed artifact copy.

---

## A. Headline numbers → file

| Claim in manuscript | Number | File |
|---|---|---|
| DVWA Base→Full, 7B | 64.1% (75/117) → 88.9% (104/117) | `analysis/primary_paired_outcomes.csv` |
| DVWA Base→Full, 9B | 59.0% (69/117) → 88.0% (103/117) | `analysis/primary_paired_outcomes.csv` |
| DVWA Base→Full, pooled | 61.5% (144/234) → 88.5% (207/234) | `analysis/primary_paired_outcomes.csv` |
| **DVWA 3-arm (Table 8B)** | 52/78 → 55/78 → 68/78 (access +3.8, orch +16.7 pp) | `analysis/k1_dvwa_3arm_osr.csv`, `analysis/k1_dvwa_3arm_mcnemar.csv` |
| **bWAPP 3-arm (Table 8A-A, 7B)** | 9/27 → 16/27 → 17/27 (access +25.9, p=0.039) | `analysis/confirm3_bwapp.csv`, `results/K2_P2_CONFIRMATORY_TIERB_HASIL.md` |
| **bWAPP 3-arm (Table 8A-B, 9B)** | 15/30 → 22/30 → 25/30 (access +23.3, p=0.0156) | `analysis/confirm3_bwapp.csv`, `results/K1_CONFIRMATORY_3ARM_HASIL.md` |
| Juice Shop transfer | 0/15 → 10/15 (OR 59.2, p=0.0002) | `analysis/external_paired_outcomes.csv` |
| bWAPP archival sweep | 14/27 → 23/30 (OR 2.92, p=0.059) | `analysis/external_scenario_outcomes.csv` |
| 12-component LOO (Table 7) | all McNemar p ≥ 0.375 | `analysis/ablation_paired_outcomes.csv`, `analysis/ablation_statistics.csv` |
| Multi-seed ablation (699 runs) | FULL 85.5%, L-TLS 77.6% | `analysis/k2_ablation_dedup.csv`, `results/K2_SUMMARY.md` |
| 2×2 RAG×Guardrail (468 runs) | interaction 0.0 pp | `results/k2b_q25.csv`, `results/K2B_Q25_INTERACTION_HASIL.md` |
| N3 vs P0 on held-out XVWA | Macro-F1 0.157 vs 0.684 | `analysis/n3_independent.csv`, `analysis/n3_class_counts.csv` |
| Retry (honest null) | fix-OFF 0/10, fix-ON 0/10 | `analysis/k2_retry_paired.csv`, `analysis/k2_canary.csv` |
| Stage-separated timing | Base 15 iters / Full 4.8 iters | `results/P3_TIMING_BREAKDOWN_HASIL.md`, `results/timing_runs/` |
| Stored/DOM XSS replay adjudication | 40/51 reproduced | `analysis/k1_stored_dom_adjudicated.csv`, `results/P4_STORED_DOM_XSS_ADJUDICATION_HASIL.md` |
| Model weight digests | qwen2.5 2bada8a7…, qwen3.5 dec52a44… | `analysis/resolved_model_digests.csv`, `results/repro_artifact/digests.json`, `model_manifests/` |
| Per-run ledger (3,908 runs) | config/scenario/seed/verdict/timing | `analysis/run_ledger.csv` (= `results/repro_artifact/run_ledger.csv`) |

## B. Reviewer 1 (R1.1–R1.6) → evidence

| # | Ask | Where addressed | Evidence files |
|---|---|---|---|
| R1.1 | Oracle spec per scenario; opportunity parity; arm-blind audit | §3.1, §4.2, §5.3, §6 | `analysis/oracle_spec.json`, `analysis/oracle_matrix.csv`, `results/P4_STORED_DOM_XSS_ADJUDICATION_HASIL.md`, `analysis/k1_stored_dom_adjudicated.csv` |
| R1.2 | Phase/run manifest; freeze points; clean-snapshot interleaved | §4.1, §5.6, Table 8A | `analysis/phase_manifest.csv`, `analysis/phase_summary.csv`, `results/prereg_confirmatory_tierB.json`, `results/confirmatory_tierB_reset_log.csv` |
| R1.3 | Reconcile 35 vs 76 follow-ups; 116/120 linkage | §4.1 (Table 3A), §5.5 | `analysis/cohort_accounting.csv`, `analysis/cumulative_coverage_linkage.csv`, `analysis/retry_cohorts.csv` |
| R1.4 | Versioned reproduction artifact | §3.2, Data Availability | `results/repro_artifact/` (sealed), `analysis/run_ledger.csv`, `requirements.lock`, `REPRODUCE.md` |
| R1.5 | C2/N3 development-vs-eval separation; held-out testbed | §3.4, §3.5, §5.4, §6 | `analysis/c2_reconstructed_prefixes.csv`, `analysis/c2_reconstructed_fold_membership.csv`, `analysis/n3_split_manifest.csv`, `analysis/n3_independent.csv` |
| R1.6 | Resource contract behind Table 5; Base=15 iters; OR wording | §4.1, §5.1, §5.2 | `analysis/historical_cost_contract.csv`, `results/P3_TIMING_BREAKDOWN_HASIL.md`, `results/timing_runs/` |

## C. Reviewer 2 (R2.1–R2.6) → evidence

| # | Ask | Where addressed | Evidence files |
|---|---|---|---|
| R2.1 | Tool/observation-matched **Simple-Tooled** arm; separate access vs orchestration | Abstract, §1, §3.1, §5.3, §5.4, §5.6, Tables 8A/8B, §6, §7 | `analysis/arm_capability_matrix.csv`, `analysis/arm_configs.json`, `analysis/k1_dvwa_3arm_osr.csv`, `analysis/confirm3_bwapp.csv` |
| R2.2 | Preregistered frozen interleaved confirmatory; development-set labeling | §4.1, §5.6, Table 8A, §6 | `results/prereg_confirmatory_tierB.json`, `results/K2_P2_CONFIRMATORY_TIERB_HASIL.md`, `results/confirmatory_tierB_reset_log.csv` |
| R2.3 | Runnable public controller under matched conditions | §1, §5.7, Table 9, §6 | `analysis/controller_adaptation_notes.md`, `analysis/controller_equivalence.csv`, `analysis/k4_controller_pin.json` |
| R2.4 | Multi-seed ablation + 2×2 interaction; paired discordance | §5.4, §6 | `analysis/k2_ablation_dedup.csv`, `results/k2b_q25.csv`, `results/K2B_Q25_INTERACTION_HASIL.md`, `analysis/ablation_paired_outcomes.csv` |
| R2.5 | Paired flagged-vs-unchanged retry; canary regression | §4.1, §5.5, §6 | `analysis/k2_retry_paired.csv`, `analysis/k2_canary.csv`, `analysis/cumulative_coverage_linkage.csv` |
| R2.6 | Scenario-level clustered external outcomes; bWAPP sensitivity | §4.2, §5.6, Tables 8/8A, §6 | `analysis/external_paired_outcomes.csv`, `analysis/external_scenario_outcomes.csv`, `analysis/external_cluster_statistics.csv`, `results/confirm3_bwapp.csv` |

## D. Structured form (M1–M4, m0–m10)

Full point-by-point narrative, cross-referenced to the files above, is in
`results/PETA_REVIEWER_HASIL_FINAL.md` and `results/SISA_POIN_DATA_HASIL.md`.
Key items: M2 (Simple-Tooled control) → `analysis/arm_capability_matrix.csv`;
M3 (no necessary component) → `results/K2_SUMMARY.md`;
m5 (model-specific OR) → `analysis/primary_paired_outcomes.csv`;
m8 (arXiv→peer-reviewed upgrades) → References [8], [13], [24];
m9 (weight digests + public repo) → `analysis/resolved_model_digests.csv`.

## E. How to verify in one command

```
python scripts/reproduce_analysis.py --check
```

Recomputes the 20,000-replication scenario-clustered bootstrap (seed 20261105), the exact
McNemar p-values, the 120-cell coverage linkage, and all cohort counts from the shipped CSVs.
No GPU, no Ollama, no network. See `REPRODUCE.md` for the full live re-run.

> **Note on language:** the `results/*_HASIL.md` write-ups are the authors' working evidence
> notes (partly in Indonesian). Every number in them is also in the language-neutral CSVs cited
> above and recomputed by the script, so verification does not depend on reading those notes.
