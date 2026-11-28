# LWASP — Local Web-Agent Scaffolding Package

Implementation and evaluation code for **IJIES 20267726**,
*"Scaffolding Effects on Local Large Language Model Web Penetration Testing Agents
via Factorial Evaluation and Component Ablation."*

Authors: Gilang Wasis Wicaksono, Vera Suryani — School of Computing, Telkom University.
Version: `v1.0.0` (archival reanalysis) · License: MIT (see `LICENSE`) · Cite: see `CITATION.cff`.

> This repository lets a reviewer **check every number in the paper against a file**, and
> **re-run the analysis in one command without a GPU**. If you only read one other file, read
> **[REVIEWER_GUIDE.md](REVIEWER_GUIDE.md)** — it maps each reviewer comment and headline number
> to its exact evidence file.

---

## 1. One-command verification (no GPU, no network)

```bash
python -m pip install -r requirements.lock      # or just: pip install numpy
python scripts/reproduce_analysis.py --check
```

This reads the shipped CSVs and recomputes the 20,000-replication scenario-clustered bootstrap
(seed 20261105), the exact McNemar p-values, the 120-cell coverage linkage, and all cohort
counts. It does **not** contact Ollama, the target apps, or the network, and does not retrain
anything. Drop `--check` to additionally write `analysis/reproduced_statistics.json`.

For the full **live** re-run (pull the pinned model weights by digest, start the targets, run the
agents) follow **[REPRODUCE.md](REPRODUCE.md)**.

## 2. Headline results

Success = **Objective Success Rate (OSR)**: the fraction of valid runs an **independent
deterministic oracle** credits from recorded target effects (SQLi row extraction, headless-browser
XSS execution, state-change markers) — never the agent's own "FINISH" claim.

**The package works on both local models (DVWA, Table 4)**

| Model | Base → Full | Source |
|---|---|---|
| Qwen2.5-7B | 64.1% (75/117) → 88.9% (104/117) | `analysis/primary_paired_outcomes.csv` |
| Qwen3.5-9B | 59.0% (69/117) → 88.0% (103/117) | " |
| **Pooled** | **61.5% (144/234) → 88.5% (207/234)** | " |

**What drives the gain is application-dependent** (Base → Simple-Tooled → Full):

| Testbed | Access (Base→Simple) | Orchestration (Simple→Full) | Source |
|---|---|---|---|
| **DVWA** (13 med × 3 seeds × 2 models) | +3.8 pp (n.s.) | **+16.7 pp**, p≈0.065–0.070 | `analysis/k1_dvwa_3arm_osr.csv` |
| **bWAPP** (9 scen × 3 seeds, 7B) | **+25.9 pp**, p=0.039 | +3.7 pp (n.s.) | `analysis/confirm3_bwapp.csv` |

The full package is strong on both; *which sub-layer dominates depends on the application.*
No single orchestration module is individually necessary (`results/K2_SUMMARY.md`).

## 3. Repository map

```
scripts/reproduce_analysis.py   one-command offline verification
requirements.lock               137 pinned packages (exact env)
REPRODUCE.md                    live re-run: model download (by weight digest) + run steps
RESULTS.md                      every headline number, meaning, and source file
REVIEWER_GUIDE.md               reviewer comment / number  ->  exact evidence file
CITATION.cff                    how to cite (incl. Zenodo DOI)

analysis/     canonical machine-readable ledgers + paired-outcome CSVs (the script reads these)
results/      per-experiment write-ups (*_HASIL.md), pre-registration files, and the sealed
              repro_artifact/ snapshot — named exactly as cited in the paper's Response Letter
model_manifests/   Ollama manifests with the content-addressable weight-layer digests
datasets/     N3 response corpus, cached embeddings, serialized N3/C2 artifacts
source_code/  full agent source (Base / Simple-Tooled / Full), runners, oracle, training
```

**Why two data folders:** `analysis/` is the canonical, script-readable set; `results/`
reproduces the folder layout and filenames cited verbatim in the Response Letter's
"Location and evidence" lines (the same canonical CSVs also sit under `results/repro_artifact/`
as the sealed artifact copy). Either path a reviewer follows will resolve.

## 4. The three arms (what each turns on)

- **Base** — HTTP requests only (no tools, no browser, no verifier).
- **Simple-Tooled** — Base **+ Action/Verify Layer** (6 access capabilities: external/MCP tools,
  sandbox, headless-browser XSS verifier, passive recon, universal oracle, OAST); **all
  orchestration OFF**. This is the *access-parity* control added for Reviewer 2.
- **Full (LWASP)** — Simple-Tooled **+ the 10-module orchestration bundle** (RAG, trial-memory +
  repetition guardrail, state-graph, progress monitor, backtrack scorer, reflection, summarizer,
  bandit, auxiliary neural evidence classifier).

The exact flag each arm turns on is in `analysis/arm_capability_matrix.csv`.

## 5. Provenance, honestly

This is an **archival reanalysis** package: it reproduces the paper's calculations from recorded
experiment data. It documents what is reconstructed and what remains under controlled access.

- **Reproducibility anchor = the weight-layer SHA-256, not the mutable `:latest` tag.** For
  qwen3.5 two short manifest IDs appear (`56671c2ab938`, `6488c96fa5fa`) — both wrap the **same**
  weight blob `sha256:dec52a44…`. Verify that digest per model in
  `analysis/resolved_model_digests.csv` and `model_manifests/*.json` (see REPRODUCE.md §2.2).
- Historical DVWA Base came from the initial sweep while final Full was calibrated afterwards;
  that phase asymmetry is exactly why the **frozen three-arm decompositions** (DVWA Table 8B,
  bWAPP Table 8A) are run separately and are the basis for the access-vs-orchestration claims.
- Open items are stated plainly: no fully-autonomous public controller could be pinned under
  matched local conditions (only a human-in-the-loop legacy controller — `analysis/controller_equivalence.csv`);
  a full inter-arm application reset and a validated unchanged-retry effect were not achieved
  (the matched retry pairing recovered 0/10 — `analysis/k2_retry_paired.csv`).
- Raw traces/screenshots and original databases stay in the authors' archive under controlled
  access; this package ships the ledgers, paired outcomes, oracle specs, and digests needed to
  recompute every reported statistic.

## 6. Authorized use

This code evaluates penetration-testing agents against **intentionally vulnerable, locally
hosted training applications** (DVWA, OWASP Juice Shop, bWAPP, XVWA) over the loopback interface
only. It is released for research and defensive-security education. Use it only against systems
you own or are explicitly authorized to test. Licensed under MIT (`LICENSE`); no warranty.

## 7. Cite

See `CITATION.cff`. The archived snapshot has a DOI via Zenodo (added on release).
