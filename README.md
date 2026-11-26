# LWASP — Local Web-Agent Scaffolding Package

Implementation and evaluation code for IJIES 20267726,
*"Scaffolding Effects on Local Large Language Model Web Penetration Testing Agents
via Factorial Evaluation and Component Ablation."*

Version: archive-reanalysis-2026-11-21

### Start here
- **[REPRODUCE.md](REPRODUCE.md)** — exact Python environment (`requirements.lock`),
  model download **with weight-hash verification**, and how to run (offline + live).
- **[RESULTS.md](RESULTS.md)** — every headline number, what it means, and which file it
  comes from (incl. the DVWA vs bWAPP access-vs-orchestration decomposition).
- One-command re-check (no GPU/network): `python scripts/reproduce_analysis.py --check`.

This repository ships machine-readable ledgers, paired outcomes, oracle specs, model/weight
digests, and the full source; it reproduces the paper's calculations from recorded experiment
data. The sections below document provenance honestly, including what is reconstructed and
what remains under controlled access.

## Reproduce the numerical analysis without RunPod

Use Python 3.10 or later with NumPy, then run from the extracted package directory:

```text
python scripts/reproduce_analysis.py --check
```

This reads paired CSVs and the 120-cell linkage, recomputes 20000 scenario-clustered bootstrap samples (seed 20261105), verifies unique pairing keys, and checks primary/external outcomes and recovery counts. It does not contact Ollama, applications, cloud services or the network, and does not retrain models. Running without --check additionally writes analysis/reproduced_statistics.json.

The original workspace reconstruction is in revision/ijies426/scripts/analyze_archives.py and build_support.py outside this portable package. It scans the original archive layout. The portable command above deliberately starts from the included machine-readable ledger/pairs instead of requiring all sensitive traces.

## Contents

- analysis/: all paired successes/failures, scheduled/missing status, phase/run and cohort ledgers, target/scenario oracle documentation, installation-log version evidence, source hashes, C2 reconstructed fold membership, N3 split/label/payload manifests, and reviewer closure status.
- source_code/: the available configuration, runner, interpreter/verifier, preprocessing and training sources, preserved as evidence. These sources include live experiment entry points; they are not invoked by the offline reproduction command.
- datasets/: the recovered 5849-response N3 corpus, cached 5849-by-768 embeddings, corpus payload definitions, and frozen serialized N3/C2 artifacts. Loading serialized models requires a compatible scikit-learn/joblib environment; the offline numerical command does not load them.
- documents/: the archival-stage red manuscript and working English response.
- HASIL_TAHAP_ARSIP.md: Indonesian explanation of findings and remaining evidence gaps.
- FILE_MANIFEST.csv: hashes of included files, excluding the manifest itself.

## Dataset and model preparation provenance

The supplied corpus_payloads.json is the existing payload corpus; build_corpus.py describes its construction. build_dataset.py describes collection from DVWA and the two internal applications, using collect_n3_data.py functions and declared application-specific response-marker labels. Re-running collection requires authorized live testbeds and is outside this archival stage.

bench_big.py combines 12 invariant numeric features and 768 cached embedding dimensions, fits on DVWA Low/Medium plus LabApp2 (3510 samples), and selects the model using LabApp3 (1170). DVWA High contains 1169 samples. LabApp3 is selection data, not an independent test. n3_split_manifest.csv preserves exact/normalized payload hashes and the historical split, showing shared payloads across splits. No payload-group-disjoint evaluation is claimed. The stored model artifacts are supplied for inspection, not newly trained here.

C2 feature/label reconstruction uses the available train_n4_promise.py and archived C0 trajectories. The 42 prefixes/10 runs/13 positives reproduce the archived development report. Fold membership is reconstructed from current source/data and is not a recovered historical index snapshot. Candidate selection reused the reported development CV.

## RAG and environment

source_code/src/memory/rag_store.py documents whitespace chunking (500-word chunks, overlap 50), embedding and cosine retrieval. analysis/rag_chunk_manifest.csv exports the recovered LOCAL 20-document collection with hashes; it is not the historical 214-chunk pod snapshot. The local Chroma collection and N3 cache both support embedding dimension 768. The original pod corpus, full embedding-weight digest and exact ingestion identity remain required for full live reproduction.

historical_versions.csv extracts versions from the archived installation log, with phase/provenance limits. requirements.txt uses version ranges and is not a historical lockfile. Short installed-model IDs are not full model digests. No current package installation or model download is presented as proof of missing historical versions. Exact DVWA/bWAPP commits, complete per-run model digest mapping and reset snapshots are not reconstructed by guesswork.

## Cohorts and outcome interpretation

The 35 follow-up records are 26 canonical probes + 3 seed42 confirmations + 6 additional seed7/123 confirmations. Twenty flagged retries and five canaries are distinct, yielding 60 follow-up executions. Cumulative 16/16 and 9/9 reuse prior/confirmation results and are not extra executions. The 116/120 coverage linkage uses 94 original successes plus 22 probe recoveries. Neither canonical coverage nor flagged recovery replaces primary OSR, and unchanged-retry controls have not been run.

bWAPP Base is taken from nine matching scenarios in the earlier sweep; Full is from the later final-package matrix. Complete-case 14/27 versus 23/27 removes three failed Full HTML-injection cells lacking Base counterparts. The original 23/30 Full result and the 14/30-to-17/30 Base sensitivity address a different ten-scenario scope. Scenario-aware intervals remain exploratory for five Juice Shop and nine bWAPP matched scenarios.

## Access and unresolved validation

Raw traces/screenshots and original databases remain in the author's archive; controlled access can redact sensitive fields with a recorded schema. File paths/hashes identify provenance but are not a claim that every historical trace is complete. evidence_completeness_flags.csv lists report-level successes whose selected archived trace lacks retained non-FINISH success evidence; these are not automatically adjudicated false positives. archive_conflicts.csv preserves differing copies with the same run_id instead of silently merging laptop and pod evidence.

A tool-matched simple agent (`simple_tooled`), post-freeze confirmatory targets, multi-seed/interaction ablations, an independent N3 testbed (XVWA), and stage-separated timing are **included** in this release (see RESULTS.md). Genuinely open items: a fully autonomous runnable public controller under matched local conditions (only a human-in-the-loop legacy controller could be pinned — see `controller_equivalence.csv`), a full application-reset between arms, and a clean unchanged-retry control (the matched pairing recovered 0/10, so the remediation-fix effect is not validated). Raw traces/screenshots stay in the authors' archive under controlled access.

## Additional recovered identities and pod metadata

resolved_model_digests.csv includes full immutable manifest SHA-256 and model-layer digests for Qwen2.5, Qwen3.5 and nomic-embed-text. These were read from local manifests whose full hashes start with the IDs already recorded in the historical inventory/setup logs. The provenance is explicit: resolving a short ID is useful identity evidence, but is not a recovered per-run server manifest or a claim that every historical tag use was independently logged.

**Reproducibility anchor = the weight-layer digest, not the short manifest ID.** The `:latest`
tag is mutable and the short manifest ID is snapshot-specific. For qwen3.5 two short IDs appear
(`56671c2ab938` from the eval-host `ollama list`; `6488c96fa5fa` from the re-resolved local
immutable manifest) — these are two manifest wrappers around the **same** weight blob
`sha256:dec52a44…`, which is identical in both. Verify that weight-layer digest (per model, in
`resolved_model_digests.csv` and `model_manifests/*.json`); see **REPRODUCE.md §2.2**.

The supplied ta_FULL_backup.tgz was inspected without running code. The recovered pod config uses /var/www/html/dvwa and num_thread=12, while the current Windows config differs. source_code/config_pod_recovered.yaml preserves that backup config. The recovered orchestrator, cognitive engine and final Full/ablation runner source files are byte-identical to the corresponding current files; recovered_metadata_manifest.csv records hashes and paths. This supports source reconstruction at the backup snapshot, without inventing a commit/freeze date for earlier runs.

The Chroma SQLite database in the FULL backup also reports dimension 768 and 20 documents. pod_rag_chunks_ta_FULL_backup.csv exports its documents. The reported historical 214-chunk corpus remains unverified; the backup snapshot is not silently relabeled as that earlier corpus.
