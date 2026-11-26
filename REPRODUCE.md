# Reproducing LWASP — environment, models, and runs

This guide makes the paper's numbers reproducible in three layers:
**(1) exact Python environment, (2) exact model weights (hash-verified), (3) how to run.**

> TL;DR for a reviewer who only wants to re-check the statistics (no GPU, no Ollama,
> no network): jump to **§3.A Offline re-analysis**. It recomputes every headline
> number from the shipped CSV ledgers in one command.

---

## 1. Python environment (byte-exact)

The eval host ran **Python 3.11** on Linux (RunPod). Two files are provided:

| File | Purpose |
|---|---|
| `requirements.lock` | **137 fully pinned packages** (`pip freeze` of the eval host). Use this for byte-exact reproduction. |
| `source_code/requirements.txt` | loose dev ranges (readability only — **not** the environment of record). |

```bash
python3.11 -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.lock
python -m playwright install chromium                 # browser verifier backend
```

Key pins (full list in `requirements.lock`): `torch==2.15.0`, `transformers==5.24.1`,
`scikit-learn==1.9.1` (N3/C2), `chromadb==1.5.9` (RAG), `playwright==1.65.2`
(XSS verifier), `sentence-transformers==6.3.0`, `numpy==2.5.5`, `scipy==1.18.1`,
`ollama==0.6.3` (client).

---

## 2. Models — download and **verify the weight hash**

Inference uses **Ollama** (pinned server **v0.40.17**) with three frozen GGUF models.
Nothing is fine-tuned; weights are static `Q4_K_M`.

### 2.1 Pull

```bash
# install Ollama v0.40.17, then:
ollama pull qwen2.5          # 7B, Q4_K_M, 4.7 GB
ollama pull qwen3.5          # 9B, Q4_K_M, 6.6 GB
ollama pull nomic-embed-text # 768-d embeddings, 274 MB
```

### 2.2 Verify you have the **same weights** (important)

The `:latest` tag is **mutable** — `ollama pull` today may fetch a newer build. Do **not**
rely on the short manifest ID; verify the **model-layer SHA-256** (the content hash of the
weight blob). These are the reproducibility anchors used in the paper
(`analysis/resolved_model_digests.csv`, `model_manifests/*.json`):

| Model | Weight-layer digest (verify THIS) | Manifest short-ID(s)† |
|---|---|---|
| qwen2.5 (7B) | `sha256:2bada8a7450677000f678be90653b85d364de7db25eb5ea54136ada5f3933730` | `845dbda0ea48` |
| qwen3.5 (9B) | `sha256:dec52a44569a2a25341c4e4d3fee25846eed4f6f0b936278e3a3c900bb99d37c` | `56671c2ab938` (eval-host `ollama list`) · `6488c96fa5fa` (local immutable manifest) |
| nomic-embed-text | `sha256:970aa74c0a90ef7482477cf803618e776e173c007bf957f635f1015bfcfef0e6` | `0a109f422b47` |

† **Why two short-IDs for qwen3.5?** The short-ID is a hash of the *manifest wrapper*
(config + layer list), which differs between the eval-host snapshot and a freshly
re-resolved local manifest. **The weight-layer digest `dec52a44…` is identical in both**,
so the actual weights are the same. Always compare the layer digest, not the manifest ID.

Check your pulled blobs:

```bash
# layer blobs live under ~/.ollama/models/blobs/ as sha256-<hex>
ls ~/.ollama/models/blobs/ | grep -E '2bada8a7|dec52a44|970aa74c'
# or inspect the manifest:
ollama show qwen3.5 --modelfile
```

Full dependency + model digests are frozen in `analysis/digests.json`
(Ollama version, `pip freeze`, model list) and `analysis/resolved_model_digests.csv`
(full manifest + layer SHA-256 per model).

---

## 3. Running

### 3.A Offline re-analysis (no GPU / no network) — recommended first

Recomputes bootstrap CIs, McNemar pairings, 116/120 linkage, and every headline number
straight from the shipped ledgers:

```bash
python scripts/reproduce_analysis.py --check
```

It reads the paired CSVs + 120-cell linkage, runs the 20,000-replication
scenario-clustered bootstrap (seed `20261105`), and verifies primary/external/recovery
counts. It never contacts Ollama, the targets, or the network. See **`RESULTS.md`** for
what each number means and which file it comes from.

### 3.B Full live evaluation (GPU + local targets)

Requires authorized **local** testbeds (DVWA, OWASP Juice Shop, bWAPP) on `127.0.0.1`
and the models from §2. Entry points in `source_code/`:

```bash
# three-arm (base / simple_tooled / full) over the frozen scenario set + 3 seeds
python source_code/eval/run_confirm_3arm.py  --config source_code/config.yaml

# single-package sweep
python source_code/eval/run_eval.py          --package full --seeds 42 7 123
```

All targets are strictly loopback; `ScopeGuard` rejects any non-`{localhost,127.0.0.1}`
host. Seeds are fixed to **{42, 7, 123}**. Budgets: `I_max=15` iterations, `T_max=1500 s`.

---

## 4. What guarantees "same result"?

1. **Same weights** — verified by the layer digests in §2.2 (not the mutable tag).
2. **Same code** — `analysis/resolved_model_digests.csv` + `FILE_MANIFEST.csv` hash every
   shipped source/data file.
3. **Same environment** — `requirements.lock` + Ollama `v0.40.17`.
4. **Same analysis** — fixed bootstrap seed `20261105`; `scripts/reproduce_analysis.py`
   is deterministic.

Open items (documented, not hidden): raw traces/screenshots stay in the authors' archive
under controlled access; exact per-run historical DVWA/bWAPP commits are recorded where
recovered and flagged where not. See `README.md` → provenance sections.
