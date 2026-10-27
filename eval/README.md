# Evaluation corpus

Local-only corpus for measuring the pipeline and calibrating thresholds.

- `manifest.json` — committed. Lists sample paths, expected labels
  (`malware | benign | suspicious | unknown`) and tags. No sample bytes.
- `corpus/` — **gitignored**. Put the actual samples here following the paths in
  the manifest.
- `results/` — **gitignored**. One directory per run, created by the harness.

> Never commit suspected malware. Keep samples in this local directory only and
> review the licence of every benign sample you add.

## Building the corpus

Both commands run from `scanner-service/`, need ClamAV running, and append to
`manifest.json` (existing entries are skipped, so re-running is safe).

```bash
# Benign set: downloads every URL in benign-sources.tsv (committed; add rows freely)
go run ./cmd/eval fetch-benign

# Malware ClamAV misses: needs MALWAREBAZAAR_API_KEY in config/.env and 7z
go run ./cmd/eval fetch-malware                       # 10 misses per type
go run ./cmd/eval fetch-malware -types exe,docm -per-type 25
```

`fetch-malware` lists the newest MalwareBazaar samples per file type (samples
with no known ClamAV signature first), extracts each `infected`-encrypted zip
into memory with 7z, scans it with the local ClamAV and writes **only the
misses** to `corpus/malware/bazaar/<type>/<sha256>.<type>` (mode `0600`). Those
are exactly the files the classifier has to decide on. Signatures update daily,
so re-running later finds new misses; samples ClamAV starts detecting stay in the
corpus and show up as ClamAV detections in `collect`.

`fetch-benign` keeps files ClamAV flags (tagged `clamav-detected`) because a
ClamAV false positive on a benign file is part of what the eval measures.
Both commands drop a `.metadata_never_index` file in `corpus/` so Spotlight does
not index or preview samples. Never open or double-click anything in
`corpus/malware/`.

## Usage

Run from `scanner-service/` so `config/.env` is loaded:

```bash
# Phase A — run ClamAV + analyzers + classifier once per sample
go run ./cmd/eval collect

# Phase A without classifier calls (offline / rule-only runs)
go run ./cmd/eval collect -no-classifier

# Phase B — replay the policy over threshold grids (no network calls)
go run ./cmd/eval analyze -in ../eval/results/<timestamp>
```

Every run directory also shows up in the frontend's **Evaluation** tab (served
by the scanner from `EVAL_RESULTS_DIR`, default `../eval/results`; restart the
scanner after changing it). Runs without `summary.json` show samples only.

`collect` writes `raw.jsonl` (one record per sample: ClamAV result, analyzer
evidence, classifier label/confidence/scores/model and per-stage latency).
`analyze` writes `summary.json` plus `report.md`, which contains:

- threshold grid (block confidence × suspicious-imports minimum)
- rule-only vs classifier-only vs combined quality
- ClamAV-miss coverage, false positives/negatives, precision/recall/F1
- latency p50/p95 and observed classifier model versions
- a recommended threshold set that maximises malware recall subject to
  `-max-fp` (default 5%)

Record the chosen thresholds in `scanner-service/config/.env.example` with a
comment pointing at the run directory.
