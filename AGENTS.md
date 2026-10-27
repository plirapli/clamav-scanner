# AGENTS.md

Hybrid malware triage: ClamAV → static analysis (PE, PDF, Office, archive, script) → Cloudflare Clef → deterministic
policy (`ALLOW`/`QUARANTINE`/`BLOCK`). Scan logs flow through Kafka to SQLite.
`plan.md` is the specification and roadmap; `README.md` is user-facing. Do not
reintroduce `be-analysis`, MongoDB, Postgres, or Kafka Connect (removed on purpose).

Current state: plan phases 1–10 implemented (PE + non-PE analysis, classifier,
policy, quarantine, cache, eval harness in `cmd/eval`). Thresholds
(`VERDICT_BLOCK_CONFIDENCE`, `SUSPICIOUS_IMPORTS_MIN`) are still experimental —
calibrate them with a real corpus in `eval/corpus/` before trusting them.

## Commands

```bash
# infra (start.sh has no executable bit, and --remove-orphans matters)
sh start.sh

# scanner-service (Go 1.25; run from this directory)
cp config/.env.example config/.env   # then set CLOUDFLARE_ACCOUNT_ID / CLOUDFLARE_API_TOKEN
go run ./cmd/main.go                # HTTP API on :4000
go run ./cmd/logwriter              # separate process; without it nothing reaches SQLite

# verification order after Go changes
gofmt -l . && go build ./... && go vet ./... && go test ./...
go test ./analysis/policy -run TestDecide -v     # single package / single test

# evaluation harness (corpus is local-only, gitignored)
go run ./cmd/eval fetch-benign                   # download eval/benign-sources.tsv into the corpus
go run ./cmd/eval fetch-malware                  # MalwareBazaar samples ClamAV misses (needs MALWAREBAZAAR_API_KEY + 7z)
go run ./cmd/eval collect                        # live classifier calls
go run ./cmd/eval analyze -in ../eval/results/<ts>  # offline threshold sweep

# fe-analysis
npm run lint                        # oxlint
npm run build                       # tsc -b && vite build
npm run dev                         # 5173, falls back to 5174
```

## Environment quirks

- Kafka external port is **39092** (`29092` is used by another local project; a
  conflict makes the kafka container start without a network and crash-loop).
  kafka-ui is on **8090** (not 8080). ClamAV is `clamav/clamav-debian` (arm64).
- Kafka healthcheck uses `clamdscan --ping=5` — the flag needs an argument.
- Topic `scan-logs` must exist before the scanner publishes. `kafka-init` creates
  it; if the scanner started earlier, restart the scanner (kafka-go caches the
  missing-topic metadata and keeps failing with `Unknown Topic Or Partition`).
- `scanner-service/config/.env` is gitignored and loaded by `config.Load()` (used
  by both `cmd/main.go` and `cmd/logwriter`). Template: `config/.env.example`.
- `CLOUDFLARE_ACCOUNT_ID`/`CLOUDFLARE_API_TOKEN` belong only in
  `scanner-service/config/.env`. Never put them in `fe-analysis/.env` — Vite inlines `VITE_*` variables into the public bundle.
- The frontend Evaluation tab reads `eval/results/*` through `GET /api/eval/runs*`
  (`app/scanner/handler/eval_handler.go`); per-sample verdicts are recomputed with
  the scanner's live policy config, while the variant/threshold tables come
  from each run's `summary.json`.
- CORS origins are hardcoded for `localhost:5173`/`5174` in `app/app.go`.

## Codebase facts

- Scan pipeline lives in `app/scanner/handler/scanner_handler.go`: ClamAV →
  analyzer → evidence → classifier → policy → quarantine → Kafka publish, per
  file. Completed scans always return HTTP 200; `4xx` is only invalid requests.
- `analysis/` is dependency-clean Go: `evidence` is a leaf; `analyzer`, `classifier`
  and `policy` build on it. Policy is a pure function (`policy.Decide`,
  escalate-only max-severity over signals) — put new decision rules there, not in
  handlers. New analyzer = implement `Analyzer` (`Input{Data, Name}`) and register
  in `app/app.go`; the registry order is PE → PDF → office → archive → script →
  generic, first match wins, generic signals (embedded PE, URLs, obfuscation)
  promote otherwise-unsupported files.
- Bump `analyzer.Version` (`analysis/analyzer/analyzer.go`) when evidence format or
  heuristics change; cached entries with an older version are ignored.
- PE evidence (`analysis/analyzer/pe.go`, `authenticode.go`): Authenticode is
  verified for integrity (file digest + signed attributes), **not** chain trust —
  `signature_status=valid` can be self-signed; `invalid` (copied/tampered) clears
  `has_digital_signature`. `debug/pe` returns imports as `Func:dll`. The
  suspicious-import list is deliberately narrow (injection/hollowing/keylogging/
  download); broad APIs like `GetProcAddress` made every benign PE look suspicious.
  Packed-size hints only count executable sections; text heuristics are skipped
  for binaries and the certificate table is excluded from the generic scan.
  `openPE` re-parses images with a corrupt COFF symbol table (common in packed
  malware; `debug/pe` otherwise rejects them).
- Clef is deterministic for identical input, so eval differences between runs come
  from evidence/prompt changes. Measure every evidence or label-description change
  with `cmd/eval collect` before and after.
- Scan cache (`scan_cache`): ClamAV always runs, cached entries store evidence +
  classifier output (never verdicts), so policy is recomputed on every hit.
  `cmd/logwriter` must be rebuilt whenever the `ScanLog` schema changes.
- SQLite schema and migrations: `infra/sqlite/sqlite.go`. Migrations are additive
  (`PRAGMA table_info` + `ALTER TABLE`) and run in the order create table →
  migrate → indexes; index statements referencing new columns must not run before
  the migration. Dev reset: stop scanner + logwriter, `rm -rf data/`.
- Kafka inserts are idempotent per unique `(request_id, filename, sha256)`.
- Only non-`ALLOW` verdicts are published to Kafka; set `PUBLISH_ALL_VERDICTS=true`
  for evaluation runs.
- Quarantine writes `data/quarantine/<sha256>` with mode `0600`; nothing is ever
  executed or auto-deleted.
- Clef (`@cf/cloudflare/clef`, Workers AI REST API): needs account ID + API
  token; one `choice` question over `CLASSIFIER_LABELS`. `confidence` is the
  chosen label's probability (can be `null`), not malware probability; store the
  returned `model` per scan. Responses are wrapped in Cloudflare's
  `{success, result, errors}` envelope. Client retries `429`/`5xx` with
  `Retry-After`, never `4xx`.
- Encrypted files: ClamAV reports `Heuristics.Encrypted.*` (alerts enabled via
  `CLAMD_CONF_AlertEncrypted*` in compose) and the policy maps those signatures to
  `ENCRYPTED_VERDICT` (default QUARANTINE) instead of BLOCK; analyzers also set
  `generic.encrypted` for ZIP entry flags, unreadable ZIPs, PDF `/Encrypt` and OLE
  `EncryptedPackage`.

## Testing quirks

- Tests never call Clef live: the client is covered with `httptest`.
- The PE analyzer is tested against a hand-built PE fixture in
  `analysis/analyzer/pe_test.go`; format analyzers use in-memory fixtures in
  `analysis/analyzer/formats_test.go`; cache and handler tests use a temp SQLite
  file (`t.TempDir()`).
- `cmd/eval collect` does call the live classifier (unless `-no-classifier`);
  `cmd/eval analyze` never does.
- End-to-end smoke test needs clamav running:
  `printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt`
  then `curl -s -F files=@/tmp/eicar.txt http://localhost:4000/api/scanner/scan`.
