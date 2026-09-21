# AGENTS.md

Hybrid malware triage: ClamAV → PE static analysis → classifier.dev → deterministic
policy (`ALLOW`/`QUARANTINE`/`BLOCK`). Scan logs flow through Kafka to SQLite.
`plan.md` is the specification and roadmap; `README.md` is user-facing. Do not
reintroduce `be-analysis`, MongoDB, Postgres, or Kafka Connect (removed on purpose).

Current state: plan phases 1–7 implemented; phases 8–10 (eval harness, scan cache,
non-PE coverage) are designed in `plan.md` §20–23 but **not implemented**.

## Commands

```bash
# infra (start.sh has no executable bit, and --remove-orphans matters)
sh start.sh

# scanner-service (Go 1.25; run from this directory)
cp config/env_example config/.env   # then set APP_PORT=4000; FE expects 4000
go run ./cmd/main.go                # HTTP API on :4000
go run ./cmd/logwriter              # separate process; without it nothing reaches SQLite

# verification order after Go changes
gofmt -l . && go build ./... && go vet ./... && go test ./...
go test ./analysis/policy -run TestDecide -v     # single package / single test

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
  by both `cmd/main.go` and `cmd/logwriter`). Template: `config/env_example`.
- `CLASSIFIER_API_KEY` belongs only in `scanner-service/config/.env`. Never put it
  in `fe-analysis/.env` — Vite inlines `VITE_*` variables into the public bundle.
- CORS origins are hardcoded for `localhost:5173`/`5174` in `app/app.go`.

## Codebase facts

- Scan pipeline lives in `app/scanner/handler/scanner_handler.go`: ClamAV →
  analyzer → evidence → classifier → policy → quarantine → Kafka publish, per
  file. Completed scans always return HTTP 200; `4xx` is only invalid requests.
- `analysis/` is dependency-clean Go: `evidence` is a leaf; `analyzer`, `classifier`
  and `policy` build on it. Policy is a pure function (`policy.Decide`,
  escalate-only max-severity over signals) — put new decision rules there, not in
  handlers. New analyzer = implement `Analyzer` and register in `app/app.go`.
- SQLite schema and migrations: `infra/sqlite/sqlite.go`. Migrations are additive
  (`PRAGMA table_info` + `ALTER TABLE`) and run in the order create table →
  migrate → indexes; index statements referencing new columns must not run before
  the migration. Dev reset: stop scanner + logwriter, `rm -rf data/`.
- Kafka inserts are idempotent per unique `(request_id, filename, sha256)`.
- Only non-`ALLOW` verdicts are published to Kafka; set `PUBLISH_ALL_VERDICTS=true`
  for evaluation runs.
- Quarantine writes `data/quarantine/<sha256>` with mode `0600`; nothing is ever
  executed or auto-deleted.
- classifier.dev: no API key needed; `confidence` can be `null` and means label
  fit, not malware probability; store the returned `model` per scan. Client
  retries `429`/`5xx` with `Retry-After`, never `4xx`.

## Testing quirks

- Tests never call classifier.dev live: the client is covered with `httptest`.
- The PE analyzer is tested against a hand-built PE fixture in
  `analysis/analyzer/pe_test.go`; no binary fixtures are committed.
- End-to-end smoke test needs clamav running:
  `printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt`
  then `curl -s -F files=@/tmp/eicar.txt http://localhost:4000/api/scanner/scan`.
