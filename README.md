# ClamAV Scanner + Static Analysis + Classifier

Hybrid malware triage pipeline. ClamAV handles known threats; files it does not
detect are analyzed statically (PE, PDF, Office, archive, script and generic
binaries) and assessed by Cloudflare Workers AI
[Clef](https://developers.cloudflare.com/workers-ai/models/clef/); a deterministic
policy turns the signals into an actionable verdict. An evaluation harness and a
dashboard tab measure how well the pipeline separates malware from benign files.

```text
upload ──> validation ──> ClamAV ──detected──> BLOCK
                             │
                        not detected
                             │
    static analysis (PE, PDF, Office, archive, script)
                             │
                       evidence object
                             │
                   Cloudflare Clef
                             │
                  ┌──────────┼──────────┐
               BENIGN    SUSPICIOUS  MALICIOUS
                  │          │          │
                ALLOW    QUARANTINE   BLOCK
                             │
                  Kafka → logwriter → SQLite → dashboard
```

- **Detection ≠ evidence ≠ assessment ≠ decision.** Each layer is reported
  separately in the API so results stay explainable.
- A ClamAV miss is not a clean verdict; high entropy is not malware.
- The full specification and roadmap live in [`plan.md`](plan.md).

## Components

| Component | Tech | Role |
| --- | --- | --- |
| `scanner-service` | Go + Fiber | HTTP API: scan files, list logs, static analysis, classifier, policy |
| `scanner-service/cmd/logwriter` | Go | Kafka consumer writing scan logs into SQLite |
| `scanner-service/cmd/eval` | Go | Evaluation harness: corpus fetchers, collect, analyze |
| `fe-analysis` | React + Vite + Tailwind | Log dashboard, upload page with per-file verdict card, evaluation results |
| `clamav` | Docker (`clamav/clamav-debian`) | Signature scanner on `localhost:3310` |
| `kafka` | Docker (`apache/kafka:3.7.0`) | Event bus, external listener `localhost:39092` |
| `kafka-init` | Docker | One-shot creation of the `scan-logs` topic |
| `kafka-ui` | Docker | Broker UI at http://localhost:8090 |
| SQLite | `scanner-service/data/scanner.db` (WAL) | Scan log storage |

Removed on purpose (do not reintroduce): `be-analysis`, MongoDB, PostgreSQL,
Kafka Connect, Mongo sink `config.json`, Vite `/analysis` proxy.

## Repository layout

```text
scanner-service/
├── analysis/
│   ├── analyzer/       # PE (+ Authenticode), PDF, Office, archive, script, generic
│   ├── classifier/     # Classifier interface + Cloudflare Clef client
│   ├── evidence/       # FileEvidence model + evidenceToText()
│   └── policy/         # deterministic verdict engine (pure function)
├── app/                # Fiber app: routes, handlers, repos
├── cmd/                # main (scanner), logwriter (Kafka → SQLite), eval (harness)
├── config/             # .env.example + .env (gitignored)
├── core/               # entities + interfaces
├── docs/               # swagger.yaml + Swagger UI
├── infra/              # clamav, kafka, sqlite, quarantine clients
└── data/               # gitignored: scanner.db + quarantine/
fe-analysis/            # React dashboard, upload UI, Evaluation tab
eval/                   # manifest.json + benign-sources.tsv (committed); corpus/ + results/ (gitignored)
docker-compose.yml      # clamav, kafka, kafka-init, kafka-ui
start.sh                # docker compose up (run with `sh start.sh`)
plan.md                 # specification + roadmap (source of truth)
```

## Prerequisites

- Docker (Docker Desktop or OrbStack) with Compose
- Go 1.25+ (the toolchain auto-downloads if your local Go is older)
- Node 20+ / npm
- `sqlite3` CLI (optional, for inspecting `data/scanner.db`)

## Quick start

```bash
# 1. Infrastructure (clamav, kafka, kafka-init, kafka-ui)
sh start.sh                      # start.sh is not executable; do not call ./start.sh

# 2. Scanner service
cd scanner-service
cp config/.env.example config/.env  # then set CLOUDFLARE_ACCOUNT_ID / CLOUDFLARE_API_TOKEN
go run ./cmd/main.go               # http://localhost:4000

# 3. Log writer (separate terminal; without it nothing lands in SQLite)
cd scanner-service
go run ./cmd/logwriter

# 4. Frontend (separate terminal)
cd fe-analysis
npm install
npm run dev                      # http://localhost:5173, falls back to 5174
```

Ports: scanner `4000`, Kafka external `39092`, kafka-ui `8090`, ClamAV `3310`,
Vite `5173`/`5174`.

## Configuration

All settings live in `scanner-service/config/.env` (gitignored; `.env.example` is
the template):

| Key | Default | Notes |
| --- | --- | --- |
| `APP_PORT` / `APP_NAME` | `8080` / `scanner-service` | template sets `4000` (what the frontend expects); app name is stored as `application` in logs |
| `KAFKA_BROKERS` / `KAFKA_TOPIC` | `localhost:39092` / `scan-logs` | external port is `39092` because `29092` is used by another local project |
| `SQLITE_PATH` | `data/scanner.db` | additive migrations run at startup |
| `CLAMAV_ADDR` | `127.0.0.1:3310` | |
| `CLASSIFIER_ENABLED` / `CLASSIFIER_MODEL` | `true` / `clef` | `clef` or `clef-flash`; `CLASSIFIER_ENABLED=false` runs fully offline (static rules still apply) |
| `CLOUDFLARE_ACCOUNT_ID` / `CLOUDFLARE_API_TOKEN` | empty | required when the classifier is enabled (token needs Workers AI read); **server-side only**, never put them in `fe-analysis/.env` |
| `CLASSIFIER_BASE_URL` / `CLASSIFIER_TIMEOUT` | `https://api.cloudflare.com/client/v4` / `30s` | |
| `CLASSIFIER_LABELS` | `benign,suspicious,malicious,insufficient-evidence` | `insufficient-evidence` acts as "none of the above" |
| `VERDICT_BLOCK_CONFIDENCE` | `0.95` | `malicious` below this becomes `QUARANTINE` |
| `STATIC_RULES_ENABLED` / `SUSPICIOUS_IMPORTS_MIN` | `true` / `3` | packed+unsigned or many suspicious imports+unsigned → `QUARANTINE` |
| `GENERIC_RULES_ENABLED` | `true` | PDF JS+auto-open, macros+external, embedded PE, archive exe, obfuscated scripts → `QUARANTINE` |
| `ENCRYPTED_VERDICT` | `QUARANTINE` | verdict for encrypted/password-protected files (ClamAV `Heuristics.Encrypted.*` or analyzer evidence) |
| `CACHE_ENABLED` / `CACHE_TTL` | `true` / `168h` | cache keyed by SHA-256; `0` TTL = never expire |
| `CACHE_ERROR_TTL` / `CACHE_MAX_ENTRIES` | `15m` / `100000` | failed classifications are retried after the cooldown |
| `QUARANTINE_DIR` / `QUARANTINE_ENABLED` | `data/quarantine` / `true` | files stored as `<sha256>`, mode `0600`, never executed |
| `PUBLISH_ALL_VERDICTS` | `false` | `true` also publishes `ALLOW` results (evaluation mode) |
| `MAX_FILES_PER_REQUEST` | `10` | |
| `EVAL_RESULTS_DIR` | `../eval/results` | run directories shown on the frontend Evaluation tab |
| `MALWAREBAZAAR_API_KEY` | empty | eval only: `cmd/eval fetch-malware` ([free key](https://auth.abuse.ch/)) |

Secrets and data (`config/.env`, `data/`) are gitignored. The Cloudflare API token
is only read by the Go service; the frontend never talks to Cloudflare.

## API

```http
POST /api/scanner/scan     # multipart "files" or raw body; no auth; CORS allows localhost:5173/5174
GET  /api/scanner/logs     # ?virus_name=&application=&verdict=&sort=&order=&limit=&skip=
GET  /api/scanner/logs/summary  # per-virus / per-application counts for the same filters
GET  /api/eval/runs        # local eval runs under EVAL_RESULTS_DIR (frontend Evaluation tab)
GET  /api/eval/runs/:name  # summary.json + per-sample verdicts with the current policy
GET  /swagger              # Swagger UI (served from docs/)
```

A completed scan always returns `200`; the outcome is in `verdict`. `4xx` is
reserved for invalid requests.

```bash
# quick pipeline check (EICAR test string)
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt
curl -s -F files=@/tmp/eicar.txt http://localhost:4000/api/scanner/scan
```

```json
{
  "code": 200,
  "status": "success",
  "message": "scan completed",
  "request_id": "9c4c2052b26a07c849a216215d6c800f",
  "data": {
    "files": [
      {
        "name": "eicar.txt",
        "sha256": "275a021b…",
        "status": "infected",
        "verdict": "BLOCK",
        "verdict_reasons": ["clamav: detected (Eicar-Test-Signature)"],
        "quarantined": true,
        "clamav": { "detected": true, "signature": "Eicar-Test-Signature" }
      }
    ]
  }
}
```

PE files that ClamAV misses additionally carry `static_analysis` (kind, sections,
entropy, packing hints, overlay, imports, .NET flag, Authenticode signer and
`signature_status`) and `classifier` (label, confidence, scores, model).
`signature_status` is `valid` when the file digest and signature match the file,
`invalid` when the signature was copied or the file was modified (then
`has_digital_signature` is `false`), or `unverified`. The certificate chain is not
validated, so `valid` proves integrity, not that the publisher is trustworthy. Non-PE files are analyzed by kind — `pdf`,
`office`, `archive`, `script`, `text`/`binary` — with generic evidence
(JavaScript, macros, external targets, nested executables, URLs, obfuscation).
Truly unrecognized files report `static_analysis.supported = false` unless they
contain signals such as an embedded executable, and are otherwise not classified.
Repeat scans of identical bytes report `"cached": true`.

### Verdict policy (deterministic, escalate-only)

| Signal | Verdict |
| --- | --- |
| ClamAV detected | `BLOCK` |
| ClamAV error / unscannable | `QUARANTINE` (`FAIL_MODE`) |
| Non-PE (unsupported type) | `ALLOW` + `analysis skipped` |
| Classifier `malicious` with confidence ≥ `VERDICT_BLOCK_CONFIDENCE` | `BLOCK` |
| Classifier `malicious` / `suspicious` / `insufficient-evidence` / null confidence | `QUARANTINE` |
| Classifier error / timeout | `QUARANTINE` (`FAIL_MODE`) |
| Classifier `benign` | `ALLOW` |
| Static rule: packed + unsigned, or ≥ `SUSPICIOUS_IMPORTS_MIN` suspicious imports + unsigned | `QUARANTINE` (`STATIC_RULE_VERDICT`) |
| Encrypted / password-protected (ClamAV `Heuristics.Encrypted.*` or analyzer evidence) | `QUARANTINE` (`ENCRYPTED_VERDICT`) |

Signals can only escalate a verdict, never downgrade it.

## Clef notes

- `POST {CLASSIFIER_BASE_URL}/accounts/{CLOUDFLARE_ACCOUNT_ID}/ai/run/@cf/cloudflare/{CLASSIFIER_MODEL}`
  with one `choice` question (`verdict`) whose options are `CLASSIFIER_LABELS`;
  only the evidence summary is sent as `state`, never the file.
- Billed per input token ($0.24/M for `clef`); no output-token charge.
- `confidence` is the probability Clef assigns to the chosen label among the
  supplied labels — it is **not** the probability of malware. All label
  probabilities are stored as `scores`. A missing probability means `null`
  confidence, which the policy treats as `QUARANTINE`.
- Missing `CLOUDFLARE_ACCOUNT_ID`/`CLOUDFLARE_API_TOKEN` is a classifier error
  (`FAIL_MODE`), not a silent skip.
- The returned `model` is stored per scan for reproducibility.
- Client behavior: 30s timeout, retry on `429`/`5xx` with `Retry-After` (max 2),
  never retries `4xx`.
- Clef is deterministic: identical evidence gives identical scores. The label
  descriptions sent with the question live in `analysis/classifier/clef.go`;
  re-run the eval after changing them.

## Storage & data flow

- `scanner-service` publishes non-`ALLOW` results to Kafka topic `scan-logs`
  (`PUBLISH_ALL_VERDICTS=true` publishes everything).
- `cmd/logwriter` consumes with group `scan-log-sqlite-writer` and inserts into
  `data/scanner.db` (`scan_logs`, WAL mode). Existing message replay is safe:
  inserts are idempotent per `(request_id, filename, sha256)`.
- Verdicts `QUARANTINE`/`BLOCK` also write the raw bytes to
  `data/quarantine/<sha256>` (mode `0600`). Nothing is deleted automatically;
  clean up manually.
- Development reset: stop scanner and logwriter, then `rm -rf data/`.

## Evaluation

The evaluation harness runs the same components in-process over a local corpus
(ClamAV must be running):

```bash
cd scanner-service
go run ./cmd/eval fetch-benign         # download eval/benign-sources.tsv into eval/corpus/
go run ./cmd/eval fetch-malware        # recent MalwareBazaar samples ClamAV misses (needs MALWAREBAZAAR_API_KEY + 7z)
go run ./cmd/eval collect -out ../eval/results/my-run   # ClamAV + analyzers + Clef -> raw.jsonl
go run ./cmd/eval collect -no-classifier
go run ./cmd/eval analyze -in ../eval/results/my-run    # summary.json + report.md, no network calls
```

`analyze` replays the policy across threshold grids and writes `summary.json` +
`report.md` (recall/FP per threshold, rule-only vs classifier-only vs combined,
ClamAV-miss coverage, latency, model versions). Every run also appears in the
frontend **Evaluation** tab (metrics, variants, threshold grid, per-category
breakdown, filterable samples), with per-sample verdicts recomputed using the
scanner's current policy.

Samples live in `eval/corpus/` and are never committed; malware stays there with
mode `0600` and Spotlight indexing disabled. See `eval/README.md`. To show the
corpus in the log dashboard as well, set `PUBLISH_ALL_VERDICTS=true` and upload
it through `POST /api/scanner/scan`.

## Testing

```bash
# Go: all tests, or a focused package/test
cd scanner-service
go test ./...
go test ./analysis/policy -run TestDecide -v
go build ./... && go vet ./...

# Frontend
cd fe-analysis
npm run lint                     # oxlint
npm run build                    # tsc -b && vite build
```

Tests cover the analyzers (synthetic PE fixtures, packing, corrupt symbol tables,
Authenticode valid vs tampered, format fixtures), evidence text (deterministic +
bounded), the Clef client (httptest: envelope, retry, 401, missing credentials),
the policy table, cache/handlers and the eval API. No live classifier calls in
tests.

## Troubleshooting

- **`sh start.sh` needed** — the script has no executable bit.
- **Kafka publish fails with `Unknown Topic Or Partition`** — the topic must
  exist before the scanner publishes. `kafka-init` creates it; if the scanner
  started earlier, restart the scanner (kafka-go caches the missing-topic
  metadata). Check with
  `docker compose exec kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list`.
- **Kafka dies with "unable to register with the controller quorum"** — the
  container failed to join its network, usually because a host port is taken
  (e.g. another project on `29092`). Verify with `docker compose ps` and
  `docker inspect kafka --format '{{.NetworkSettings.Networks}}'`.
- **Apple Silicon** — ClamAV must use the `clamav/clamav-debian` image (the
  `clamav/clamav` image is amd64-only). Healthcheck runs
  `clamdscan --ping=5` (the `--ping` flag needs an argument).
- **Vite on 5174** — port 5173 may be taken by another project; CORS in
  `scanner-service/app/app.go` whitelists both ports.
- **No logs in the dashboard** — `cmd/logwriter` is a separate process and must
  be running; `ALLOW` files are not published by default.
- **Evaluation tab is empty** — it lists directories under `EVAL_RESULTS_DIR`
  that contain `raw.jsonl`; run `cmd/eval collect` (and `analyze` for the
  tables), and restart the scanner after changing the setting.

## Roadmap

`plan.md` is the specification. Phases 8–10 are implemented:

1. **Phase 8** — evaluation harness (`cmd/eval` + `eval/`), threshold grids and
   reports. Thresholds remain experimental until a representative corpus is run.
2. **Phase 9** — scan cache keyed by SHA-256 (ClamAV still runs; evidence and
   classifier output are reused, policy is recomputed).
3. **Phase 10** — non-PE coverage: generic, PDF, Office, archive and script
   analyzers with deterministic generic rules.

Current eval (200 samples: 120 recent MalwareBazaar samples ClamAV misses, 74
benign): 88% of malware caught, 47% of benign files flagged. Remaining work:

- Benign false positives: PDFs, macro documents, archives with executables and
  unsigned installers are mostly quarantined.
- Signature trust: validate Authenticode chains against code-signing roots
  before letting a trusted signer influence the verdict.
- Thresholds: no Clef `malicious` label reaches 0.8 yet, so
  `VERDICT_BLOCK_CONFIDENCE` does not change any verdict in the current corpus.
