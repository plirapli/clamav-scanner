# ClamAV Scanner + Static Analysis + Classifier

Hybrid malware triage pipeline. ClamAV handles known threats; files it does not
detect are analyzed statically (PE for now) and assessed by
[classifier.dev](https://classifier.dev); a deterministic policy turns the
signals into an actionable verdict.

```text
upload ──> validation ──> ClamAV ──detected──> BLOCK
                             │
                        not detected
                             │
                    static analysis (PE)
                             │
                       evidence object
                             │
                        classifier.dev
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
| `fe-analysis` | React + Vite + Tailwind | Upload page with per-file verdict card + log dashboard |
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
│   ├── analyzer/       # Analyzer interface + PE analyzer (debug/pe)
│   ├── classifier/     # Classifier interface + classifier.dev client
│   ├── evidence/       # FileEvidence model + evidenceToText()
│   └── policy/         # deterministic verdict engine (pure function)
├── app/                # Fiber app: routes, handlers, repos
├── cmd/                # main (scanner) + logwriter (Kafka → SQLite)
├── config/             # env_example + .env (gitignored)
├── core/               # entities + interfaces
├── docs/               # swagger.yaml + Swagger UI
├── infra/              # clamav, kafka, sqlite, quarantine clients
└── data/               # gitignored: scanner.db + quarantine/
fe-analysis/            # React dashboard + upload UI
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
cp config/env_example config/.env  # then set APP_PORT=4000 (8080 is often taken by other stacks)
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

All settings live in `scanner-service/config/.env` (gitignored; `env_example` is
the template):

| Key | Default | Notes |
| --- | --- | --- |
| `APP_PORT` / `APP_NAME` | `8080` / `scanner-service` | app name is stored as `application` in logs |
| `KAFKA_BROKERS` / `KAFKA_TOPIC` | `localhost:39092` / `scan-logs` | external port is `39092` because `29092` is used by another local project |
| `SQLITE_PATH` | `data/scanner.db` | additive migrations run at startup |
| `CLAMAV_ADDR` | `127.0.0.1:3310` | |
| `CLASSIFIER_ENABLED` / `CLASSIFIER_URL` / `CLASSIFIER_TIER` | `true` / `https://classifier.dev` / `fast` | `CLASSIFIER_ENABLED=false` runs fully offline (static rules still apply) |
| `CLASSIFIER_API_KEY` | empty | **server-side only**; never put it in `fe-analysis/.env` |
| `CLASSIFIER_LABELS` | `benign,suspicious,malicious,insufficient-evidence` | `insufficient-evidence` acts as "none of the above" |
| `VERDICT_BLOCK_CONFIDENCE` | `0.95` | `malicious` below this becomes `QUARANTINE` |
| `STATIC_RULES_ENABLED` / `SUSPICIOUS_IMPORTS_MIN` | `true` / `3` | packed+unsigned or many suspicious imports+unsigned → `QUARANTINE` |
| `QUARANTINE_DIR` / `QUARANTINE_ENABLED` | `data/quarantine` / `true` | files stored as `<sha256>`, mode `0600`, never executed |
| `PUBLISH_ALL_VERDICTS` | `false` | `true` also publishes `ALLOW` results (evaluation mode) |
| `MAX_FILES_PER_REQUEST` | `10` | |

Secrets and data (`config/.env`, `data/`) are gitignored. The classifier API key
is only read by the Go service; the frontend never talks to classifier.dev.

## API

```http
POST /api/scanner/scan     # multipart "files" or raw body; no auth; CORS allows localhost:5173/5174
GET  /api/scanner/logs     # ?virus_name=&application=&verdict=&limit=&skip=
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
entropy, packing hints, digital signature, imports) and `classifier`
(label, confidence, scores, model). Non-PE files report
`static_analysis.supported = false` and are not sent to the classifier.

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

Signals can only escalate a verdict, never downgrade it.

## classifier.dev notes

- Zero-shot **text** classifier; only the evidence summary is sent, never the file.
- No API key required; free tier is rate limited per IP (fast: 3,000/min,
  20,000/day). An optional key (Pro) raises the quota; put it in
  `CLASSIFIER_API_KEY`.
- `confidence` measures which supplied label fits best — it is **not** the
  probability of malware. It can be `null`; the policy treats null as
  `QUARANTINE`.
- The returned `model` version is stored per scan for reproducibility.
- Client behavior: 10s timeout, retry on `429`/`5xx` with `Retry-After` (max 2),
  never retries `4xx`.

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

Tests cover the PE analyzer (synthetic PE fixtures, entropy, packing), evidence
text (deterministic + bounded), classifier client (httptest: retry, 401, null
confidence) and the policy table. No live classifier calls in tests.

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

## Roadmap

`plan.md` is the specification. Next phases (sections 20–23):

1. **Phase 8** — evaluation harness (`cmd/eval`): collect raw pipeline output over
   a local corpus, then sweep thresholds offline to calibrate
   `VERDICT_BLOCK_CONFIDENCE` and `SUSPICIOUS_IMPORTS_MIN`.
2. **Phase 9** — scan cache keyed by SHA-256 (ClamAV still runs; evidence and
   classifier output are reused, policy is recomputed).
3. **Phase 10** — non-PE coverage: generic analyzer (embedded PE, URLs, scripts),
   PDF (JS/auto-open), Office (macros/external targets), archives (nested
   executables).
