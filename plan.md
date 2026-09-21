# ClamAV Scanner + Static Analysis + Classifier

## 1. Project Goal

Extend the existing ClamAV scanner into a hybrid malware triage pipeline.

The current project performs file scanning with ClamAV and stores infected-file
metadata in SQLite. The next version adds a static-analysis + zero-shot
classification layer using `classifier.dev`.

The goal is not to replace ClamAV. Instead:

- ClamAV remains the first line of defense for known threats.
- Static analysis extracts observable characteristics from files that ClamAV does not detect.
- `classifier.dev` evaluates those characteristics and estimates how suspicious the file is.
- Application code applies deterministic security policy to produce the final result.

The previous AI-analysis component (`be-analysis`), MongoDB, PostgreSQL, and
Kafka Connect are no longer part of the project and must not be reintroduced.

### Core question

> Can static file characteristics combined with zero-shot classification identify suspicious files that are not detected by ClamAV's signature database?

---

## 2. Current Project State

This section describes what exists today. The plan below evolves this state; it
does not assume the old architecture.

### Components

| Component | Tech | Role |
| --- | --- | --- |
| `scanner-service` | Go + Fiber | HTTP API: scan files, list infected logs |
| `cmd/logwriter` | Go | Kafka consumer that writes scan logs into SQLite |
| `fe-analysis` | React + Vite + Tailwind | Upload page + infected-log dashboard |
| `clamav` | Docker `clamav/clamav-debian` | Signature scanner (host port `3310`) |
| `kafka` | Docker `apache/kafka:3.7.0` | Event bus (external listener `localhost:39092`) |
| `kafka-init` | Docker | One-shot topic creation for `scan-logs` |
| `kafka-ui` | Docker | Broker UI (host port `8090`) |
| SQLite | `data/scanner.db` (WAL) | Scan log storage |

Removed and out of scope: `be-analysis`, MongoDB, Kafka Connect, PostgreSQL
(`ddl.sql`), `config.json` (Mongo sink config), Vite `/analysis` proxy, AI
analysis UI.

### Current flow

```text
fe-analysis ──POST /api/scanner/scan──> scanner-service (:4000)
                                              │
                                       ClamAV (streamed)
                                              │
                                     infected files only
                                              │
                                         Kafka topic
                                          scan-logs
                                              │
                                      cmd/logwriter
                                              │
                                     data/scanner.db
                                              │
                 fe-analysis <──GET /api/scanner/logs── scanner-service
```

### Current API

```http
POST /api/scanner/scan     # multipart "files" or raw body; no auth; CORS whitelist 5173/5174
GET  /api/scanner/logs     # ?virus_name=&application=&limit=&skip= ; infected only
GET  /swagger              # static OpenAPI docs
```

### Current limitations relevant to this plan

- Only infected files are persisted; clean/undetected files are discarded.
- No file validation beyond the body limit (`MAX_SCAN_SIZE`, default 25 MiB).
- No static analysis, no classification, no quarantine storage.
- Response is per file: `status` is `clean | infected | failed`.

### Configuration (scanner-service `config/.env`)

```text
APP_PORT=4000
APP_NAME=scanner-service
KAFKA_BROKERS=localhost:39092
KAFKA_TOPIC=scan-logs
KAFKA_GROUP_ID=scan-log-sqlite-writer
SQLITE_PATH=data/scanner.db
CLAMAV_ADDR=127.0.0.1:3310
MAX_SCAN_SIZE=26214400
```

---

## 3. Target Architecture

```text
                         ┌──────────────────┐
                         │   File Upload    │
                         └────────┬─────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │ File Validation  │
                         │ size / name /    │
                         │ MZ magic / hash  │
                         └────────┬─────────┘
                                  │
                                  ▼
                            ┌───────────┐
                            │  ClamAV   │
                            └─────┬─────┘
                                  │
                     ┌────────────┴────────────┐
                     │                         │
                  DETECTED                 NOT DETECTED
                     │                         │
                     ▼                         ▼
                   BLOCK              Static Analysis
                                               │
                                               ▼
                                        Evidence Object
                                               │
                                               ▼
                                       classifier.dev
                                               │
                                  ┌────────────┼────────────┐
                                  ▼            ▼            ▼
                               BENIGN      SUSPICIOUS    MALICIOUS
                                  │            │            │
                                  ▼            ▼            ▼
                                ALLOW      QUARANTINE      BLOCK
```

### Responsibility of each layer

#### ClamAV

Answers:

> Does the file match a known threat/signature?

ClamAV is deterministic and remains the primary known-threat scanner.

#### Static Analysis

Answers:

> What observable characteristics does this file have?

It extracts evidence without producing the final malware verdict.

MVP examples (PE only):

- File type, architecture, file size, SHA-256
- Section list, section entropy, maximum entropy
- Packing indicators
- Digital signature (Authenticode) presence
- Import table and suspicious import list

#### classifier.dev

Answers:

> Given the extracted evidence, how suspicious does this file appear?

The classifier receives a text summary of the evidence, never the uploaded binary.

#### Application Policy

Answers:

> What should the system actually do with this result?

The final `ALLOW`, `QUARANTINE`, or `BLOCK` decision is deterministic
application logic, implemented separately from the classifier client.

---

## 4. Repository Changes

The existing project is evolved, not rewritten.

### Already removed (do not reintroduce)

```text
be-analysis/            # AI analysis service
config.json             # Mongo sink connector config
ddl.sql                 # PostgreSQL schema
MongoDB, Kafka Connect  # services and volumes
```

### Keep

```text
scanner-service/
fe-analysis/
docker-compose.yml
start.sh
company.ndb             # custom ClamAV signature (optional test asset)
```

The existing structure and naming conventions must be preserved where practical.

### Add (inside `scanner-service`, no new service)

```text
scanner-service/
├── analysis/
│   ├── analyzer/
│   │   ├── analyzer.go        # Analyzer interface + registry
│   │   └── pe.go              # PE analyzer (debug/pe)
│   ├── classifier/
│   │   ├── classifier.go      # FileClassifier interface + result types
│   │   └── classifierdev.go   # classifier.dev HTTP client
│   ├── evidence/
│   │   └── evidence.go        # FileEvidence model + evidenceToText()
│   └── policy/
│       └── policy.go          # deterministic verdict engine
├── core/scanner/...           # existing entities/interfaces/repositories
└── app/scanner/...            # existing handlers/routes
```

Rationale: the analysis layer is pure Go, has no new runtime, receives the file
bytes already held by the scanner, and can call `classifier.dev` over plain HTTP.
A separate TypeScript service would add a container and a file-handoff boundary
for no benefit. The `FileClassifier` and `Analyzer` interfaces keep both layers
replaceable.

`company.ndb` may be mounted into ClamAV for testing custom signatures:

```yaml
# optional, docker-compose.yml
volumes:
  - ./company.ndb:/var/lib/clamav/company.ndb:ro
```

---

## 5. End-to-End Request Flow

### Step 1 — Upload and validation

The frontend keeps using the existing endpoint:

```http
POST /api/scanner/scan
Content-Type: multipart/form-data
```

Immediately collect:

```json
{
  "filename": "example.exe",
  "size": 481231,
  "mime": "application/vnd.microsoft.portable-executable",
  "sha256": "..."
}
```

Validate:

- Maximum file size (existing `MAX_SCAN_SIZE` / Fiber `BodyLimit`)
- Filename is sanitized (`filepath.Base`, existing behavior)
- Maximum number of files per request (new, suggested: 10)
- Request timeout (new)
- Never execute the uploaded file
- Total memory budget: files are processed in memory; cap `files × size`

PE detection is by magic bytes (`MZ` + successful `debug/pe` parse), not by
extension alone. Non-PE files do not fail validation; they take the fallback path
described in Step 3.

### Step 2 — ClamAV scan

Reuse the existing streaming client (`infra/clamav`). Result per file:

```json
{ "detected": true,  "signature": "Win.Trojan.Example" }
{ "detected": false, "signature": null }
```

If detected:

```text
ClamAV → DETECTED → BLOCK (skip static analysis and classifier)
```

If not detected, continue to Step 3.

If ClamAV itself errors (daemon unreachable/timeout):

- Record `scan_error` for the file.
- Skip the classifier.
- Verdict defaults to `QUARANTINE` (fail-closed) and is configurable
  (`FAIL_MODE=quarantine|allow`).

> ClamAV not detecting a file does not mean the file is safe. It means the
> current scan did not identify a threat.

### Step 3 — Static analysis (PE for MVP)

Supported: PE32/PE32+ executables and DLLs.

Unsupported types (PDF, DOCX, JS, archives, ...) are marked
`static_analysis.supported = false`. Default policy for unsupported files:
`ALLOW` with an explicit `analysis_skipped` reason, so the UI never implies the
file was analyzed. This default is configurable but must not silently change.

### Step 4 — Evidence object

See section 7. Built in Go, no file bytes leave the process except the text
summary sent to `classifier.dev`.

### Step 5 — Evidence to classifier input

See section 8. Deterministic, canonical text, capped at 2,000 characters.

### Step 6 — Classification

See section 9. One `POST https://classifier.dev` request per file, `tier: "fast"`.

### Step 7 — Deterministic policy

See section 10. Runs after ClamAV, static analysis, and classification have all
settled (including error/null cases).

### Step 8 — Quarantine action

See section 11. `QUARANTINE` and `BLOCK` verdicts persist the file bytes to a
local quarantine directory; nothing is ever executed or deleted automatically.

### Step 9 — Persistence

Non-`ALLOW` verdicts are published to Kafka (`scan-logs`) as today, with the
extended payload; `cmd/logwriter` writes them to SQLite. `ALLOW` results are
published only when `PUBLISH_ALL_VERDICTS=true` (used for evaluation runs).

### Step 10 — Response

See section 12. Per-file verdict, evidence, and classifier output.

---

## 6. Static Analysis — PE Features

MVP extracts:

```json
{
  "file_type": "PE32+",
  "architecture": "x86_64",
  "is_dll": false,
  "is_signed": false,
  "entry_point_section": ".text",
  "sections": [
    { "name": ".text",   "size": 123456, "entropy": 6.10, "writable": false, "executable": true },
    { "name": ".packed", "size": 234567, "entropy": 7.94, "writable": true,  "executable": true }
  ],
  "max_entropy": 7.94,
  "has_packed_section": true,
  "has_digital_signature": false,
  "packer_hints": ["high-entropy executable section", "section name resembles packer"],
  "imports_count": 7,
  "suspicious_imports": [
    "VirtualAlloc",
    "WriteProcessMemory",
    "CreateRemoteThread"
  ]
}
```

### Go implementation notes

- Use the standard library `debug/pe`. No new dependency is required:
  - `pe.NewFile(bytes.NewReader(data))`
  - `f.Sections` + `section.Data()` for entropy
  - `f.OptionalHeader.(*pe.OptionalHeader64/.OptionalHeader32)` for architecture,
    entry point, and `DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY]` to detect
    an Authenticode certificate table
  - `f.ImportedSymbols()` / `f.ImportedLibraries()` for imports
- Entropy: Shannon entropy over each section's raw bytes (0–8).
- Suspicious imports: curated, configurable list (process injection, anti-debug,
  crypto, persistence, network APIs). Store hits, not everything.
- Packing heuristics — do not rely on a single `max_entropy > X` check:
  - high entropy (> 7.2) on an executable section
  - section name matches known packers (UPX0/UPX1, .aspack, .petite, ...)
  - virtual size >> raw size (or the reverse)
  - very few imports for a large binary
  - entry point outside the first executable section
  - writable + executable section
- Cap analysis work per file (section count, import count, evidence size).

### Important interpretation

Entropy is evidence, not a verdict.

```text
7.94 entropy   → compressed, encrypted, packed, or obfuscated data
high entropy  != malware
```

Legitimate installers and self-extracting archives are often high-entropy and
unsigned. The classifier receives entropy together with all other evidence.

---

## 7. Evidence Object (Go model)

```go
type FileEvidence struct {
    File struct {
        Name   string `json:"name"`
        Size   int64  `json:"size"`
        MIME   string `json:"mime"`
        SHA256 string `json:"sha256"`
    } `json:"file"`

    ClamAV struct {
        Detected  bool   `json:"detected"`
        Signature string `json:"signature,omitempty"`
        Error     string `json:"error,omitempty"`
    } `json:"clamav"`

    StaticAnalysis struct {
        Supported            bool     `json:"supported"`
        FileType             string   `json:"file_type,omitempty"`
        Architecture         string   `json:"architecture,omitempty"`
        MaxEntropy           float64  `json:"max_entropy,omitempty"`
        HasPackedSection     bool     `json:"has_packed_section"`
        HasDigitalSignature  bool     `json:"has_digital_signature"`
        PackerHints          []string `json:"packer_hints,omitempty"`
        SuspiciousImports    []string `json:"suspicious_imports,omitempty"`
        ImportsCount         int      `json:"imports_count,omitempty"`
        Error                string   `json:"error,omitempty"`
    } `json:"static_analysis"`
}
```

This object is the central input to the classification layer and is also what
gets persisted (`evidence_json`).

---

## 8. Evidence to Classifier Input

Do not upload the binary. Convert evidence into a short, canonical text.
Rules:

- Fixed order and formatting, sorted lists, two-decimal numbers (reproducible).
- Omit empty fields; state explicitly when analysis was skipped.
- Maximum 2,000 characters (safe for both classifier.dev tiers).

Example:

```text
File type: PE32+ executable.
Architecture: x86_64.

Maximum section entropy: 7.94.
A packed section is present (high-entropy executable section).
The executable is not digitally signed.
Number of imports: 7.

Suspicious imports detected:
- VirtualAlloc
- WriteProcessMemory
- CreateRemoteThread

ClamAV did not detect a known malware signature.
```

For unsupported types the text is not sent to the classifier; the policy layer
short-circuits to the skipped-analysis path.

---

## 9. Classification with classifier.dev

Verified behavior (per classifier.dev docs, 2026):

- Endpoint: `POST https://classifier.dev` with JSON
  `{"input": "<text>", "labels": [...], "tier": "fast"}`.
- Zero-shot **text** classifier; no API key required for free use (optional
  bearer key for paid tiers).
- Free limits per IP: fast 3,000 classifications/minute and 20,000/day.
  One single-label decision = one classification.
- Response:

```json
{
  "tier": "fast",
  "model": "jev-1.13.0",
  "results": [
    {
      "label": "suspicious",
      "confidence": 0.91,
      "scores": { "benign": 0.03, "suspicious": 0.91, "malicious": 0.06, "insufficient-evidence": 0 },
      "model": "jev-1.13.0"
    }
  ],
  "usage": { "classifications": 1, "escalated": 0, "ms": 260 }
}
```

### Labels

Use these labels for the single-label decision:

```text
benign
suspicious
malicious
insufficient-evidence
```

`insufficient-evidence` is required: classifier.dev confidence measures which of
the supplied labels fits best, not whether any of them fits. Without an explicit
"none of these" label, every evidence text is forced into a risk label.

### Client requirements

- Interface: `FileClassifier.classify(ctx, evidence) (ClassificationResult, error)`
- Implementation `ClassifierDev` hidden behind the interface (replaceable).
- Timeout per call (suggested 10s) using `context`.
- Retry on 429/5xx with `Retry-After` and exponential backoff (max 2 retries);
  never retry on 4xx input errors.
- Confidence and scores may be `null`; **check for null before comparing
  thresholds**. Also treat scores as two-decimal values; avoid thresholds exactly
  on a rounding boundary.
- Persist the returned `model` version for reproducibility.
- `CLASSIFIER_API_KEY` (server-side only): when set, send
  `Authorization: Bearer <key>`; when empty, call anonymously. Never log the key
  or the header, and do not retry on `401 invalid_api_key`.
- `CLASSIFIER_ENABLED=false` must disable external calls (offline mode).

### Caveats to keep in mind

- This is a decision model, not a security engine; measured accuracy on public
  text tasks is ~88% (news topics) to ~62% (emotion). Treat output as a triage
  signal, not proof of malware.
- The upstream model can be overconfident; thresholds are experimental.
- Do not send filenames or paths if they may contain sensitive information; the
  evidence text is built from file metadata only (name optional, see config).

---

## 10. Deterministic Security Policy

The classifier never triggers security actions directly. Policy is computed from
independent signals; each signal produces a verdict and the final verdict is the
**highest severity** across signals (`ALLOW < QUARANTINE < BLOCK`). Signals can
escalate a verdict, never downgrade it.

```text
Signals: clamav, classifier, static_rules
Output:  ALLOW | QUARANTINE | BLOCK
```

| Signal | Condition | Verdict |
| --- | --- | --- |
| ClamAV | detected | BLOCK |
| ClamAV | error / unscannable | QUARANTINE (fail-closed, configurable) |
| Analysis | unsupported (non-PE) | ALLOW + `analysis_skipped` |
| Analysis | error | QUARANTINE |
| Classifier | error / timeout / null confidence | QUARANTINE (fail-closed, configurable) |
| Classifier | label = malicious, conf >= T_BLOCK | BLOCK |
| Classifier | label = malicious | QUARANTINE |
| Classifier | label = suspicious | QUARANTINE |
| Classifier | label = insufficient-evidence | QUARANTINE |
| Classifier | label = benign | ALLOW |
| Static rule | packed section AND unsigned | STATIC_RULE_VERDICT (default QUARANTINE) |
| Static rule | suspicious imports >= SUSPICIOUS_IMPORTS_MIN AND unsigned | STATIC_RULE_VERDICT (default QUARANTINE) |

Static rules are independent deterministic heuristics over the evidence. They run
even when the classifier is disabled or fails, and keep the pipeline conservative
without the external service. They never lower a verdict produced by another
signal, and — like every other signal — they are triage evidence, not proof of
malware.

`null` confidence must be handled explicitly — in TS `null < 0.90` evaluates to
`true`, which would silently quarantine every unscored answer.

Thresholds and rule verdicts live in configuration, not code constants, and must
be evaluated against a test corpus (Phase 8) before being treated as meaningful.

---

## 11. Quarantine

`QUARANTINE` and `BLOCK` verdicts persist the file bytes so the result is
actionable:

- Directory: `data/quarantine/` (gitignored, created at startup).
- Filename: `sha256` (+ original extension stored in metadata only).
- Permissions: `0600`, never executable; the directory is not served by the API.
- Metadata (verdict, evidence, classifier output) lives in SQLite; the bytes live
  on disk keyed by SHA-256.
- No automatic deletion. Retention/cleanup is a manual, explicitly documented
  operation (out of MVP automation).
- Duplicate SHA-256 overwrites nothing: existing artifact wins, metadata is
  still recorded.

If quarantine storage is disabled, the verdict is still returned and persisted,
but the response marks `quarantined: false`.

---

## 12. Persistence and API Response

### Kafka payload / SQLite schema

The Kafka message is today's `ScanLog` JSON with new optional fields (backwards
compatible; `omitempty`):

```text
scan_id / request_id   (existing request_id)
verdict                ALLOW | QUARANTINE | BLOCK
verdict_reasons        string[] (which signals fired)
clamav_detected        bool
clamav_signature       string
analysis_supported     bool
evidence               object (evidence_json in SQLite)
classifier_label       string
classifier_confidence  float (nullable)
classifier_scores      object (nullable)
classifier_model       string
classifier_error       string
quarantined            bool
```

SQLite (`scan_logs`) gains the same columns. `infra/sqlite` applies idempotent
additive migrations (`PRAGMA table_info` + `ALTER TABLE`); during development
`data/scanner.db` may simply be deleted to recreate the schema.

Existing `status` (`infected`) and `virus_name` columns stay for compatibility.

### Publish rule

- `BLOCK` / `QUARANTINE` → always published.
- `ALLOW` → published only if `PUBLISH_ALL_VERDICTS=true` (evaluation mode).

### API response (per file)

Keep the current envelope and extend it:

```json
{
  "code": 200,
  "status": "success",
  "message": "scan completed",
  "request_id": "…",
  "data": {
    "files": [
      {
        "name": "example.exe",
        "size": 481231,
        "mime": "application/vnd.microsoft.portable-executable",
        "sha256": "…",
        "status": "clean",
        "verdict": "QUARANTINE",
        "verdict_reasons": ["classifier: suspicious (0.91)", "static_rule: packed and unsigned"],
        "quarantined": true,
        "clamav": { "detected": false, "signature": null },
        "static_analysis": {
          "supported": true,
          "file_type": "PE32+",
          "architecture": "x86_64",
          "max_entropy": 7.94,
          "has_packed_section": true,
          "has_digital_signature": false,
          "packer_hints": ["high-entropy executable section"],
          "suspicious_imports": ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"]
        },
        "classifier": {
          "label": "suspicious",
          "confidence": 0.91,
          "model": "jev-1.13.0",
          "scores": { "benign": 0.03, "suspicious": 0.91, "malicious": 0.06, "insufficient-evidence": 0 }
        }
      }
    ]
  }
}
```

HTTP semantics change (and the frontend plus swagger must follow):

- `200` — scan completed, regardless of verdict (`verdict` carries the outcome).
- `4xx` — invalid request only (no file, too large, too many files, ...).
- The legacy `status: clean | infected | failed` is kept and derived from the
  verdict for backwards compatibility (`ALLOW → clean`, `BLOCK → infected`,
  errors → `failed`).

`GET /api/scanner/logs` keeps its shape; the items now include verdict,
evidence, and classifier fields, so the dashboard can show them.

---

## 13. Frontend

`fe-analysis` keeps its two pages (dashboard + upload). This section is the
implementation-level spec for both views.

### 13.1 Component structure

```text
fe-analysis/src/
├── components/
│   ├── FileUploadPanel.tsx     # existing upload widget (extended)
│   ├── ScanResultCard.tsx      # new: per-file result card
│   ├── VerdictBadge.tsx        # new: ALLOW / QUARANTINE / BLOCK pill
│   ├── ClassifierBars.tsx      # new: horizontal score bars
│   ├── EvidenceList.tsx        # new: static-analysis indicators
│   ├── ScanLogsTable.tsx       # existing: + Verdict & Classifier columns
│   └── ScanLogDetail.tsx       # new: expanded row (bars + evidence)
├── types.ts                    # extended scan types
└── api.ts                      # unchanged endpoints
```

### 13.2 Types

```ts
export type Verdict = 'ALLOW' | 'QUARANTINE' | 'BLOCK'

export interface ClassifierResult {
  label: string
  confidence: number | null
  model?: string
  scores?: Record<string, number> | null
}

export interface StaticAnalysis {
  supported: boolean
  file_type?: string
  architecture?: string
  max_entropy?: number
  has_packed_section?: boolean
  has_digital_signature?: boolean
  packer_hints?: string[]
  suspicious_imports?: string[]
  imports_count?: number
}

export interface ScanFileResult {
  name: string
  size: number
  mime: string
  sha256: string
  status: 'clean' | 'infected' | 'failed'
  verdict: Verdict
  verdict_reasons: string[]
  quarantined: boolean
  clamav: { detected: boolean; signature?: string | null; error?: string }
  static_analysis?: StaticAnalysis
  classifier?: ClassifierResult
}
```

### 13.3 Classifier scores as horizontal bars

Do not render confidence as a single number only. Render every label score as a
horizontal bar, in fixed order, with the chosen label highlighted:

```text
Classifier   suspicious · confidence 0.91        model jev-1.13.0

benign              █▏                              3%
suspicious          ██████████████████▍              91%
malicious           █▎                              6%
insufficient-ev.    ▏                               0%
```

`ClassifierBars` props:

| Prop | Type | Notes |
| --- | --- | --- |
| `scores` | `Record<string, number> \| null` | from `classifier.scores` |
| `activeLabel` | `string` | `classifier.label` |

Rules:

- Order is fixed: `benign`, `suspicious`, `malicious`, `insufficient-evidence`;
  unknown labels append alphabetically.
- Row layout: label (fixed width `w-28`, truncate) + track
  (`h-2 rounded bg-slate-100`) + fill (`width: score * 100%`) + value
  (`tabular-nums`, right-aligned).
- Do not normalize scores: classifier.dev rounds to two decimals, so they may not
  sum to exactly 1.
- `scores` null or `confidence` null → render `—` in place of the bars (offline
  mode, escalated smart-tier answers, provider without scores).
- Active label: `font-semibold` + subtle ring; inactive rows stay muted.
- Accessibility: each row carries `aria-label="{label} {percent}%"`.
- Percentages display as integers (`Math.round(score * 100)`).

Color mapping (Tailwind):

| Label | Fill | Meaning |
| --- | --- | --- |
| `benign` | `bg-emerald-500` | low risk |
| `suspicious` | `bg-amber-500` | needs review |
| `malicious` | `bg-red-500` | high risk |
| `insufficient-evidence` | `bg-slate-400` | not enough evidence |

The bars visualize label fit, not malware probability. The card labels them
`Classifier assessment` and never presents them as "91% malware".

### 13.4 Upload result card

One card per file, rendered from the `POST /api/scanner/scan` response:

```text
┌──────────────────────────────────────────────────────────┐
│ example.exe                              ⚠ QUARANTINE    │
│ 481 KB · PE32+ · x86_64 · sha256 2546dcff…               │
├──────────────────────────────────────────────────────────┤
│ ClamAV            ✓ Not detected                         │
│ Static analysis   ⚠ packed · unsigned · 3 suspicious     │
│                   imports                                │
│ Classifier        suspicious · confidence 0.91           │
│   benign            █▏                             3%    │
│   suspicious        ██████████████████▍            91%   │
│   malicious         █▎                             6%    │
│   insufficient-ev.  ▏                              0%    │
├──────────────────────────────────────────────────────────┤
│ Reasons                                                 │
│ • classifier: suspicious (0.91)                         │
│ • static rule: packed and unsigned                      │
│ Quarantined: yes                                        │
└──────────────────────────────────────────────────────────┘
```

Card rules:

- Verdict badge colors: `ALLOW` emerald, `QUARANTINE` amber, `BLOCK` red.
- Show ClamAV, static analysis, and classifier as separate rows so the
  detection / evidence / assessment separation stays visible.
- `EvidenceList` renders `static_analysis`: file type, architecture, max entropy,
  packed section, digital signature, packer hints, suspicious imports (with count).
- Optional entropy bar (scale 0–8) next to `max_entropy` for quick reading; it is
  evidence, not a verdict.
- The scan button is disabled while a request is running; each uploaded file gets
  its own card.

### 13.5 Dashboard

Extend the existing table; keep the existing filters (`virus_name`,
`application`) and add an optional `verdict` filter.

```text
File          | Virus      | Verdict       | Classifier        | Aplikasi | Ukuran | Waktu
eicar.txt     | Eicar-Test | 🔴 BLOCK      | —                 | scanner  | 68 B   | 10:41
setup.exe     | —          | 🟠 QUARANTINE | suspicious · 91%  | scanner  | 481 KB | 10:52
doc.pdf       | —          | 🟢 ALLOW      | skipped (non-PE)  | scanner  | 220 KB | 10:53
```

- `Verdict` reuses the `VerdictBadge` component.
- `Classifier` cell shows `label · confidence%`; skipped analysis shows
  `skipped (non-PE)`; unavailable shows `assessment unavailable`.
- Expanded row (`ScanLogDetail`) renders the full horizontal bars plus evidence,
  `verdict_reasons`, sha256, and quarantine state.
- Data source stays `GET /api/scanner/logs`; the endpoint now returns verdict,
  evidence, and classifier fields.
- `virus_name` exists only for ClamAV detections; other rows show `—`.

### 13.6 State matrix

| State | Upload card | Dashboard |
| --- | --- | --- |
| ClamAV detected | verdict `BLOCK`, classifier row `not needed` | verdict + virus name |
| PE, classifier benign | verdict `ALLOW`, bars with benign highlighted | `ALLOW` / `benign · N%` |
| PE, classifier suspicious/malicious | verdict `QUARANTINE`/`BLOCK`, bars + reasons | verdict + `label · N%` |
| Static rule fired (classifier benign) | verdict `QUARANTINE`, reasons show the rule | same |
| Non-PE | `Analysis skipped (unsupported type)`, verdict `ALLOW` | `skipped (non-PE)` |
| Analysis/classifier error | `Assessment unavailable`, verdict per `FAIL_MODE` | `assessment unavailable` |
| Null confidence | label shown, bars replaced by `—` | `label · —` |
| Classifier disabled | rows show `disabled`; static rules still apply | same |
| Quarantined | footer `Quarantined: yes` | quarantine badge |

Rules:

- Distinguish ClamAV, static-analysis evidence, classifier assessment, and final verdict.
- Non-PE files show `Analysis skipped (unsupported type)` — never a green "safe" state.
- Classifier errors show as `Assessment unavailable` with the resulting verdict.
- Null confidence renders as `—`, not `0%`.
- Rule-triggered verdicts display their `verdict_reasons`, so a quarantine can be
  explained even when the classifier reported `benign`.
- Dashboard table adds `Verdict` and `Classifier` columns; existing filters stay.

---

## 14. Configuration

New `scanner-service` environment variables:

```text
CLASSIFIER_ENABLED=true
CLASSIFIER_URL=https://classifier.dev
CLASSIFIER_API_KEY=              # optional; server-side only, NEVER in fe-analysis/.env
CLASSIFIER_TIER=fast
CLASSIFIER_TIMEOUT=10s
CLASSIFIER_LABELS=benign,suspicious,malicious,insufficient-evidence
CLASSIFIER_SEND_FILENAME=false

VERDICT_BLOCK_CONFIDENCE=0.95
FAIL_MODE=quarantine            # quarantine | allow, for ClamAV/classifier errors
ALLOW_UNSUPPORTED=true          # non-PE fallback verdict ALLOW
STATIC_RULES_ENABLED=true
STATIC_RULE_VERDICT=QUARANTINE  # verdict when a static rule fires (escalates only)
SUSPICIOUS_IMPORTS_MIN=3
PACKER_ENTROPY_THRESHOLD=7.2    # analyzer heuristic for has_packed_section
QUARANTINE_DIR=data/quarantine
QUARANTINE_ENABLED=true
PUBLISH_ALL_VERDICTS=false      # evaluation mode

CACHE_ENABLED=true
CACHE_TTL=168h                  # 0 = never expire
CACHE_ERROR_TTL=15m             # cooldown for cached classifier errors
CACHE_MAX_ENTRIES=100000        # 0 = unlimited; prunes oldest last_seen_at
GENERIC_RULES_ENABLED=true
EMBEDDED_PE_SCAN_MAX=8388608    # bytes scanned for embedded PE signatures

MAX_FILES_PER_REQUEST=10
```

---

## 15. MVP Scope

### In scope

- File upload and validation (size, filename, file count, magic-byte PE detection)
- SHA-256 calculation
- ClamAV scanning (existing client)
- PE static analysis: file type, architecture, sections, entropy, packing
  heuristics, digital-signature presence, imports, suspicious imports
- Evidence normalization (Go model, `evidence_json`)
- `evidenceToText()` (canonical, bounded)
- classifier.dev integration behind `FileClassifier` (timeout, retries, nulls)
- Deterministic `ALLOW / QUARANTINE / BLOCK` policy
- Quarantine file storage
- Extended API response
- Kafka → logwriter → SQLite persistence of new fields
- Frontend result display and dashboard columns
- Swagger update

### Out of scope for MVP

- Dynamic malware execution, sandbox, network/memory analysis
- Reverse engineering
- Formats other than PE (PDF, DOCX, JS, archives, ...)
- Training a custom ML model
- Sending raw files to external services
- Fully autonomous malware deletion
- Quarantine retention automation

---

## 16. Implementation Order

### Phase 1 — Cleanup (done)

- `be-analysis`, MongoDB, Kafka Connect, PostgreSQL artifacts removed
- Frontend AI features removed
- ClamAV + Kafka + SQLite pipeline verified end to end

### Phase 2 — PE analyzer

`analysis/analyzer/pe.go` using `debug/pe`:

1. File type and architecture
2. Section list with entropy
3. Maximum entropy and packing heuristics
4. Digital-signature presence (certificate data directory)
5. Import table and suspicious import list

### Phase 3 — Evidence model

- `FileEvidence` struct + builders from the existing scan result
- `evidenceToText()` with deterministic ordering and a 2,000-character cap

### Phase 4 — classifier.dev client

- `FileClassifier` interface + `ClassifierDev` implementation
- Timeout, retry/backoff, null handling, model version capture
- Unit tests with recorded responses (no live calls in CI)

### Phase 5 — Decision engine + quarantine

- `analysis/policy` as a pure function: per-signal verdicts → highest severity,
  with table-driven tests
- Static-analysis rules (packed + unsigned, suspicious imports) as independent
  deterministic signals
- Quarantine writer (`data/quarantine/<sha256>`)
- Config plumbed through `config/config.go` and `.env.example`

### Phase 6 — API response + persistence

- Extend handler + swagger
- Extend `ScanLog`, Kafka payload, `logwriter`, and SQLite schema/migrations
- Keep `status` backwards compatible

### Phase 7 — Frontend

- Upload result card, skipped-analysis state, classifier null handling
- Dashboard columns for verdict and classifier

### Phase 8 — Evaluation (detailed design in section 20)

Two-phase harness (`cmd/eval`): `collect` runs the pipeline over a local corpus and
writes raw outputs; `analyze` re-applies the policy across threshold grids offline,
without extra classifier calls. Produces `results.json` + `report.md` with the
metrics listed in section 20 and a recommended `T_BLOCK`.

### Phase 9 — Scan cache (detailed design in section 21)

`scan_cache` table keyed by SHA-256. ClamAV always runs; on a cache hit the stored
evidence + classifier result are reused and the policy is recomputed, which saves
classifier quota and latency for repeated files.

### Phase 10 — Non-PE coverage (detailed design in section 22)

Generic analyzer (magic type, entropy, embedded PE, URLs, scripts), PDF analyzer
(JavaScript, auto-open actions, embedded files), Office analyzer (macros, external
targets, DDE) and archive analyzer (nested executables). The evidence model gains
`kind` + `generic` fields, the policy gains deterministic generic rules, and the
classifier also runs for supported non-PE types.

---

## 17. Target Architecture After MVP

```text
                         ┌──────────────┐
                         │ File Upload  │
                         └──────┬───────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │   Validation    │
                       │ SHA256 / magic  │
                       └────────┬────────┘
                                │
                                ▼
                         ┌────────────┐
                         │   ClamAV   │
                         └─────┬──────┘
                               │
                  ┌────────────┴────────────┐
                  │                         │
               DETECTED                 NOT DETECTED
                  │                         │
                  ▼                         ▼
                BLOCK                ┌──────────────┐
                                     │ PE Analyzer  │
                                     └──────┬───────┘
                                            │
                                            ▼
                                     ┌──────────────┐
                                     │   Evidence   │
                                     │    Object    │
                                     └──────┬───────┘
                                            │
                                            ▼
                                     ┌──────────────┐
                                     │classifier.dev│
                                     └──────┬───────┘
                                            │
                                  ┌─────────┼─────────┐
                                  ▼         ▼         ▼
                               BENIGN  SUSPICIOUS MALICIOUS
                                  │         │         │
                                  ▼         ▼         ▼
                                ALLOW   QUARANTINE  BLOCK
                                            │
                                            ▼
                                  Kafka → logwriter → SQLite
                                            │
                                            ▼
                                        Dashboard
```

---

## 18. Design Principles

### 1. Detection ≠ evidence ≠ decision

```text
ClamAV       → detection
Static       → evidence
Classifier   → assessment
Application  → decision
```

### 2. A ClamAV miss is not a clean verdict

The second layer exists specifically because signature-based detection has
coverage limitations.

### 3. High entropy is not malware

Entropy, packing, unsigned binaries, and suspicious APIs are indicators. None
should independently be treated as proof of malware.

### 4. The classifier does not replace static analysis

`classifier.dev` consumes meaningful evidence extracted by the application, and
its confidence measures label fit — not threat truth.

### 5. Keep the final policy deterministic

The classifier does not decide whether a file is released, quarantined, or
blocked. Nulls, timeouts, and skipped analysis are handled explicitly in the
policy layer, never by accident. Static-analysis rules are deterministic signals
that can escalate a verdict but never downgrade it.

### 6. Start with PE files

Supporting one format deeply is better than supporting many shallowly. Files
outside PE are clearly marked as not analyzed.

### 7. Keep the classifier replaceable

```text
FileClassifier
     │
     ├── ClassifierDev
     └── OtherClassifier (future)
```

### 8. Everything observable is persisted

Verdict, verdict reasons, evidence, classifier label/confidence/model, errors,
and quarantine state are stored so that decisions can be explained and evaluated
later.

---

## 19. Expected Result

The finished project demonstrates a hybrid pipeline:

```text
Known threat
    ↓
ClamAV
    ↓
BLOCK


Unknown / undetected by signature
    ↓
Static analysis (PE)
    ↓
Evidence
    ↓
classifier.dev
    ↓
Risk assessment
    ↓
ALLOW / QUARANTINE / BLOCK
    ↓
Kafka → SQLite → Dashboard
```

The main value is not a claim that the classifier detects all unknown malware.
The value is demonstrating how signature-based detection and probabilistic
evidence classification can be combined into a layered malware-triage system
whose decisions remain deterministic, explainable, and measurable.

---

## 20. Phase 8 — Evaluation Harness (detail)

### Goal

Answer the core question with measurements, not intuition, and turn the
experimental thresholds (`VERDICT_BLOCK_CONFIDENCE`, `SUSPICIOUS_IMPORTS_MIN`)
into values that are defensible on a local corpus.

Key constraint: classifier.dev is rate limited and slow, so threshold sweeps must
not re-call it. The harness therefore splits into two phases.

### Layout

```text
eval/
├── manifest.json          # committed; sample list + expected labels (no bytes)
├── corpus/                # gitignored; actual samples (never committed)
├── results/               # gitignored; one directory per run
│   └── 2026-09-22T10-00/
│       ├── raw.jsonl      # one record per sample (collect phase)
│       ├── summary.json   # metrics per threshold config (analyze phase)
│       └── report.md      # human-readable tables
└── README.md              # how to obtain samples, licensing, safety notes

scanner-service/cmd/eval/main.go
```

### Manifest

```json
{
  "samples": [
    { "path": "malware/eicar.txt",                "expected": "malware",    "tags": ["eicar"] },
    { "path": "malware/injected-sample.exe",      "expected": "malware",    "tags": ["clamav-miss", "injection"] },
    { "path": "benign/7zip-installer.exe",        "expected": "benign",     "tags": ["packed", "signed"] },
    { "path": "benign/self-extracting.exe",       "expected": "benign",     "tags": ["packed", "unsigned"] },
    { "path": "suspicious/packed-unsigned.exe",   "expected": "suspicious", "tags": ["packed"] },
    { "path": "benign/notes.pdf",                 "expected": "benign",     "tags": ["non-pe"] }
  ]
}
```

`expected` is `malware | benign | suspicious | unknown`. Samples with `unknown`
are collected for latency/coverage statistics but excluded from FP/FN.

### CLI

```bash
# Phase A — run ClamAV + analyzer + classifier once per sample
go run ./cmd/eval collect \
  --manifest ../eval/manifest.json \
  --corpus ../eval/corpus \
  --out ../eval/results/2026-09-22T10-00

# Phase B — re-apply policy offline over a threshold grid
go run ./cmd/eval analyze \
  --in ../eval/results/2026-09-22T10-00 \
  --block-confidence 0.80,0.85,0.90,0.95,0.99 \
  --imports-min 1,3,5
```

`collect` calls the same components as the service (in-process, no HTTP, no
Kafka, no quarantine writes) and records:

```json
{
  "path": "suspicious/packed-unsigned.exe",
  "expected": "suspicious",
  "tags": ["packed"],
  "sha256": "81d2a1a0…",
  "size": 66048,
  "clamav": { "detected": false, "error": "" },
  "analysis": { "supported": true, "kind": "pe", "has_packed_section": true },
  "classifier": { "label": "suspicious", "confidence": 0.89, "scores": {}, "model": "jev-1.13.0" },
  "classifier_error": "",
  "duration_ms": { "clamav": 6, "analysis": 1, "classifier": 812, "total": 819 }
}
```

`analyze` reads `raw.jsonl`, replays `policy.Decide` for every threshold
combination, and writes `summary.json` + `report.md`.

### Metrics (per threshold config)

- Verdict counts and expected-label counts
- Detection rate on expected `malware` (verdict != ALLOW)
- False negatives: expected `malware` but `ALLOW`
- False positives: expected `benign` but non-`ALLOW`
- ClamAV miss count and how many misses the second layer escalates
- Rule-only vs classifier-only vs combined quality (precision/recall/F1)
- Null-confidence rate and label distribution by expected class
- Latency p50/p95 per stage (`clamav`, `analysis`, `classifier`, total)
- Quarantine count and `model` versions observed

### Choosing thresholds

Pick the config with the highest malware recall subject to
`false-positive rate on benign ≤ 5%` (target is configurable). Record the chosen
values in `config/env_example` with a comment referencing the run directory, so
the number has provenance.

### Ground rules

- Samples are never committed; `eval/corpus/` and `eval/results/` are gitignored.
- Corpus must include deliberately hard benign files: packed installers,
  unsigned self-extracting archives, high-entropy documents.
- Free-tier limits (20k classifications/day per IP) are enough for corpora up to
  a few thousand samples; the collect phase prints progress and rate-limit errors.
- Report honestly: if the classifier does not improve on ClamAV misses on this
  corpus, that is a valid result and must be stated in the report.

### Definition of done

- `report.md` exists with tables, chosen thresholds, and model versions.
- Chosen thresholds are written into `env_example` and the plan's section 14.
- Known limitations (corpus size, sample provenance, model drift) documented.

---

## 21. Phase 9 — Scan Cache (detail)

### Goal

Skip static analysis and classifier calls for files already seen, while keeping
ClamAV correctness and policy freshness:

- ClamAV **always** runs, so signature-database updates are never masked by cache.
- Cached entries store **signals** (evidence + classifier output), not the final
  verdict; policy is recomputed on every hit so threshold/config changes apply
  immediately.

### Schema

```sql
CREATE TABLE IF NOT EXISTS scan_cache (
  sha256               TEXT PRIMARY KEY,
  size                 INTEGER NOT NULL,
  analysis_supported   INTEGER NOT NULL DEFAULT 0,
  evidence_json        TEXT NOT NULL DEFAULT '',
  classifier_label     TEXT NOT NULL DEFAULT '',
  classifier_confidence REAL,
  classifier_scores    TEXT NOT NULL DEFAULT '',
  classifier_model     TEXT NOT NULL DEFAULT '',
  classifier_error     TEXT NOT NULL DEFAULT '',
  first_seen_at        TEXT NOT NULL,
  last_seen_at         TEXT NOT NULL,
  hits                 INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_scan_cache_last_seen ON scan_cache(last_seen_at);
```

### Flow

```text
sha256 = hash(bytes)
ClamAV scan (always)
  detected → BLOCK (skip cache lookup and store)
  not detected → cache lookup by sha256 (+ size match, TTL not expired)
      hit  → reuse evidence + classifier result, hits++, last_seen_at = now
             policy.Decide(...) recomputed; response marks cached=true
      miss → analyzer + classifier
             store signals (including ALLOW results)
             policy.Decide(...)
```

### Behavior rules

- A cache entry is only used when `size` matches and `last_seen_at` is within
  `CACHE_TTL` (`0` disables expiry).
- ALLOW results are cached too — that is the main quota saver.
- `classifier_error` is cached only for a short cooldown (`CACHE_ERROR_TTL=15m`,
  separate from `CACHE_TTL`) so transient classifier outages do not permanently
  mark a file as unassessable.
- Analyzer version changes should invalidate entries: store a schema/analyzer
  version column (`analyzer_version INTEGER`, bumped when evidence format
  changes) and ignore mismatches.

### Interfaces

```go
type CachedScan struct {
    SHA256       string
    Size         int64
    Analysis     evidence.StaticAnalysis
    Classifier   *classifier.Result
    ClassifierErr string
    FirstSeenAt  time.Time
    LastSeenAt   time.Time
    Hits         int64
}

type ScanCacheRepository interface {
    Lookup(ctx context.Context, sha256 string, size int64, maxAge time.Duration) (CachedScan, bool, error)
    Store(ctx context.Context, entry CachedScan) error
    Prune(ctx context.Context, maxEntries int) error
}
```

Implementation: `app/scanner/repo/scan_cache_repo.go` (SQLite, same DB file).

### Pruning

On `Store`, when `CACHE_MAX_ENTRIES > 0`:

1. delete rows older than `CACHE_TTL` (if TTL > 0),
2. if still above the cap, delete the oldest `last_seen_at` rows.

### Observability

- Response per file gains `"cached": true|false`.
- `scan_logs` gains a `cached` column so evaluation can measure hit rates.
- Log a counter line on hit: `cache hit sha256=… hits=…`.

### Tests

- Hit path: classifier fake counts calls — second scan of the same bytes must not
  call it.
- ClamAV-detected sample bypasses lookup and store.
- TTL expiry and analyzer-version mismatch force a miss.
- Policy recomputation on hit (e.g., change `VERDICT_BLOCK_CONFIDENCE` and observe
  the stored signals produce a new verdict).

---

## 22. Phase 10 — Non-PE Coverage (detail)

### Goal

Make the second layer meaningful for the formats users actually upload
(PDF, DOCX/XLSX, scripts, archives, plain text) instead of the current
`ALLOW + analysis_skipped` path.

Principle stays the same: analyzers extract **evidence**, the classifier assesses
it, policy decides. No file bytes leave the process.

### Evidence model extension

Keep the existing PE fields; add a discriminator and generic evidence:

```go
type StaticAnalysis struct {
    Supported bool   `json:"supported"`
    Kind      string `json:"kind"` // pe | pdf | office | script | archive | text | unknown
    // ... existing PE fields ...
    Generic   GenericEvidence `json:"generic,omitempty"`
}

type GenericEvidence struct {
    MagicType         string   `json:"magic_type,omitempty"`
    FileEntropy       float64  `json:"file_entropy,omitempty"`
    EmbeddedPE        bool     `json:"embedded_pe,omitempty"`
    EmbeddedTypes     []string `json:"embedded_types,omitempty"`
    URLs              []string `json:"urls,omitempty"`               // capped at 20
    HasJavaScript     bool     `json:"has_javascript,omitempty"`
    HasMacros         bool     `json:"has_macros,omitempty"`
    ExternalTargets   []string `json:"external_targets,omitempty"`
    AutoExec          bool     `json:"auto_exec,omitempty"`
    SuspiciousStrings []string `json:"suspicious_strings,omitempty"` // capped at 20
    ObfuscationHints  []string `json:"obfuscation_hints,omitempty"`
}
```

`Analyzer` interface and `Registry` stay unchanged; each analyzer sets `Kind`.

### Analyzer roadmap

**10a — Generic analyzer (`generic.go`)** — first, everything depends on it:
- magic type via `http.DetectContentType` + explicit signatures
- whole-file Shannon entropy
- embedded PE: scan for `MZ` (cap `EMBEDDED_PE_SCAN_MAX`, default 8 MiB), validate
  with `pe.NewFile` at that offset; count and record nested types
- URL extraction (regex, capped)
- script markers: `WScript.Shell`, `ActiveXObject`, `eval(`, `Invoke-Expression`,
  `-enc`, `FromBase64String`, shebangs
- base64 blob detection and long-line/obfuscation hints

**10b — PDF analyzer (`pdf.go`)**, marker-based (no external dependency):
`/JavaScript`, `/JS`, `/OpenAction`, `/AA`, `/Launch`, `/EmbeddedFile`, `/URI`,
`/Encrypt`; JS occurrence count; auto-open + JavaScript combination is the
high-signal case.

**10c — Office analyzer (`office.go`)**:
- OOXML (docx/xlsx) via `archive/zip`: `vbaProject.bin` → macros;
  `TargetMode="External"` / `oleObject` / remote template rels → external targets;
  DDE markers (`fldChar` + `INCLUDETEXT`)
- legacy OLE (`D0 CF 11 E0`): macro strings, `VBA` streams

**10d — Archive analyzer (`archive.go`)**: zip entry listing via `archive/zip`;
flag nested executables, double extensions, encrypted entries, `../` traversal
names. Nested archives are listed, not recursively scanned (cap entries).

**10e — Text analyzer**: entropy, URLs, script markers, base64 blobs. Lowest
priority; generic markers cover most of it.

### Classifier input

`ToText()` includes `kind` and generic findings, e.g.:

```text
File type: PDF document.
Embedded JavaScript: yes.
Auto-open action: yes.
Embedded files: 2.
URLs: 3.
```

Budget stays 2,000 characters; URLs/strings truncated to the first five entries.
Unknown types keep `supported=false` and are not sent to the classifier.

### Policy rules (escalate-only, configurable)

| Rule | Condition | Verdict |
| --- | --- | --- |
| PDF active content | JavaScript AND auto-open action | `STATIC_RULE_VERDICT` |
| Office macros + network | macros AND external targets | `STATIC_RULE_VERDICT` |
| Embedded executable | `EmbeddedPE` in a document/archive | `STATIC_RULE_VERDICT` |
| Script obfuscation | base64 blob AND (`eval` or `-enc`) | `STATIC_RULE_VERDICT` |
| Archive with executable | nested `.exe/.dll/.scr` | `STATIC_RULE_VERDICT` |

Guarded by `GENERIC_RULES_ENABLED`; same max-severity model as section 10.

### API and frontend

- `EvidenceList` renders generic indicators: kind badge, macros, embedded PE,
  JavaScript, external targets, URL count.
- Types (`StaticAnalysis`, `GenericEvidence`) extended in `types.ts`.
- Swagger `StaticAnalysis` schema extended with `kind` + `generic`.

### Tests

Crafted fixtures (small, text-based, committed under `analysis/analyzer/testdata`):
- PDF with `/OpenAction /JavaScript`
- OOXML zip containing `vbaProject.bin` + external relationship
- zip containing `setup.exe`
- JS file with base64 blob + `eval`
Plus policy table cases for each new rule.

### Out of scope

- Format-parsing beyond the markers above (full PDF/Office parsers)
- Recursive archive extraction
- Dynamic analysis (unchanged)

---

## 23. Updated Roadmap Summary

| Phase | Scope | Status |
| --- | --- | --- |
| 1 | Cleanup (AI/Mongo/Postgres removal) | done |
| 2–7 | PE analysis, evidence, classifier, policy, quarantine, persistence, FE | done |
| 8 | Evaluation harness + threshold calibration | section 20 |
| 9 | Scan cache (SHA-256) | section 21 |
| 10 | Non-PE coverage (generic/PDF/Office/archive) | section 22 |

Recommended order: **8 → 9 → 10**. Phase 8 needs no new runtime components and
tells us whether the thresholds we shipped are defensible; Phase 9 immediately
reduces classifier quota usage during evaluation and daily use; Phase 10 widens
the second layer to the formats users actually upload.
