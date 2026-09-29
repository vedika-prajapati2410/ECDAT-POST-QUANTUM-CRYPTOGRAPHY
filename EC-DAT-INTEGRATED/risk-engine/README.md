# ECDAT Risk & Recommendation Engine (Dev 2 module)

Backend for **Problem Statement 26164 — Enterprise Cryptographic Discovery &
Analysis Tool (ECDAT)**, sponsored by NTRO. This is the Dev 2 half of the
stack: it takes a CBOM (Cryptographic Bill of Materials) produced by Dev 1's
scanner and turns it into risk scores, classifications, PQC migration
recommendations, standardised report exports, and a set of differentiating
analyses (Crypto-Agility Score, migration roadmap, harvest-now-decrypt-later
exposure, dependency blast radius, Indian regulatory mapping, and more).

**28/28 tests passing.** Every endpoint below has been run live end-to-end,
not just unit-tested in isolation — see "What's verified" at the bottom.

## Quick start

```bash
pip install -r requirements.txt
export ECDAT_API_KEYS="pick-a-real-key-here"   # required — see Authentication below
python3 run.py
# API now running at http://localhost:5000
```

Try it immediately without waiting on the scanner:

```bash
curl -X POST http://localhost:5000/api/scans/sample \
  -H "X-API-Key: pick-a-real-key-here" \
  -H "Content-Type: application/json" \
  -d '{"years_to_crqc": 12}'
```

Run the test suite:

```bash
python3 tests/test_pipeline.py
```

## Authentication

Every `/api/*` route except `/api/health`, `/api/openapi.json`, and `/api/docs`
requires an `X-API-Key` header. If you don't set `ECDAT_API_KEYS`, the server
falls back to a dev default (`ecdat-dev-key-change-me`) and prints a loud
warning on startup — fine for local development, **never deploy with the
default key**. Set multiple valid keys as a comma-separated list:
`ECDAT_API_KEYS="team-key-1,ci-key-2"`.

## Input validation & request limits

`POST /api/scans` validates the submitted CBOM *before* it reaches the
pipeline (`app/validation.py`) and returns every problem found in one
response, not just the first:

```json
{"error": "1 validation error(s) found in submitted CBOM.",
 "details": [{"index": 0, "field": "id", "message": "'id' is required."}]}
```

Checked: required fields present, `type`/`data_classification`/`confidence`
are valid enum values, `key_length`/`data_volume_gb` are sane numbers, `id`s
are unique within the submission, and string fields aren't absurdly long. A
single scan is capped at 5,000 artefacts, and the whole request body is
capped at 15 MB — both to stop a very large or malformed payload from being
used to exhaust memory/CPU on one request.

## Rate limiting

Per-API-key, fixed-window: 15 requests/minute for scan creation (the
expensive full-pipeline endpoints), 120/minute for everything else. A
limited request gets `429` with a `Retry-After` header. This is in-memory
and process-local (see `app/rate_limit.py`) — fine for a single-process
hackathon deployment; swap to a Redis-backed limiter if you ever run
multiple worker processes.

## API documentation

Interactive docs (Swagger UI) at `GET /api/docs`; the raw OpenAPI 3.0 spec
at `GET /api/openapi.json`. Both are public (no API key) since they're
documentation, not data. A test (`test_openapi_spec_covers_every_registered_flask_route`)
fails the build if a route gets added to `api.py` without a matching entry
in `app/openapi_spec.py`, so the two can't silently drift apart.

## Frontend integration

`client/ecdatClient.js` is a dependency-free JS wrapper around every
endpoint below — the frontend dev should import this rather than
hand-writing `fetch()` calls against each route. It has its own
integration test (`client/ecdatClient.test.mjs`) that runs against a
real live server and covers all 20+ methods, including the error paths
(404s, validation 422s). See `client/README.md` for usage, a React
example (`client/ReactUsageExample.jsx`), and how to re-verify the
client still matches the API after you change something in `api.py`.

## Persistence

Scan history and triage overrides are stored in a local SQLite file
(`ecdat.db` in the project root by default; override with `ECDAT_DB_PATH`).
This is deliberate: an earlier in-memory-only version lost every scan on
restart, which is a real risk mid-demo (a crash, a redeploy, a laptop
sleep/wake). This has been verified to survive an actual process kill and
restart — see `tests/test_pipeline.py`'s `test_storage_*` tests, or reproduce
it yourself: run a scan, `kill` the server, start it again, `GET` the same
scan ID back. Delete `ecdat.db` any time to reset to a clean demo state.

## Architecture

```
Raw scanner findings (from Dev 1, or /api/scans/sample)
        │
        ▼
 aggregation.py        -- dedup repeated findings into one artefact + occurrence_count
        │
        ▼
 classification.py     -- algorithm family + quantum vulnerability tier
        │
        ▼
 risk_engine.py         -- Mosca's theorem (X+Y>Z), confidence-capped risk tiers
        │
        ├─► recommendations.py     -- PQC/hybrid replacement + tradeoffs
        ├─► agility_score.py       -- Crypto-Agility Score + CMMI-style maturity level
        ├─► migration_roadmap.py   -- phased 4-stage migration plan
        ├─► harvest_now.py         -- harvest-now-decrypt-later exposure (GB)
        ├─► dependency_graph.py    -- blast-radius / dependency propagation
        ├─► regulatory_mapping.py  -- Indian regulatory/compliance triage flags
        ├─► cve_lookup.py          -- known-CVE cross-reference for libraries
        └─► certificate_analysis.py -- expiry / self-signed / weak-signature checks
        │
        ▼
   pipeline.py (orchestrator) ──► storage.py (scan history + triage overrides)
        │                                           │
        ├─► cyclonedx_export.py (standardised JSON) │
        ├─► pdf_report.py (standardised PDF)         │
        ├─► trend_analysis.py (diff two scans)        │
        ├─► simulator.py (what-if remediation)          │
        ├─► triage.py (manual override workflow)          │
        ├─► ci_cd_template.py (GitHub Actions gate)          │
        └─► report_signing.py (tamper-evident signature)      │
                                                                ▼
                                                        api.py (Flask REST)
                                                                │
                                                                ▼
                                                        Frontend dev consumes this
```

Every module under `app/` except `api.py` is framework-agnostic pure Python
— if the team switches to FastAPI, only `api.py` needs to be rewritten.
`storage.py` persists to SQLite (stdlib `sqlite3`, no extra dependency).

## CBOM input schema (contract with Dev 1)

```json
{
  "id": "art-001",
  "name": "api-gateway-tls-cert",
  "type": "certificate",
  "algorithm": "RSA-2048",
  "location": "services/api-gateway/tls/cert.pem",
  "key_length": 2048,
  "internet_facing": true,
  "data_classification": "PII",
  "data_volume_gb": 120.0,
  "used_by": ["mobile-app", "partner-api", "web-frontend"],
  "first_seen": "2021-03-01",

  "confidence": "high",
  "library_name": null,
  "library_version": null,
  "issuer": null,
  "expiry_date": null,
  "self_signed": null,
  "signature_algorithm": null
}
```

All fields below `first_seen` are **optional** — Dev 1's scanner can omit
any it doesn't populate yet; defaults kick in. `confidence` should be
`"high"` (resolved API call), `"medium"` (config/string match) or `"low"`
(heuristic/keyword match) if the scanner can distinguish these. `library_*`
fields enable CVE cross-referencing; `expiry_date`/`self_signed`/
`signature_algorithm` enable certificate deep-analysis. The same
`(name, type, algorithm)` fingerprint appearing at multiple `location`s is
automatically merged into one artefact with an `occurrence_count` — you do
**not** need to dedup on the scanner side.

`app/sample_cbom.py` has 16 example findings (which dedup to 14 artefacts)
covering RSA/ECC/AES-128/3DES, already-PQC ML-KEM/ML-DSA, a vulnerable
OpenSSL version, an expired self-signed cert with a weak signature, a
low-confidence heuristic hit, and repeated findings to demo aggregation.

## API reference

All endpoints require `X-API-Key` except `/api/health`, `/api/openapi.json`, `/api/docs`.

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/health` | Liveness check (no auth) |
| GET | `/api/docs` | Interactive Swagger UI (no auth) |
| GET | `/api/openapi.json` | Raw OpenAPI 3.0 spec (no auth) |
| POST | `/api/scans` | Run a scan. Body: `{"cbom": [...], "years_to_crqc": 12, "skip_dedup": false}` — validated, rate-limited to 15/min |
| POST | `/api/scans/sample` | Run a scan against the built-in sample CBOM — rate-limited to 15/min |
| GET | `/api/scans` | List scan history (summaries) |
| GET | `/api/scans/<id>` | Full report (triage overrides applied) |
| GET | `/api/scans/<id>/cbom` | Normalised, deduplicated artefact inventory |
| GET | `/api/scans/<id>/risk` | Per-artefact Mosca risk assessment (overrides applied) |
| GET | `/api/scans/<id>/recommendations` | PQC replacement + tradeoffs per artefact |
| GET | `/api/scans/<id>/agility-score` | Crypto-Agility Score + maturity level |
| GET | `/api/scans/<id>/roadmap` | Phased migration roadmap |
| GET | `/api/scans/<id>/hndl` | Harvest-now-decrypt-later exposure |
| GET | `/api/scans/<id>/blast-radius` | Dependency blast-radius graph |
| GET | `/api/scans/<id>/regulatory` | Indian regulatory/compliance triage flags |
| GET | `/api/scans/<id>/cve-findings` | Known-CVE matches for scanned libraries |
| GET | `/api/scans/<id>/certificates` | Certificate expiry/self-signed/weak-sig findings |
| GET | `/api/scans/<id>/cyclonedx` | **CycloneDX 1.6 CBOM export (standardised JSON)** |
| GET | `/api/scans/<id>/report.pdf` | **Human-readable PDF report (standardised format)** |
| GET | `/api/scans/<id>/trend` | Diff vs. the immediately previous scan |
| GET | `/api/scans/<older>/diff/<newer>` | Diff between two specific scans |
| POST | `/api/scans/<id>/simulate` | What-if: project score after remediating given artefact IDs |
| POST | `/api/scans/<id>/triage` | Set a manual override (`accepted_risk` / `false_positive` / `confirmed`) |
| GET | `/api/scans/<id>/triage` | List current overrides for a scan |
| GET | `/api/scans/<id>/ci-gate.yml?fail_on_tier=Critical` | Generated GitHub Actions gate workflow |
| GET | `/api/scans/<id>/signature` | Tamper-evident signature for the report |
| POST | `/api/scans/<id>/verify` | Verify a report+signature pair |

`years_to_crqc` (default 12) is the tunable "years until a
cryptographically-relevant quantum computer exists" planning assumption —
exposed as a request parameter so the frontend can build a live slider for
scenario analysis in the demo.

## What each feature actually does (and its honesty boundaries)

- **Deduplication (`aggregation.py`)** — merges repeated raw findings sharing
  `(name, type, algorithm)` into one artefact with `occurrence_count` and a
  `locations` list, taking the most-sensitive classification and
  lowest-confidence value across merges. Prevents a report full of 200
  near-identical rows.
- **Confidence scoring** — artefacts carry `confidence: high/medium/low`.
  Low-confidence findings are capped at Medium risk, medium-confidence at
  High, regardless of the raw Mosca math — an unverified heuristic match
  shouldn't trigger the same alarm as a confirmed one.
- **Mosca's theorem (`risk_engine.py`)** — `X` (data shelf-life) and `Y`
  (migration time) come from configurable tables; `Z` (years to CRQC)
  defaults to 12, loosely anchored to NSA's CNSA 2.0 migration deadlines
  (phased through 2033) and industry expert-survey timelines — presented
  explicitly as a *planning assumption*, not a verified prediction, and
  disclosed as such in the PDF report.
- **Crypto-Agility Score (`agility_score.py`)** — weighted blend of %
  quantum-safe, average exposure margin, and criticality-weighted risk
  concentration, mapped to a CMMI-style Level 0–5 maturity label.
- **Migration roadmap** — 4-phase plan (0-6mo / 6-18mo / 18-36mo / 36mo+),
  sorted by criticality and exposure margin within each phase.
- **Harvest-now-decrypt-later** — flags confidentiality-relevant artefacts
  (excludes pure signature algorithms — you can't "harvest" a signature)
  whose data outlives the CRQC horizon, and sums exposed data volume.
- **Dependency blast radius** — uses the `used_by` field to show how many
  downstream services a single vulnerable artefact would affect.
- **Indian regulatory mapping (`regulatory_mapping.py`)** — flags DPDP Act
  2023 / RBI / SEBI / CERT-In / NCIIPC relevance based on data
  classification and exposure. **Explicitly labelled an automated triage
  aid, not a legal determination**, in every output — route to a
  compliance/legal reviewer for confirmation.
- **CVE cross-reference (`cve_lookup.py`)** — a small, curated, offline
  table of well-known historical CVEs for common libraries (OpenSSL,
  Log4j, Struts, OpenSSH). **Not a live NVD/OSV feed** — see the module's
  TODO for the swap-in path once network access to a vulnerability
  database is available. Never fabricates a CVE ID.
- **Certificate deep analysis** — expiry countdown, self-signed detection,
  weak signature-hash detection (MD5/SHA-1), independent of the quantum
  question.
- **CycloneDX export** — real CycloneDX 1.6 `cryptographic-asset` component
  schema, directly answering the "standardised formats" deliverable
  requirement — consumable by any CycloneDX-compatible tool, not just this
  frontend. `serialNumber` is a spec-valid UUID5 URN deterministically
  derived from the scan ID (not a string splice) so it actually validates
  against the CycloneDX schema in tools like Dependency-Track.
- **PDF report** — human-readable companion to the CycloneDX JSON, built
  with reportlab (no external binary dependency), including an explicit
  assumption-disclosure line.
- **Trend/diff analysis** — compares two scans (or a scan against the one
  immediately before it) to show newly introduced artefacts, remediated
  artefacts, and Agility Score delta — reframes the tool as continuous
  monitoring, not a one-off audit.
- **What-if simulator** — projects the Agility Score and risk-tier counts
  *before* doing remediation work, by re-running the scoring functions on a
  hypothetically-migrated artefact set. No new scanning logic; pure
  re-computation.
- **Manual triage/override** — a reviewer can mark a finding
  `false_positive` (forces Safe) or `accepted_risk` (keeps it visible but
  flagged as a knowing exception). A justification is **mandatory** — the
  code raises `ValueError` on an empty one, so overrides are always
  auditable, never silent.
- **CI/CD gate template** — generates a real, valid GitHub Actions workflow
  (validated by parsing it back with PyYAML in the test suite) that fails a
  build when new artefacts at or above a chosen risk tier are found. This
  is a template generator — there's no live CI runner in this sandbox to
  execute it against, but the YAML itself is directly usable.
- **Report signing** — signs the report with **Ed25519** (via the
  `cryptography` package) for real, verifiable tamper-evidence today. It
  is explicitly **not** presented as ML-DSA/PQC signing — that would
  require `liboqs`, a native-compiled library not installable in this
  offline sandbox. The module's docstring documents the exact one-function
  swap to real ML-DSA once `liboqs-python` is available in your actual
  deployment environment, and every signature payload states its
  algorithm explicitly so nothing downstream could mistake it for PQC.

## What's verified vs. what's a documented placeholder

Being upfront about this so nobody gets caught off guard by a judge's
question:

| Feature | Status |
|---|---|
| Classification, Mosca risk engine, recommendations | Fully implemented, real logic, tested |
| Agility Score, roadmap, HNDL, blast radius | Fully implemented, real logic, tested |
| Deduplication, confidence capping | Fully implemented, real logic, tested |
| Regulatory mapping | Real rule-based logic; **explicitly not legal advice** |
| CVE lookup | Real matching logic against a **small curated offline table**, not a live NVD feed |
| Certificate analysis | Fully implemented, real logic, tested |
| CycloneDX export | Real CycloneDX 1.6 structure, tested |
| PDF report | Fully implemented, real PDF generation, tested |
| Trend/diff, what-if simulator | Fully implemented, real logic, tested |
| Triage/override | Fully implemented, mandatory justification enforced, tested |
| CI/CD gate | Real, valid YAML generated and parse-tested; **not run against a live CI runner** |
| Report signing | Real, working Ed25519 signatures, tested; **explicitly not PQC** — documented upgrade path to ML-DSA via liboqs |
| Scan history persistence | Real SQLite-backed storage (stdlib, no extra dependency); verified to survive an actual `kill` + restart of the server process, not just unit-tested |
| Empirical PQC latency benchmarking | **Not implemented** — `recommendations.py` cites literature-typical overhead percentages, not locally-measured numbers (liboqs isn't installable offline here) |

## Next steps for integration

1. Frontend calls `POST /api/scans/sample` on load to have something to
   render immediately.
2. Once Dev 1's scanner is ready, it POSTs its raw findings to
   `POST /api/scans` instead — dedup happens automatically, no other
   changes needed.
3. If deploying with multiple worker processes (gunicorn `-w N` etc.),
   move `storage.py` from SQLite to Postgres — SQLite's file-level locking
   is fine for one process but becomes a bottleneck/correctness risk across
   several. The `save_scan`/`get_scan`/... interface is unchanged either way.
4. If you get liboqs installed in your real dev environment, swap
   `report_signing.py` per its documented TODO, and optionally add a real
   empirical benchmarking module for recommendation latency figures.
5. Swap `cve_lookup.py`'s static table for a live OSV.dev/NVD query if
   network access is available at demo time.
