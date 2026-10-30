# AEGIS dashboard

Implemented React/TypeScript/Vite frontend for the existing Core API. It submits
real LLVM Shield jobs, polls status, renders Core reports and hashes, downloads
reports, reopens jobs by ID and imports verified local research summaries.
No simulated security events, active licenses or honeypot counts are shown.

## Build and run

Requires Node ≥22.18/npm. From the repository root:

```sh
npm --prefix platform/dashboard ci
npm --prefix platform/dashboard test
npm --prefix platform/dashboard run build
```

Use the [product runbook](../../docs/release/RUNBOOK.md) to build and register the
real LLVM 22 adapter, compile the owned fixture and start API plus **built** UI.
For frontend-only development, `npm --prefix platform/dashboard run dev` binds
loopback. Both dev and preview proxy `/healthz` and `/v1` to `127.0.0.1:8000`.
No external font requests or chart dependencies are required.

## Existing API contracts

| Endpoint | UI behavior |
| --- | --- |
| `GET /healthz` | Connection and registered-adapter readiness; not a plugin execution test |
| `POST /v1/jobs` | Base64 input plus `llvm-shield`, task `protect`, string seed, max-sites 16; 202 is accepted, not succeeded |
| `GET /v1/jobs/{id}` | Poll pending/running every 1.5 seconds and render terminal status; previous IDs can be loaded manually |
| `GET /v1/jobs/{id}/report` | Render/download terminal report, artifact SHA-256s, adapter transformation counts, source labels and limitations |

Optional API bearer token is entered in Capabilities and held in memory only.
No localStorage or credential bundling. Session jobs are also in memory; Core’s
store survives reloads. There is no job-list, native-output download, telemetry,
license or research API. Those absences have explicit UI states. A failed request
never supplies sample data. POST timeouts leave acceptance uncertain; no automatic
resubmission occurs. A terminal report failure can be retried with Refresh.

## Research imports

Run `scripts/export-product-evidence.py` outside the browser first. Reconstruction
exports call Lab’s existing `verify_experiment`; Mirage exports bind input/output
IR digests; ImageLab exports bind recorded artifact bytes. Exports intentionally
omit transcripts, hidden cases, worker diagnostics, candidate source, decoy names
and source paths. Raw records are refused by the UI.

The frontend-only local format is `aegis.product.evidence.v1`, with exactly:

- `schema`, `kind` (`reconstruction`, `mirage`, `benchmark`), `source_sha256`,
  `verification` (`offline_hash_bindings_checked`), and `summary`.
- Reconstruction summary: trial/pair IDs, artifact/candidate digests, provider/
  requested model, aggregate step/token/cost counts, generation state, pending
  behavioral scoring, `execution_performed=false`, `attack_effectiveness=not_established`.
- Mirage summary: input/output digests, insertion count, no established security
  property and final retention requiring an independent check.
- ImageLab summary: baseline, recorded output-match flag, allowlisted measurement
  conditions/settings, and per-variant/operation sample count/min/median/max.

Files are limited to 1 MiB. The operator must paste the exporter’s SHA-256 from a
trusted terminal. Browser Web Crypto checks that exact UTF-8 file, then schema/
field allowlists reject unexpected data. Imports stay in memory and never enter
a network request. The badge says local evidence; it does **not** certify a
signature, authorship, measured security or the truth of a hand-edited record.
Hash binding and benchmark measurement validity remain distinct.

Raw Phase 4 scoring records remain unsupported because they contain private data
and need matching, not-yet-merged Core verification. Generation is displayed as
behaviorally unscored. No live AI analysis or NVIDIA GPU inference is claimed.
Sentinel is a cooperating policy package, not an AI analyst. Mirage is an LLVM
transformer, not a web honeypot service.

## Verification

```sh
npm --prefix platform/dashboard test
PLAYWRIGHT_BROWSERS_PATH=/tmp/aegis-product-browsers \
  npm --prefix platform/dashboard exec -- playwright install chromium
PLAYWRIGHT_BROWSERS_PATH=/tmp/aegis-product-browsers \
  npm --prefix platform/dashboard run test:e2e
```

Before browser tests, run `product.py build` and `configure`, then stop any manual
local server. Playwright starts/stops both loopback services itself and refuses to
reuse an unrelated server. `AEGIS_PRODUCT_WORKSPACE` can point at another configured
scratch root. The browser suite uses the real adapter and owned fixture, compares
rendered/downloaded reports and hashes, tests real invalid-IR failures, unknown
jobs, a network outage, private-import rejection and mobile navigation. Synthetic
fixtures in unit tests test parsers only and are not protection evidence.

[Release validation](../../docs/release/VALIDATION.md) records exact results,
warnings and suites not run. [Agent 1 notes](../../docs/release/AGENT1-CONTRACT.md)
describe the remaining endpoint boundary without modifying Core.
