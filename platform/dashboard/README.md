# AEGIS dashboard

React/TypeScript/Vite software-protection workspace with a Protect → Verify →
Evaluate → Results flow. Existing Overview, Protect LLVM IR, Protection jobs,
Research evidence and Capabilities pages remain available. Verify artifact and
Results bring signing, policy decisions and research evidence into the same flow.

## Run and validate

Requires Node ≥22.18/npm, the repository Python environment and LLVM 22 tools.
Dependencies must already be installed (ask before installing packages).

```sh
npm --prefix platform/dashboard test
npm --prefix platform/dashboard run build
```

The build runs TypeScript checks. Contract tests run without process isolation so
Node reports individual cases. No external fonts or chart dependencies are used.
Development and preview bind loopback; `/healthz` and `/v1` proxy to the port in
`AEGIS_API_PORT` (default 8000). See the [product runbook](../../docs/release/RUNBOOK.md)
for real plugin builds and current backend registration.

Use a fresh, configured scratch workspace. Browser tests require working Shield
and Shield+Mirage registrations and the owned `annotated.ll` fixture. Current
`product.py configure` probes both real adapters before registering them. No test
uses a fake adapter as protection evidence. Isolated ports avoid the operator demo:

```sh
PLAYWRIGHT_BROWSERS_PATH=/tmp/aegis-product-browsers \
AEGIS_PRODUCT_WORKSPACE=/tmp/YOUR_CONFIGURED_WORKSPACE \
AEGIS_API_PORT=8700 AEGIS_DASHBOARD_PORT=5873 \
npm --prefix platform/dashboard run test:e2e
```

Playwright refuses to reuse another server. Results/traces use a port-specific
`/tmp/aegis-dashboard-browser-results-PORT` directory. The signing walkthrough
starts an additional API on a free loopback port, with a temporary test key outside
Git and the store, mode 0600. Only that server reads the private key. It exercises
real signatures, cooperating policy denial/permission, verified byte download,
manifest download, tampering and recovery. Controlled HTTP fixtures separately
exercise malformed/untrusted responses and privacy failures; they are labeled
synthetic and are not research evidence.

## Actual API contracts

[Agent 1's final contract](../../docs/release/FINAL_API_CONTRACT.md) is authoritative.

| Endpoint | Dashboard behavior |
| --- | --- |
| `GET /healthz` | Registered backend name, availability and `protect` task gate profiles; 503/degraded retains Core's problem list |
| `POST /v1/jobs` | Real base64 `.ll` input, selected `llvm-shield` or `llvm-shield-mirage`, string seed, max-sites 16; 202 means accepted |
| `GET /v1/jobs/{id}` | Poll pending/running every 1.5 seconds; reopen by known ID |
| `GET /v1/jobs/{id}/report` | Core-recorded artifact hashes, source labels, adapter counts, limitations and report download |
| `GET /v1/attestation` | Configured/unconfigured signing, trusted public-key fingerprints and Sentinel configuration |
| `GET /v1/jobs/{id}/attestation` | Exact job/artifact bindings; verified, unsigned and failed signatures; policy status and verbatim limitations |
| `GET /v1/jobs/{id}/artifacts/{sha256}` | Bearer-authenticated bytes; require matching hash header, Sentinel decision header, byte length and browser-computed SHA-256 before saving |
| `GET /v1/jobs/{id}/artifacts/{sha256}/manifest` and `/policy` | Download the documented signed manifest or policy JSON |
| `POST /v1/jobs/{id}/artifacts/{sha256}/evaluate` | Send only the selected documented action; display permitted/denied, enforcement mode, reason and evaluation time |

Only `signature.status=verified` produces **Signature verified**. Configured
signing or a stored manifest does not. Signing disabled shows **Not signed
(signing not configured)**. A failed check retains its explicit error code.
Sentinel decisions are cooperating rights metadata; the API's download route
applies its policy, and third-party tools are not bound. A 200 denial stays denied.
Caller identity remains unauthenticated. `attack_evaluate` never authorizes Lab
execution or changes its two independent gates.

Shield+Mirage is selectable only when its actual backend is registered, available
and supports `protect`. Both profiles take annotated textual LLVM 22 IR. The
combined default inserts 3 decoys after Shield; its shared seed is bounded to
9223372036854775807. Shield alone retains uint64 seeds. Unknown registered backends
remain disabled without a dashboard input contract. Arbitrary native binaries,
websites, mobile apps and consoles remain unsupported inputs.

Tokens, jobs and imported summaries stay in browser memory. No localStorage,
sessionStorage, credential bundling or credential logging. Submission timeouts
leave acceptance uncertain; the UI never resubmits automatically. Refresh retries
status, report or verification failures. Results labels verification timestamps as
last checked and links standalone reconstruction summaries only by output digest.
Core's store survives reload; there is no job-list endpoint.

## Privacy-filtered Lab evidence

The [Lab public summary contract](../../attack_lab/docs/public-summary.md) defines
v2 reconstruction and three-variant comparison exports. `research-schema.json`
is a pinned copy of the published schema, with a contract test detecting drift.
The browser validates the schema recursively, rejects extra fields and checks
cross-field identity, usage, billing and comparison invariants. It never imports
raw prompts, candidate source, hidden cases, approvals or private execution records.

Run `scripts/export-product-evidence.py` outside the browser. Select the exported
file (≤1 MiB) and paste the exporter's digest from a trusted terminal. Web Crypto
checks its exact UTF-8 bytes before parsing; imports never enter a network request.
These are unsigned local bindings, not provider authenticity or attack resistance.
The operator must establish the origin of external-provider records.

The UI prominently distinguishes offline, external-provider and synthetic records.
Requested/reported model identity, complete/partial/unknown usage, provider-reported
tokens, conservative token charges, reserved spend and estimated cost remain
separate. Nebius invoice amounts are unknown. Raw system fingerprints are excluded;
only their published identity digest is shown. Comparisons display only recorded
baseline/Shield/Shield+Mirage rows, states and usage, with missing rows preserved.
No success percentages, security scores, live attack animation or GPU statistics.
Candidates remain behaviorally unscored; no protection effect is established.

Historical v1 offline reconstruction, Mirage and ImageLab exports remain supported.
ImageLab timings include sample counts and conditions, without extrapolation.
No signing key or Nebius credential is requested by any product flow. Live calls
and their explicit authorization remain in the operator-run Lab workflow.

## Post-hoc parser reviews

The optional v2 `completion_parser` and `post_hoc_review` fields follow Agent 2's
published schema. Older exports that omit them remain valid. The UI shows the
original generation state, parser and candidate digest separately from a later
post-hoc parser review. An original `invalid_output` with no candidate remains
that original outcome even if a newer parser accepts a text envelope.

Reviews must bind the original source digest, retain the documented legacy
parser/original failure, and satisfy their separate status/envelope/hash
invariants. Comparison rows bind any review to their own source record. Extra
nested fields are refused. A reviewed candidate is uncompiled, unexecuted and
behaviorally unscored. Review hashes are local consistency bindings; there is
no new inference or spending from the browser, and original usage estimates
never become provider invoices.
