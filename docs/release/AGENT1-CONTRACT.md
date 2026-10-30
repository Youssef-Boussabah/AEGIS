# Agent 1 product API handoff

> Historical product request, superseded by [FINAL_API_CONTRACT.md](FINAL_API_CONTRACT.md).
> Registered-output downloads, optional job signing, fresh verification and Sentinel
> evaluation are now implemented. Research imports remain local and behaviorally
> unscored. Current verification is in [FINAL_RELEASE_REPORT.md](FINAL_RELEASE_REPORT.md).

No backend change is necessary for the supported Shield demonstration. The real
UI uses the merged `GET /healthz`, `POST /v1/jobs`, `GET /v1/jobs/{job_id}` and
`GET /v1/jobs/{job_id}/report`. The product launcher supplies `AEGIS_CONFIG` with
an absolute argv registration for the existing `llvm-shield` adapter. The successful
browser test proves this path without a fake backend.

No job-list, output-download or research-report endpoint exists in this checkout.
The UI recovers a job by its known 32-hex ID, downloads the already available Core
report, and accepts verified local research summaries. Native protected outputs
remain in the operator’s private store, with Core-recorded hashes shown in the UI.

If Agent 1 later supplies artifact retrieval, the minimal product need is:

- `GET /v1/jobs/{job_id}/artifacts/{sha256}` using the same bearer-token gate as
  other `/v1` routes. Resolve only registered **output** artifacts of that job
  through Core’s containment/integrity checks. No caller-supplied filesystem path.
- Success: exact bytes, attachment filename from the registered sanitized name,
  SHA-256 binding, byte length and `application/octet-stream` or an allowlisted
  media type. Fail explicitly on absent/mismatched artifact, pending job, changed
  bytes, symlink or escaping path; never stream before checks complete.
- Existing structured `{"error":{"code":...,"message":...,"details":...}}`
  envelope. Exact new ErrorCode/status mappings need Agent 1 approval; none is
  invented or implemented by this branch.

For future research retrieval, first agree on an allowlisted summary contract
with Lab and Core, validate its private evidence server-side, and retain both
attack-lab authorization gates. Never return requests/responses, candidate source,
hidden cases, raw diagnostics or private Core execution records. The frontend’s
`aegis.product.evidence.v1` is an unsigned **local export format**, documented in
its README, not a proposed public Core schema or a security attestation.

Phase 4 scoring export remains unavailable until matching Core is merged and the
Lab owner supplies the verified private-record loading path. Pending generation
records are shown as behaviorally unscored. Do not turn them into scored results.

Agent 1 owns updates to ARCHITECTURE.md and docs/PROJECT_STATUS.md at integration;
this product task was explicitly prohibited from editing those files. The root
README and release validation record describe this branch’s supported behavior.
