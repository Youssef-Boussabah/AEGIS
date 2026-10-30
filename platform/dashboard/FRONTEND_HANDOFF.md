# Frontend integration handoff — product release branch

The earlier frontend handoff’s pending successful-LLVM-job gap is closed on this
branch. The dashboard uses the existing API and real LLVM Shield adapter through
`scripts/product.py`. The real Chromium smoke verifies accepted job → succeeded
status → displayed report → downloaded report → independently matching output
hashes. Invalid IR remains failed and has no registered output artifacts.
See [release validation](../../docs/release/VALIDATION.md) for exact runs.

Removed simulated security events, threat charts, license totals, web-decoy hits
and scripted “AI analyst” interactions. Navigation now leads to real protection
jobs and local research evidence. The interface labels Core observations, adapter
claims, unavailable telemetry, pending behavioral scoring and unmeasured resistance.
Health checks register readiness only; plugin viability is checked by actual jobs.

The built dashboard and both services bind loopback. Health and API requests share
a proxy. Optional bearer authentication and job-ID reload work with existing
contracts; no backend changes were made. Research imports are local, digest-checked
and allowlisted after the existing Lab/Mirage/ImageLab verification paths. Private
request or hidden-suite data is not displayed or uploaded.

Remaining limits: no list/download/research endpoints, no live telemetry, no real
AI analysis, no live Nebius/NVIDIA inference evidence, no merged Core scoring
runtime, and no established Shield/Mirage security property. Core architecture and
project-status notes remain Agent 1’s integration responsibility.

See [dashboard README](README.md), [runbook](../../docs/release/RUNBOOK.md),
[API handoff](../../docs/release/AGENT1-CONTRACT.md) and
[submission checklist](../../docs/release/SUBMISSION.md). No commit, push, deployment
or public release has been performed.
