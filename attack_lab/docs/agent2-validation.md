# Agent 2 validation and handoff — 30 October 2026 UTC

Scope: `attack_lab/` and `scripts/export-product-evidence.py`, in the shared
`/home/youss/Projects/aegis` checkout. Other agents' edits were present and were
not changed. No commits, pushes, resets, package installation or sudo were used.
No credential value was inspected, no genuine inference/catalogue access was
performed, no approval was granted or consumed from the prepared plan, no
generated candidate was compiled/executed, and Firecracker was not enabled.

## Verified path and changes

| Stage | Actual implementation and validation |
| --- | --- |
| Manifest and paired conditions | `manifest.py` strict v2 records and `validate_pair`; prepared baseline compared against each protected manifest. Distinct final-artifact hashes and trial IDs. |
| Ghidra evidence | `ghidra.py` bounded process group, private staging, minimal environment, full report invariants; `evidence.bind_ghidra_evidence` rechecks artifact, launcher/version and configuration identity. Real-Ghidra integration exercises success, missing/ambiguous selection, analysis timeout and process-group termination. |
| Request preparation | `prepare_reconstruction` binds evidence, selects one function, checks prompt/sampling/workflow digests and access policy; `verify_prepared` reconstructs it before generation. Source, retrieval, network and runtime-oracle access remain disallowed. |
| Approval | `check_inference_approval` checks opt-in, exact disclosure/manifest/workflow, deadlines, limits and retention review; `claim_approval` reserves the whole approval once using O_EXCL. Real JSON booleans are now required, so numeric 1/0 cannot stand in for review or storage decisions. Core authorization gates are unchanged. |
| Model verification | Bounded authenticated availability GET and public NVIDIA catalogue check before POST. A shared pure checker now also checks archived bodies offline, rejecting absent/inactive/external models, changed context, exceeded caps, negative/nonfinite/malformed prices. No model weights or provider signatures are verified. |
| Spending and transport | Full context plus output is reserved per request; worst-case micro-USD spending is reserved before submission. Bounded trusted subprocess covers blocking DNS/TLS/header/body phases; minimal environment, anonymous key pipe, TLS, no redirects, no retries and private bounded outputs. Existing transport tests run against deterministic stubs, never the live account. |
| Private archive and verification | `verify_experiment` now replays exact conversations and response classification, checks selected candidate provenance, per-step conservative charges, estimated reported-token costs and approval start window. It rejects relabeled failures and changed provider identities. Export source hashes are checked against the same bytes being verified, preventing replacement between hashing and validation. |
| Three-way verification | `live_trial verify` verifies private plan binding, seeded order, every available experiment/digest, outcomes, equal approval limits, unique artifacts/trials and paired conditions. It never opens original paths from the archived plan. Identity comparability requires one consistent, complete reported model/fingerprint pair. Missing archives stay explicit. |
| Public projection | `public_summary.py` strictly allowlists v2 reconstruction and comparison records. Unknown usage is null, conservative reservations are separate from reported usage, actual live billing stays null, generation remains behaviorally unscored. Raw prompts, source, candidate text, bodies, fingerprints, approvals, archives, keys, paths and free-form limitations/diagnostics are excluded. Mirage/benchmark v1 formats remain unchanged. |

## Prepared plan, read-only observations

`/tmp/aegis-live-imagelab-ready/plan.json` SHA-256:
`37fae93210ab83ba411a9fe1df038318de5476eed3ab51c392f3c848fff7b1b0`.
No changes were made to it or its approvals. Offline preflight made **zero network
and zero billable requests**, verified all three artifacts/report bindings and
pair comparability, and confirmed all plan approval paths are null. Aggregate
approved spending remains unknown, not zero. Existing draft review booleans are
false and their deadlines have expired.

| Variant | Final artifact SHA-256 | Ghidra 12.1.4 functions |
| --- | --- | --- |
| baseline | `f5090a8da14f21da10f1516184d51d9c6dc650861c618461a552f511b8f598df` | 151 |
| Shield | `a08a1b42ba50769db9e829437cf36c1cca8ef25850d6be3c9c5ce79acb26dc2c` | 151 |
| Shield+Mirage | `b06fa4130d9492ac18df4ef169c56784ce8422c2630f66937551d0c4ebd42a90` | 154 |

All selected functions decompiled successfully. Baseline selected text differs
from Shield; Shield selected text equals Shield+Mirage. Both protected prompts
therefore have the same rendered-prompt digest. Only this selected function
enters the request: the comparison does **not** measure exposure to or distraction
by the decoy inventory. Artifact differences and candidate text are not attack
resistance or behavioral reconstruction evidence. Build/source provenance remains
operator-declared, not independently reconstructed here.

## Exact validation commands and results

Use the existing `.venv` from repository root; no dependencies were changed.
Observed interpreter: CPython 3.14.7; LLVM/opt 22.1.8, x86-64 Linux; Ghidra 12.1.4.
All providers in automated tests are deterministic offline stubs, including those
that claim external identity to exercise the live gates. Test approval fixtures
authorize only owned synthetic artifacts and are not operator approvals.

```sh
PYTHONPATH=attack_lab/src .venv/bin/python -m pytest attack_lab/tests \
  --lab-profile offline -q
AEGIS_GHIDRA_HEADLESS=/home/youss/Applications/ghidra_12.1.4_PUBLIC/support/analyzeHeadless \
PYTHONPATH=attack_lab/src .venv/bin/python -m pytest attack_lab/tests \
  --lab-profile integration -q
PYTHONPATH=attack_lab/src .venv/bin/python -m pytest \
  attack_lab/tests/test_public_summary.py attack_lab/tests/test_live_inference.py \
  attack_lab/tests/test_experiment.py -q
PYTHONPATH=core/src:platform/api/src:platform/cli/src .venv/bin/python -m pytest \
  core/tests platform/api/tests platform/cli/tests provenance/tests sentinel/tests \
  protectors/llvm/adapter/tests scripts/tests -q \
  --shield-plugin /tmp/aegis-shield-build/AegisShield.so \
  --shield-opt /usr/bin/opt --shield-clang /usr/bin/clang
ctest --test-dir /tmp/aegis-shield-build --output-on-failure
ctest --test-dir /tmp/aegis-role-b-imagelab --output-on-failure
git diff --check -- attack_lab scripts/export-product-evidence.py
```

| Suite | Observed result | Private log |
| --- | --- | --- |
| Final Lab offline | **2011 passed, 23 NOT RUN**, zero failures/warnings; 68.61 s. 22 real-Ghidra cases intentionally omitted by the offline profile; one Unix-socket fixture blocked by the sandbox. | `/tmp/aegis-agent2-offline-final.log` |
| Final strict Lab with real Ghidra | **2034 passed, zero failures/skips/warnings**, 168.64 s. All 23 cases omitted by the sandboxed offline run were exercised here. | `/tmp/aegis-agent2-integration-final.log` |
| Focused final regression | **118 passed**, zero skips/warnings; 14.91 s. Includes 48 new public-export/verification regression cases. | `/tmp/aegis-agent2-focused-final.log` |
| Companion Python + real adapter + scripts | **752 passed, one warning**, zero skips; 45.97 s. Warning: installed Starlette/httpx TestClient deprecation. | `/tmp/aegis-agent2-companion-final.log` |
| Existing Shield build CTest | **1/1 passed**, 1.22 s. Existing matching LLVM build, not rebuilt by Agent 2. | `/tmp/aegis-agent2-shield.log` |
| Existing ImageLab build CTest | **14/14 passed**, 4.39 s. Existing build; trusted ImageLab test programs, not generated candidates. | `/tmp/aegis-agent2-imagelab.log` |

Earlier results are retained as history, not counted as final validation: initial
offline **1963 passed / 23 NOT RUN** before the new regressions; first extended
strict integration **2017 passed / zero skips**. One intermediate focused run was
**1 failed / 115 passed**: its new environment guard blocked an unrelated Pydantic
environment lookup. The guard was narrowed to the credential variable and the
final focused suite passed. The first sandboxed companion run stalled and was
interrupted (exit 130); the approved unrestricted retry above passed. Strict Lab
integration also ran outside the sandbox so its local Unix-socket fixture could
run. No failed/interrupted/skipped run is represented as passed.

All four existing real-Ghidra/offline-scripted demonstration archives were also
reverified and projected successfully. One was exported to
`/tmp/aegis-agent2-verified-offline-summary.json`.
Its public bytes SHA-256 is
`6a4900775e33ee249ce2c4e88d696e3bf739a3fd4024daf8ff1f87f4a22d3668`.
It is explicitly `offline_scripted`; its candidate is text only. The synthetic
Nebius/comparison fixtures are interface examples with invented values and no
inference or billing history.

## Handoff and remaining limits

- Agent 3 received [the exact v2 contract](public-summary.md), generated JSON
  Schemas and explicitly labeled [offline/synthetic fixtures](../tests/fixtures/public-summary/).
  Browser import must validate the supplied digest and every allowlist and remain
  local. UI implementation/testing belongs to Agent 3 and is not claimed here.
- [Operator-only instructions](operator-live-run.md) cover fresh draft review,
  one approved live NVIDIA request, offline verification/export, then a separately
  approved three-way comparison. The smoke's single-use baseline approval cannot
  be reused: the comparison requires three fresh approvals, including baseline.
- Genuine authenticated model availability, current account pricing/context,
  account credits, live NVIDIA responses and actual billing: **NOT RUN**, no
  operator authorization. Proposal values in commands are not current-price claims.
- Candidate compilation/execution/behavioral scoring and Firecracker validation:
  **NOT RUN**, separate authorization and runtime required. Direct REA integration:
  **not implemented**. No reconstruction success, Mirage benefit or protection
  effectiveness has been established.
- Root `ARCHITECTURE.md` synchronization belongs to Agent 1 under the explicit
  ownership restriction. Integration should document Lab-local inference approval,
  catalogue-evidence replay, comparison verification and the public-summary v2
  projection without implying a Lab API/backend or candidate execution permission.
  No shared Core/API/storage/backend schema was changed by Agent 2.
- Evidence archives are unsigned local files. Verification cannot distinguish an
  external test double from genuine provider-origin evidence, independently check
  model weights/token counts/invoices, enforce provider retention, reconstruct
  missing archives, or resist an operator rewriting the entire local chain.

## Every file changed by Agent 2

- `attack_lab/README.md`
- `attack_lab/docs/live-inference.md`
- `attack_lab/docs/operator-live-run.md`
- `attack_lab/docs/public-summary.md`
- `attack_lab/docs/agent2-validation.md`
- `attack_lab/src/aegis_lab/bounded_provider.py`
- `attack_lab/src/aegis_lab/disclosure.py`
- `attack_lab/src/aegis_lab/experiment.py`
- `attack_lab/src/aegis_lab/live.py`
- `attack_lab/src/aegis_lab/live_trial.py`
- `attack_lab/src/aegis_lab/public_summary.py`
- `attack_lab/tests/test_public_summary.py`
- `attack_lab/tests/fixtures/public-summary/schema.json`
- `attack_lab/tests/fixtures/public-summary/offline-scripted.json`
- `attack_lab/tests/fixtures/public-summary/synthetic-nebius.json`
- `attack_lab/tests/fixtures/public-summary/synthetic-comparison.json`
- `scripts/export-product-evidence.py`
