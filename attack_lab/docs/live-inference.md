# Approved Nebius inference (Agent 2)

Latest operator-evidence follow-up: [NVIDIA research deliverable](nvidia-research-deliverable.md).
An operator-supplied response now has separate, offline-verified post-hoc and
dashboard-safe summaries. Two remaining invalid drafts use the actual baseline's
8,192-token cap. The original experiment is unchanged; Agent 2 made no new calls.

30 October integration follow-up: see [the operator-only runbook](operator-live-run.md)
for commands from the current checkout, fresh approval handling and offline
verification/export, [the v2 public-summary contract](public-summary.md) for React,
and [current validation](agent2-validation.md). No genuine inference was authorized
or conducted. The reproduction paths and counts below are historical evidence
from the earlier worktree, not the current validation run.

Status: implemented within Lab; live account verification and inference have **not
been run**. No credits spent, generated candidates executed, packages installed,
commits made, branches changed or pushes performed. This is REA-style controlled
reconstruction, not direct REA integration.

## Authorization decision and scope

An `aegis.lab.inference-approval.v1` is a separate, single-use, local operator
attestation. It permits inference only. It is not an `AttackLabAuthorization`,
Core execution grant, sandbox authorization or an `aegis.adapter.v1` request.
Core's `[attack_lab] enabled` and `AttackLabAuthorization` gates and its separate
candidate execution authorization remain unchanged. No candidate compiler,
executor, runtime oracle, retrieval tool or hidden-test tool is introduced.

The approval requires `operator_approved: true`, a named reviewer and reference,
the exact artifact/evidence/base-prompt/manifest hashes, disclosure findings,
Nebius HTTPS endpoint, explicit `nvidia/` model ID, workflow digest, request and
token limits, pricing caps in **micro-USD per million tokens**, spending cap in
**micro-USD**, per-request timeout, UTC request deadline, reviewed provider
retention policy and private archive deletion date. Dynamic continuation is
limited to the approved evidence, model replies and fixed workflow instructions.
The workflow digest covers the instructions, action schema, context bound,
step/tool settings and live request parameters. Artifact identity is checked
before provider construction. Invalid approval, stale evidence, unequal budgets
and unbounded transports fail closed. No environment variable grants permission.

Approval JSON must be a regular, owner-only file (0600); draft approvals contain
`operator_approved: false` and `provider_retention_reviewed: false` and are invalid.
They must be reviewed and deliberately changed by the operator. The CLI reserves
the complete experiment budget once with `O_EXCL` in `.inference-uses/` beside the
approval. Reusing the same approval digest fails before network. A reservation is
never automatically released, even after an uncertain submission or crash. CLI
operators must preserve that directory; local unsigned attestations and files do
not defend against a malicious operator deleting state or forging approval.
Direct Python callers must maintain one persistent private `approval_state_dir`.

## Transport and verified vendor documentation

Verified official documentation on 2026-10-29:

- [Authentication and endpoint](https://docs.tokenfactory.nebius.com/api-reference/introduction).
- [Authenticated model list](https://docs.tokenfactory.nebius.com/api-reference/models/list-models).
- [Chat completions and usage](https://docs.tokenfactory.nebius.com/api-reference/inference/create-chat-completion).
- [Public context/pricing catalogue](https://tokenfactory.nebius.com/api/public/models_info).

`BoundedNebiusProvider` runs the existing HTTP implementation in a trusted Python
subprocess with its own process group. The supervisor's wall timeout includes
DNS, TLS, headers and buffered body reads. It kills the entire process group on
timeout, interruption and normal exit, then reaps the worker. Output has a 24 MiB
file limit and is read with a size bound. HTTP bodies retain the existing 8 MiB
limit. Scratch is private and removed. Only trusted transport code runs here;
this is not an isolation mechanism for candidates. POSIX is required. Host process
creation, scheduling and SIGKILL cleanup can add small overhead beyond the request
timeout; there is no real-time operating-system guarantee.

The key travels through an anonymous stdin pipe, never argv, inherited environment,
logs or archival output. The worker uses a minimal environment and default TLS
validation. Redirects are refused. Live requests use `store=false`,
`service_tier=default`, `n=1`, `stream=false`, `max_tokens`, and the same
`max_completion_tokens` cap, which the official API documents as including
reasoning tokens. `store=false` controls API output storage for distillation; it
is **not** a zero-retention guarantee. Applicable provider/account terms require
operator review. Local archive deletion on the recorded date is an operator duty;
there is no deletion scheduler.

Before any inference POST, a bounded worker performs authenticated `GET /v1/models`
and reads the public catalogue. The exact requested ID must be available to that
credential, belong to an active NVIDIA entry with a license URL, and use Nebius
hosting rather than an external provider. The published `max_model_len` must equal
the approval and current prices must not exceed its caps. Both response bodies
are archived privately. Catalogue GETs disclose no target evidence. These checks
do not establish that an account has inference credits, pin actual model weights,
or prove the provider honors its published limits/prices.

Each request conservatively reserves **the entire published context ceiling plus
maximum completion tokens**, and its worst-case price, before submission. This
avoids using the legacy unverified UTF-8 tokenizer heuristic as a live limit.
It intentionally over-reserves: according to Nebius, prompt plus completion must
fit the model context. Unknown usage stays unknown and keeps the full reservation.
Reported usage, conservative ledger charges and estimated reported-token cost are
separate; actual billed cost is unknown, never asserted to be zero. Provider
usage overruns are explicit failures and stop the trial. Any POST that may have
been processed is never automatically repeated; even definite pre-submission
failures stop this live workflow. Provider/account behavior remains a trust
assumption, not a provider-side billing quota enforced by Lab.

## Reproduction without inference

This worktree has no `.venv`. The existing interpreter used here is
`/home/youss/Projects/aegis/.venv/bin/python`; no packages were installed. All
commands run from `/home/youss/Projects/aegis-live-nebius`.

```sh
PYTHONPATH=attack_lab/src /home/youss/Projects/aegis/.venv/bin/python \
  -m aegis_lab.live_trial preflight /tmp/aegis-live-imagelab-ready/plan.json
```

This makes **zero network/billable requests**, displays credential **presence only**,
checks regular readable binaries against exact hashes, rebinds Ghidra reports,
validates pair comparability and any supplied approval, and shows proposed model,
request/token budget and spending caps. Account availability remains explicitly
unchecked. Without an approval the proposed spending cap is unknown, not zero.

The existing trusted ImageLab artifacts were prepared using this exact command:

```sh
PYTHONPATH=attack_lab/src /home/youss/Projects/aegis/.venv/bin/python \
  attack_lab/scripts/prepare_imagelab_live.py \
  --build-dir /tmp/aegis-role-b-imagelab \
  --mirage-report /tmp/aegis-role-b-imagelab-mirage/report.json \
  --ghidra-headless /home/youss/Applications/ghidra_12.1.4_PUBLIC/support/analyzeHeadless \
  --output-dir /tmp/aegis-live-imagelab-ready \
  --source-revision existing-build-revision-not-independently-verified \
  --model nvidia/Nemotron-3_5-Lightning --max-model-tokens 2000000 \
  --max-output-tokens 2048 --steps 1 --authorized-owned-artifacts
```

Use a **new** output directory for reproduction. The script reads existing build
artifacts, runs real Ghidra, checks Shield insertions and Mirage report bindings,
requires distinct final artifacts and changed selected Shield decompilation, and
checks decoy retention in Ghidra. It does not rebuild or execute those binaries.
Build/source provenance remains explicitly operator-declared and unverified.
It writes safe private failure records if preparation fails. Scoring identities
are explicitly absent placeholders and cannot be used for behavioral scoring.

Private preparation evidence: `/tmp/aegis-live-imagelab-ready/preparation.json`.
Ghidra 12.1.4 exported 151/151/154 functions for baseline/Shield/Shield+Mirage.
Selected function: `imagelab_color_adjust_pixel`. All three decompiled successfully.
The selected Shield decompilation differs from baseline; Shield and Mirage have
the same selected decompilation. All three Mirage decoys appear in its inventory.

| Variant | Final artifact SHA-256 |
| --- | --- |
| baseline | `f5090a8da14f21da10f1516184d51d9c6dc650861c618461a552f511b8f598df` |
| Shield | `a08a1b42ba50769db9e829437cf36c1cca8ef25850d6be3c9c5ce79acb26dc2c` |
| Shield+Mirage | `b06fa4130d9492ac18df4ef169c56784ce8422c2630f66937551d0c4ebd42a90` |

These observations establish static differences only. A fixed selected-function
prompt does not expose the decoy inventory; no Mirage reconstruction advantage,
behavioral correctness or protection effectiveness has been measured.

## Exact remaining operator gate and live command

Review the exact prompts locally with `aegis_lab.reconstruction prepare
MANIFEST REPORT --max-output-tokens 2048 --show-prompt` (private terminal only).
For each selected target, generate an invalid draft:

```sh
PYTHONPATH=attack_lab/src /home/youss/Projects/aegis/.venv/bin/python -m aegis_lab.live draft \
  /tmp/aegis-live-imagelab-ready/baseline/manifest.json \
  /tmp/aegis-live-imagelab-ready/baseline/ghidra/ghidra-analysis.json \
  /tmp/aegis-role-b-imagelab/ir-baseline/imagelab-cli \
  --max-output-tokens 2048 --steps 1 \
  --output /tmp/aegis-live-imagelab-ready/baseline/approval.DRAFT.json \
  --context-tokens 1048576 --input-microusd-per-million 60000 \
  --output-microusd-per-million 240000 --max-spend-microusd 100000 --request-timeout 120
```

The model, context and prices above are **proposals**, not account availability or
current pricing claims. The live catalogue checks fail closed if they do not
match. The operator must approve the exact artifact/disclosure, model, limits,
spending (here at most $0.10 for one target), deadline and retention; supply the
reviewer/reference and applicable retention terms; refresh expired timestamps;
and explicitly set both review booleans true. Save as private `approval.json`.
The draft command also writes a private `.request-review.json` containing the
exact initial provider body, including workflow instructions. Review that file.
Do not paste credentials into JSON or the terminal. The key must already be
configured as `NEBIUS_API_KEY` in the operator's environment.

After that approval, this exact single-target command makes fresh catalogue GETs
and at most one genuine inference POST (candidate execution stays disabled):

```sh
PYTHONPATH=attack_lab/src /home/youss/Projects/aegis/.venv/bin/python -m aegis_lab.live run \
  /tmp/aegis-live-imagelab-ready/baseline/manifest.json \
  /tmp/aegis-live-imagelab-ready/baseline/ghidra/ghidra-analysis.json \
  /tmp/aegis-role-b-imagelab/ir-baseline/imagelab-cli \
  --max-output-tokens 2048 --steps 1 \
  --approval /tmp/aegis-live-imagelab-ready/baseline/approval.json \
  --output-dir /tmp/aegis-live-approved-baseline-1 --approve-live-inference
```

For the full comparison, prepare/review three fresh equal-limit approvals,
**including baseline** (the earlier single-target approval is consumed). Put their
absolute `approval` paths in a new copy of the three-target plan, run
`live_trial preflight` again, then:

```sh
PYTHONPATH=attack_lab/src /home/youss/Projects/aegis/.venv/bin/python -m aegis_lab.live_trial run \
  /tmp/aegis-live-imagelab-ready/plan.json \
  --output-dir /tmp/aegis-live-approved-comparison-1 --approve-live-inference
```

This uses seeded randomized order, equal model/request/token/spend limits and fresh
providers. The three $0.10 approvals permit at most $0.30 aggregate. Every response
is private; failures remain visible in `experiment.json`, operational `failure.json`
or `live-trial.json`. Exit 0 means acceptable generation for every requested target;
it never means behavioral reconstruction. Missing fingerprints leave reported
identity comparability unestablished. Candidate archives remain behaviorally
unscored until Core separately authorizes compilation and execution.

`run_live_reconstruction` is the new Python entry point. The legacy offline
`run_reconstruction` record format remains unchanged and disclosure approval alone
still fails. Its CLI `run-live` also supports `--inference-approval`, `--artifact`,
`--output-dir` and `--steps`, alongside its existing disclosure review/opt-in.
`run_experiment` and `run_controlled_pair` accept the same inference approvals.
Exact request/response bodies, model-reported identities, usage, UTC timestamps,
candidates and the approval are archived content-addressed with 0700 directories
and 0600 files. `experiment.verify_experiment` reloads hashes and provenance offline.

## Integration ownership

All changes are under `attack_lab/`. Root `ARCHITECTURE.md` and shared ADRs were
not changed under the explicit ownership restriction. Role A must incorporate this
Lab-local authorization/transport decision in the root architecture at integration;
no Core, shared API/storage contract or execution gate has been changed here.

## Validation and remaining limits

Final strict Lab integration: **1,948 passed, zero failures/skips/warnings**, 160.98 s;
log `/tmp/aegis-live-integration-final.log`. This includes real Ghidra and deterministic
external-provider fakes, with no live model access or candidate execution. The 47
new live-inference tests cover approval negatives, deadline phases, worker wire
provenance, private archival, catalogue failures, refusals, usage, iterative scope,
pairs and the three-variant runner. Focused final run: **461 passed**, no warnings,
27.68 s; log `/tmp/aegis-live-focused-final.log`.

Companion Core/API/CLI/real LLVM adapter suite: **199 passed, one warning**, 14.87 s;
log `/tmp/aegis-live-companion-python-pinned.log`. The warning is the installed
Starlette/httpx TestClient deprecation; no dependencies were installed or changed.
Shield CTest: **1/1 passed**, 1.27 s, using `/tmp/aegis-shield-build`.
ImageLab CTest: **14/14 passed**, 4.22 s, using `/tmp/aegis-role-b-imagelab`.
These use existing matching LLVM 22.1.8 builds, not newly built plugins.

The strict Lab command used the existing Core execution-contract snapshot from
Role B's handoff; the companion command used this checkout's unchanged Core:

```sh
PYTHONPATH=attack_lab/src:/tmp/aegis-role-b-core-snapshot/src \
AEGIS_GHIDRA_HEADLESS=/home/youss/Applications/ghidra_12.1.4_PUBLIC/support/analyzeHeadless \
  /home/youss/Projects/aegis/.venv/bin/python -m pytest attack_lab/tests --lab-profile integration -q
PYTHONPATH=core/src:platform/api/src:platform/cli/src \
  /home/youss/Projects/aegis/.venv/bin/python -m pytest \
  core/tests platform/api/tests platform/cli/tests protectors/llvm/adapter/tests -q \
  --shield-plugin /tmp/aegis-shield-build/AegisShield.so --shield-opt /usr/bin/opt --shield-clang /usr/bin/clang
```

Earlier verification failures remain in private logs: the first strict run was
**1 failed / 1,941 passed** because concurrent ImageLab preparation tripped the
existing global Ghidra-process assertion; it passed unchanged in the isolated run.
The first offline run was **1 failed / 1,909 passed / 23 not run** because a test
hardcoded the absent local `.venv`; that owned test now uses the running interpreter
and this checkout's module path. A sandboxed companion run stopped progressing and
was interrupted. Its unrestricted retry passed 105 Core/API/CLI tests but had 94
adapter setup errors because the default plugin path was absent; explicitly pinning
the existing plugin resolved all 94. No failed run is counted as a pass.

Live authenticated catalogue access and genuine NVIDIA inference: **not run**,
operator approval absent and `NEBIUS_API_KEY` not configured in this environment.
Candidate compilation/execution/scoring: **not run**, separate Core authorization
and runtime required. REA integration: **not implemented**. Shared architecture
sync remains with Role A under the ownership restriction.

## Changed files

- `attack_lab/README.md`
- `attack_lab/docs/live-inference.md`
- `attack_lab/scripts/prepare_imagelab_live.py`
- `attack_lab/src/aegis_lab/bounded_provider.py`
- `attack_lab/src/aegis_lab/disclosure.py`
- `attack_lab/src/aegis_lab/experiment.py`
- `attack_lab/src/aegis_lab/inference.py`
- `attack_lab/src/aegis_lab/live.py`
- `attack_lab/src/aegis_lab/live_trial.py`
- `attack_lab/src/aegis_lab/provider.py`
- `attack_lab/src/aegis_lab/provider_worker.py`
- `attack_lab/src/aegis_lab/reconstruction.py`
- `attack_lab/tests/test_live_inference.py`
- `attack_lab/tests/test_paired_trial.py`
- `attack_lab/tests/test_reconstruction.py`
- `attack_lab/tests/test_reconstruction_cli.py`
