# NVIDIA research evidence deliverable — 30 October 2026 UTC

The operator's historical experiment and all 11 archived regular files remain
byte-for-byte unchanged. The separate post-hoc report was parsed strictly and
**every field was independently recomputed** against that verified archive.
Matching a report's source hash alone is insufficient: altered hashes, model,
usage, candidate state, booleans, limitations or extra fields are rejected.
No live request, approval consumption, spending-limit edit, generated-code
execution, package installation, commit or push occurred during this work.

## Exported public evidence

Import only this file into Agent 3's **Research** dashboard, supplying its digest
separately:

```text
/tmp/aegis-nvidia-baseline-public-summary.json
SHA-256: 16be4b7bf0bfdbbe36389aca550fa703fe7f35c5e5dc3f4161b87d87e41292b6
```

The schema remains `aegis.product.evidence.v2`, kind `reconstruction`, with strict
optional `completion_parser` and `post_hoc_review` additions. Existing v2 imports
remain supported. Every nested post-hoc key is allowlisted. Raw reasoning,
prompts, generated source, responses, private records, approvals, credentials,
fingerprints and private paths are excluded. Only safe metadata and hashes were
exported; the file is 0600. The source experiment's status/candidate fields are
not replaced by the independently revalidated candidate.

| Fact | Verified value / interpretation |
| --- | --- |
| Requested and provider-reported NVIDIA model | `nvidia/Nemotron-3_5-Lightning`, exact match; weights not independently verified |
| Historical generation state | `invalid_output`; original candidate SHA-256 remains null |
| Historical parser | `aegis.lab.completion-parser.v1` |
| Post-hoc parser | `aegis.lab.nebius-reasoning-text.v2` |
| Separate post-hoc state | `candidate_text_revalidated_but_behaviorally_unscored` |
| Candidate envelope | Structurally valid; no compilation, execution or behavioral score |
| Observed provider-reported usage | **1786 prompt + 8039 completion = 9825 total tokens** |
| Archived estimated reported-token cost | **2037 micro-USD = $0.002037**; approved-price estimate, not an invoice |
| Actual billed cost | Unknown/null |
| Historical conservative token charge | Full context plus output reservation, separate from reported usage |
| Historical reserved spend | **64881 micro-USD = $0.064881**, not actual billing |
| Reported model-weight fingerprint | Missing; weight-level identity comparability is not established |
| Behavioral scoring / attack effectiveness | Pending authorized runtime / not established |

The public envelope source hash is the original experiment JSON hash:
`b62672834231442ad53ecdc1f1ec5ed4b50e27343f0400fc7f6397890415126a`.
The nested review binds the verified sidecar hash
`a5fa0aae488f93428522e10dc0bbbe4f564206bf6480118108bd5334baada63b`,
the archived response hash and the separately revalidated candidate-text hash.
Local unsigned consistency checks cannot independently attest provider origin,
weights, token counts, billing, retention or reverse-engineering success.

Exact export command used (the output now exists and will not be overwritten):

```sh
PYTHONPATH=attack_lab/src .venv/bin/python scripts/export-product-evidence.py \
  reconstruction /tmp/aegis-operator-review-i2Si6nvI/baseline-8192-live-run \
  --post-hoc-report /tmp/aegis-nebius-compat-post-hoc-review.json \
  --output /tmp/aegis-nvidia-baseline-public-summary.json
```

The original archive, its approval and the supplied sidecar were not edited.
Dashboard import uses the public projection only. Agent 3 reported a successful
desktop (1440×1000) and mobile (390×844) import of these exact bytes/digest with
**zero browser POSTs**, separate original/post-hoc states, **14 contract tests and
22 browser tests passed**, and TypeScript/build passed. Screenshots:
`/tmp/aegis-dashboard-nvidia-post-hoc.png` and
`/tmp/aegis-dashboard-nvidia-post-hoc-mobile.png`. Those frontend checks were
performed by Agent 3, not rerun by Agent 2.

## Configurations and remaining requests

The old prepared plan still declares 2048 output tokens and different trial/pair
IDs. The actual baseline declares **8192 output tokens**. The old manifests cannot
be reused unchanged as an equal-configuration continuation.

`aegis_lab.remaining_inference` verified the actual baseline, old plan, Ghidra
bindings and on-disk artifacts. In a **new private directory** it reissued only
pair/trial identities and the sampling digest derived from the actual baseline's
8192-token request. Every other baseline field must match exactly, and both
protected declarations must pass `validate_pair` against the archived baseline.
It rejects changed compiler/workflow/access/budget conditions or artifact bytes
before writing output. The original plan remains read-only, with SHA-256:
`37fae93210ab83ba411a9fe1df038318de5476eed3ab51c392f3c848fff7b1b0`.

Prepared files are under **`/tmp/aegis-nvidia-remaining-8192`**:

- `comparability.json`: checked artifact/report/manifest/prompt hashes and limits.
- `operator-commands.json`: exact preflight and run argv arrays; never executed.
- `shield/manifest.json`, `mirage/manifest.json`: fresh paired declarations.
- Each target's `approval.DRAFT.json`: **invalid**, both review booleans false.
- Each target's `approval.DRAFT.json.request-review.json`: private exact request
  body for operator review; never import it into the dashboard or repository.

The preparation command already run was entirely offline:

```sh
PYTHONPATH=attack_lab/src .venv/bin/python -m aegis_lab.remaining_inference \
  /tmp/aegis-operator-review-i2Si6nvI/baseline-8192-live-run \
  /tmp/aegis-live-imagelab-ready/plan.json \
  --output-dir /tmp/aegis-nvidia-remaining-8192
```

Use a fresh output directory to repeat preparation. Preparation neither grants
approval nor reserves inference usage. It constructs no provider or runner.

| Shared request/approval setting | Exact baseline-matched value |
| --- | --- |
| Model | `nvidia/Nemotron-3_5-Lightning` |
| Temperature / sampling | 0.0; archived settings and derived sampling digest |
| Requests / workflow steps per target | 1 / 1 |
| Output cap | 8192 tokens |
| Aggregate token budget per target | 2000000 |
| Published context reservation | 1048576 tokens |
| Input / output price caps | 60000 / 240000 micro-USD per million tokens |
| Approval spending ceiling | **10000000 micro-USD = $10 per target**, copied from the actual baseline approval, not increased |
| Per-request timeout / trial wall budget | 120 / 240 seconds |
| Conservative per-request reservation | 64881 micro-USD = $0.064881 |
| Parser for the remaining runs | `aegis.lab.nebius-reasoning-text.v2` |

The two proposed approval ceilings total **$20**, while the two conservative
single-request reservations total **$0.129762** at these caps. Neither figure is
actual billing, nor approval to spend. The operator must deliberately review these
existing baseline-matched ceilings. Current catalogue/account availability and
prices have not been queried; the live runner must check them freshly after approval.

**Comparability limits:** request conditions are matched, but the baseline was
already observed first. This is not a randomized prospective three-way trial.
Its historical parser was v1; only its explicitly labeled post-hoc interpretation
uses the same v2 policy as future runs. Do not compare the original failure as a
reconstruction failure or silently replace it with success. Baseline selected
decompilation differs from Shield; Shield and Shield+Mirage have identical
selected-function prompts. The model never sees the decoy inventory, so this
experiment cannot establish Mirage distraction benefit. Build provenance remains
operator-declared; no candidate behavior or protection effect is established.

## Required operator actions and exact two runs

The two live commands below **have not been executed**. They require separate
operator approvals; the consumed baseline approval must not be reused. Privately
review each draft and request-review body, exact model, disclosure findings,
hashes, limits, provider retention terms and local deletion date. Only the operator
may create each target's `approval.json`, owner-only 0600, with an actual
reviewer/reference, fresh valid UTC window/deadline, reviewed retention terms and
both `operator_approved` and `provider_retention_reviewed` set deliberately true.
Refresh draft times if expired. Preserve scope hashes and limits. No generated
candidate compilation or execution is authorized by these files.

Keep any credential in the operator's own private environment; do not print it,
copy it into JSON, command arguments, evidence files or the dashboard.

After those independent reviews, run the two local preflights:

```sh
PYTHONPATH=attack_lab/src .venv/bin/python -m aegis_lab.live preflight \
  /tmp/aegis-nvidia-remaining-8192/shield/manifest.json \
  /tmp/aegis-live-imagelab-ready/shield/ghidra/ghidra-analysis.json \
  /tmp/aegis-role-b-imagelab/shield/imagelab-cli \
  --steps 1 --max-output-tokens 8192 \
  --approval /tmp/aegis-nvidia-remaining-8192/shield/approval.json
PYTHONPATH=attack_lab/src .venv/bin/python -m aegis_lab.live preflight \
  /tmp/aegis-nvidia-remaining-8192/mirage/manifest.json \
  /tmp/aegis-live-imagelab-ready/mirage/ghidra/ghidra-analysis.json \
  /tmp/aegis-role-b-imagelab/external/imagelab-cli \
  --steps 1 --max-output-tokens 8192 \
  --approval /tmp/aegis-nvidia-remaining-8192/mirage/approval.json
```

Only if separately approved, the operator runs **Shield**:

```sh
PYTHONPATH=attack_lab/src .venv/bin/python -m aegis_lab.live run \
  /tmp/aegis-nvidia-remaining-8192/shield/manifest.json \
  /tmp/aegis-live-imagelab-ready/shield/ghidra/ghidra-analysis.json \
  /tmp/aegis-role-b-imagelab/shield/imagelab-cli \
  --steps 1 --max-output-tokens 8192 \
  --approval /tmp/aegis-nvidia-remaining-8192/shield/approval.json \
  --output-dir /tmp/aegis-nvidia-remaining-8192/shield-live-run --approve-live-inference
```

Only if separately approved, the operator runs **Shield+Mirage**:

```sh
PYTHONPATH=attack_lab/src .venv/bin/python -m aegis_lab.live run \
  /tmp/aegis-nvidia-remaining-8192/mirage/manifest.json \
  /tmp/aegis-live-imagelab-ready/mirage/ghidra/ghidra-analysis.json \
  /tmp/aegis-role-b-imagelab/external/imagelab-cli \
  --steps 1 --max-output-tokens 8192 \
  --approval /tmp/aegis-nvidia-remaining-8192/mirage/approval.json \
  --output-dir /tmp/aegis-nvidia-remaining-8192/mirage-live-run --approve-live-inference
```

Each permits at most one inference POST after fresh catalogue GETs. Retain the
single-use `.inference-uses/` directory beside each approval, including after
failure or uncertainty. Do not retry a consumed approval or remove its reservation.
Do not run the three-target runner: that would request a new baseline unnecessarily.
Afterward, preserve all failures and verify/export each available experiment:

```sh
PYTHONPATH=attack_lab/src .venv/bin/python scripts/export-product-evidence.py \
  reconstruction /tmp/aegis-nvidia-remaining-8192/shield-live-run \
  --output /tmp/aegis-nvidia-shield-public-summary.json
PYTHONPATH=attack_lab/src .venv/bin/python scripts/export-product-evidence.py \
  reconstruction /tmp/aegis-nvidia-remaining-8192/mirage-live-run \
  --output /tmp/aegis-nvidia-mirage-public-summary.json
```

Only these public projections and their separately supplied digests should enter
Research. Until the two archives exist, their generation/usage results remain
unmeasured. No successful behavioral three-way comparison is available.

## Final validation

Existing CPython 3.14.7, LLVM 22.1.8 and Ghidra 12.1.4; no dependency changes.

```sh
PYTHONPATH=attack_lab/src .venv/bin/python -m pytest \
  attack_lab/tests/test_research_deliverable.py attack_lab/tests/test_nebius_reasoning.py \
  attack_lab/tests/test_public_summary.py attack_lab/tests/test_provider.py \
  attack_lab/tests/test_live_inference.py attack_lab/tests/test_experiment.py -q
PYTHONPATH=attack_lab/src .venv/bin/python -m pytest attack_lab/tests --lab-profile offline -q
AEGIS_GHIDRA_HEADLESS=/home/youss/Applications/ghidra_12.1.4_PUBLIC/support/analyzeHeadless \
PYTHONPATH=attack_lab/src .venv/bin/python -m pytest attack_lab/tests --lab-profile integration -q
PYTHONPATH=core/src:platform/api/src:platform/cli/src .venv/bin/python -m pytest \
  core/tests platform/api/tests platform/cli/tests provenance/tests sentinel/tests \
  protectors/llvm/adapter/tests scripts/tests -q \
  --shield-plugin /tmp/aegis-shield-build/AegisShield.so --shield-opt /usr/bin/opt --shield-clang /usr/bin/clang
ctest --test-dir /tmp/aegis-shield-build --output-on-failure
ctest --test-dir /tmp/aegis-role-b-imagelab --output-on-failure
git diff --check -- attack_lab scripts/export-product-evidence.py
```

| Suite | Exact result | Log |
| --- | --- | --- |
| Focused regressions | **314 passed**, zero skips/warnings; 20.86 s. Includes 26 new sidecar/public-projection/continuation cases. | `/tmp/aegis-nvidia-deliverable-focused-final.log` |
| Full offline Lab | **2082 passed, 23 NOT RUN**, zero failures/warnings; 74.56 s. 22 real-Ghidra cases omitted and one local socket fixture blocked by sandbox. | `/tmp/aegis-nvidia-deliverable-offline.log` |
| Strict Lab, real Ghidra | **2105 passed**, zero failures/skips/warnings; 169.74 s. Covers all 23 omitted cases. | `/tmp/aegis-nvidia-deliverable-integration.log` |
| Companion Python, real LLVM adapter, scripts | **753 passed**, zero skips, one existing Starlette/httpx TestClient deprecation warning; 45.97 s. | `/tmp/aegis-nvidia-deliverable-companion.log` |
| Existing Shield CTest | **1/1 passed**, 1.17 s; existing matching build, not rebuilt by Agent 2. | `/tmp/aegis-nvidia-deliverable-shield.log` |
| Existing ImageLab CTest | **14/14 passed**, 4.19 s; trusted ImageLab tests, no generated candidates. | `/tmp/aegis-nvidia-deliverable-imagelab.log` |

The first focused run had **1 failed / 118 passed**: its new fixture put the
output under the original plan's protected parent directory. The preparation
correctly refused. The test input plan now lives in its own read-only source
directory; production validation was not relaxed. Strict Lab and companion tests
ran outside the sandbox for local socket/subprocess integration. No paid request
or generated-code execution occurred in any validation.

The current blockers are the **two separate operator approvals and live runs**,
missing baseline weight fingerprint, selected-function scope, and absent
authorized behavioral scoring. Source/build provenance and provider billing are
not independently established. Root architecture synchronization belongs to
Agent 1 under the ownership restriction; Agent 2 changed no Core/API/dashboard
implementation or shared authorization gate.

## Every file changed in this follow-up

- `attack_lab/src/aegis_lab/completion_review.py`
- `attack_lab/src/aegis_lab/public_summary.py`
- `attack_lab/src/aegis_lab/remaining_inference.py`
- `scripts/export-product-evidence.py`
- `attack_lab/tests/test_research_deliverable.py`
- `attack_lab/tests/fixtures/public-summary/schema.json`
- `attack_lab/tests/fixtures/public-summary/synthetic-post-hoc.json`
- `attack_lab/README.md`
- `attack_lab/docs/live-inference.md`
- `attack_lab/docs/public-summary.md`
- `attack_lab/docs/nvidia-research-deliverable.md`

The shared checkout contains earlier tasks and other agents' changes; those are
not part of this follow-up. Private archives, prompts, source, reasoning and
approval records were not added to the repository.
