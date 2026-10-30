# Judge reproduction: a real NVIDIA request through Nebius

Release-readiness audit, 30 October 2026. Run from the extracted `aegis/`
directory or approved release checkout, after [INSTALL.md](INSTALL.md). This
route creates its own artifacts, Ghidra records and approval drafts. It needs no
team filesystem, old response archive, signing key or team credential. Linux
x86-64, matching LLVM/Clang 22, Ghidra **12.1.4**, JDK 21+, and the installed Lab
and Mirage Python packages are required. Obtain Ghidra and review its terms
separately; it is not bundled.

The code path is `aegis_lab.live run` → `run_live_reconstruction` → controlled
experiment → `BoundedNebiusProvider` → `NebiusProvider.complete` → HTTPS
`POST https://api.tokenfactory.nebius.com/v1/chat/completions`. The exact model
is supplied while preparing the manifest below; do not rely on the provider
module's unrelated default model. A dashboard JSON import performs no inference.
Nebius documents the [endpoint and bearer authentication](https://docs.tokenfactory.nebius.com/api-reference/introduction)
and [chat-completion interface](https://docs.tokenfactory.nebius.com/api-reference/inference/create-chat-completion).
These pages were checked during this audit. Current account availability, model
catalogue, tariff, retention terms and credits must still be checked at run time.

## 1. Prepare fresh, owned inputs without networking or credentials

These commands build only repository-owned ImageLab code. They do not run a
model, consume an inference approval, or compile/execute generated candidates.
Only use `--authorized-owned-artifacts` when you are authorized to analyze and
disclose the supplied artifacts. Use the owned fixture for judging; external
target code is unnecessary.

```sh
umask 077
JUDGE_WORK=$(mktemp -d /tmp/aegis-judge-XXXXXXXX)
GHIDRA_HEADLESS=/absolute/path/to/ghidra_12.1.4_PUBLIC/support/analyzeHeadless

cmake -S protectors/llvm -B "$JUDGE_WORK/shield" -G Ninja \
  -DLLVM_DIR="$(llvm-config --cmakedir)" \
  -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Release
cmake --build "$JUDGE_WORK/shield" -j2
cmake -S demo/image_processor -B "$JUDGE_WORK/imagelab" -G Ninja \
  -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Release \
  -DIMAGELAB_SHIELD_PLUGIN="$JUDGE_WORK/shield/AegisShield.so"
cmake --build "$JUDGE_WORK/imagelab" -j2
.venv/bin/python -m aegis_mirage \
  "$JUDGE_WORK/imagelab/ir/kernels.shield.ll" \
  --output-dir "$JUDGE_WORK/mirage" --seed 42
cmake -S demo/image_processor -B "$JUDGE_WORK/imagelab" -G Ninja \
  -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Release \
  -DIMAGELAB_SHIELD_PLUGIN="$JUDGE_WORK/shield/AegisShield.so" \
  -DIMAGELAB_EXTERNAL_KERNELS_IR="$JUDGE_WORK/mirage/module.ll"
cmake --build "$JUDGE_WORK/imagelab" -j2
ctest --test-dir "$JUDGE_WORK/imagelab" --output-on-failure

.venv/bin/python attack_lab/scripts/prepare_imagelab_live.py \
  --build-dir "$JUDGE_WORK/imagelab" \
  --mirage-report "$JUDGE_WORK/mirage/report.json" \
  --ghidra-headless "$GHIDRA_HEADLESS" \
  --output-dir "$JUDGE_WORK/prepared" \
  --source-revision judge-local-rebuild-record-release-manifest-separately \
  --model nvidia/Nemotron-3_5-Lightning \
  --max-model-tokens 2000000 --max-output-tokens 8192 --steps 1 \
  --authorized-owned-artifacts
```

Keep the downloaded archive checksum and `RELEASE-MANIFEST.json` beside your
private reproduction record. The source-revision string above is a declaration,
not verified build provenance. Preparation binds actual artifact/report/tool
digests, checks distinct final binaries, changed baseline/Shield selected
decompilation and Mirage decoy retention. It fails explicitly if a new toolchain
does not reproduce those conditions. Do not substitute fake evidence to proceed.

## 2. Draft and independently review the disclosure and spending authorization

```sh
MANIFEST="$JUDGE_WORK/prepared/baseline/manifest.json"
GHIDRA_REPORT="$JUDGE_WORK/prepared/baseline/ghidra/ghidra-analysis.json"
OWNED_BINARY="$JUDGE_WORK/imagelab/ir-baseline/imagelab-cli"

.venv/bin/python -m aegis_lab.live draft \
  "$MANIFEST" "$GHIDRA_REPORT" "$OWNED_BINARY" \
  --max-output-tokens 8192 --steps 1 \
  --context-tokens 1048576 \
  --input-microusd-per-million 60000 \
  --output-microusd-per-million 240000 \
  --max-spend-microusd 100000 --request-timeout 120 \
  --output "$JUDGE_WORK/approval.DRAFT.json"
```

The numbers are archived **review proposals**, not a claim about today's prices
or availability. The proposed spend ceiling is **$0.10**, one request, 120-second
timeout, 8,192 maximum completion tokens. At those caps the conservative reserve
is **$0.064881** and **1,056,768 budget tokens**, reserving the entire published
context plus output. This is a local accounting rule, not a provider billing
quota or an invoice. A different catalogue context/price may require a fresh
draft and independent review; the live path refuses mismatches or price excess.

During this audit, a fresh unauthenticated public catalogue GET confirmed this
exact ID active with the same 1,048,576 context and $0.06/M input, $0.24/M output
values. This does not replace the runner's fresh account/catalogue checks at
the time of an approved request. See the
[public catalogue](https://tokenfactory.nebius.com/api/public/models_info).

Privately inspect `approval.DRAFT.json` and its sibling
`approval.DRAFT.json.request-review.json` (the exact initial request body,
including selected Ghidra text). Review rights to disclose that text, its hash
bindings, endpoint, exact model, all limits, retention terms and archive deletion
date. The draft is deliberately invalid. The spending/disclosure decision must
come from the credential/account operator, not an agent preparing the draft.

After approving, the operator saves a **new 0600** `approval.json`, preserving
all reviewed hashes and limits and setting:

- `operator_approved` and `provider_retention_reviewed` deliberately to `true`;
- `disclosure.approved_by`, `disclosure.reference`, and scope to actual reviewed values;
- `disclosure.created_at`, `valid_from`, `expires_at` and `request_deadline` to
  a fresh valid UTC window (deadline inside the approval window);
- `provider_retention_policy` to the applicable reviewed terms, and
  `private_archive_delete_after` to the actual deletion commitment after the deadline.

Do not place a credential in either file. `store=false` does not promise zero
provider retention. Local deletion on the specified date is the operator's duty.
No supplied expired approval or team approval is reusable.

## 3. Operator-only runtime request using their own credential

Only after the above spending decision: configure **your own** `NEBIUS_API_KEY`
privately in the runner's environment through your normal secret mechanism.
Do not put it in command arguments, shell history, frontend settings, recordings,
source or reports. The release task did not inspect or use a credential.

Offline preflight reads no credential value, sends zero requests, and consumes
no approval. Require `approval_validated: true`, the exact proposed model,
`candidate_execution_authorized: false`, and the approved spend ceiling:

```sh
.venv/bin/python -m aegis_lab.live preflight \
  "$MANIFEST" "$GHIDRA_REPORT" "$OWNED_BINARY" \
  --max-output-tokens 8192 --steps 1 \
  --approval "$JUDGE_WORK/approval.json"
```

**The next command is the genuine, potentially billable runtime integration.**
It is provided for the independently authorizing operator; it was not executed
by the release-readiness task:

```sh
.venv/bin/python -m aegis_lab.live run \
  "$MANIFEST" "$GHIDRA_REPORT" "$OWNED_BINARY" \
  --max-output-tokens 8192 --steps 1 \
  --approval "$JUDGE_WORK/approval.json" \
  --output-dir "$JUDGE_WORK/runtime-request-1" --approve-live-inference
```

The runner reserves a single-use approval before authenticated account-model and
public-catalogue GETs, then sends **at most one inference POST**. It checks
availability and context/pricing before target disclosure. The credential goes
to the bounded HTTPS worker through stdin, never worker argv or archived output.
There are no automatic inference retries. Preserve `.inference-uses/` beside
the approval even on failure or crash. A failed POST may still cost money;
obtain a fresh independently reviewed approval for any further attempt.

Success exits 0 with `generated_but_behaviorally_unscored`; other outcomes remain
explicit failures. Private `experiment.json` records request/response provenance,
requested/reported model identity, usage and accounting when available. Some
operational failures produce only `failure.json`. Neither exit 0 nor a valid
candidate envelope proves correct reconstruction or protection effectiveness.

## 4. Offline verification and safe optional dashboard import

```sh
.venv/bin/python scripts/export-product-evidence.py \
  reconstruction "$JUDGE_WORK/runtime-request-1" \
  --output "$JUDGE_WORK/runtime-public-summary.json"
sha256sum "$JUDGE_WORK/runtime-public-summary.json"
```

The exporter verifies private archive bindings before producing an allowlisted
summary and prints its SHA-256. If the experiment is absent or invalid it refuses;
retain the failure rather than inventing a summary. Import only the public JSON
and separately supplied digest into **Research**. Raw prompts, reasoning,
candidate source, responses, approvals and archives stay private. Local hashes
are consistency evidence; they do not authenticate provider origin or weights.

This is a new single-baseline reproduction, not a continuation of the team's
historical response and not a three-way study. Shield/Mirage continuations need
separate approvals. Their selected-function prompts in the historical design
are identical and do not expose the decoy inventory. Generated candidates remain
uncompiled and unexecuted; Core's two attack-lab gates stay disabled.

## Team runtime handoff (distinct from a judge's own account)

The operator's separate Fish terminal at `/home/youss/Projects/aegis` already
has `NEBIUS_API_KEY` exported. No agent needs to obtain or copy it. The operator
centrally coordinates all spending under the shared $20 total and per-request
approval; no additional agent-accessible ledger is required. **Claude owns the
baseline and Shield live evaluation. Do not run this guide's baseline as an
extra team request or create another three-way batch without coordinating with
that experiment.** Reuse its verified fresh records where appropriate.

This guide's shell snippets use POSIX shell syntax. From Fish, an operator can
run a reviewed script with `bash /absolute/path/to/reviewed-script.sh`; exported
credentials are inherited without including their value in argv. Do not enable
shell tracing. Have the script reference the exact approved regular 0600
approval, target manifest/report/binary and a new output directory. Use the
production `aegis_lab.live run` command above; keep `.inference-uses/` intact.
Only the operator performs any interactive approval required by their chosen
wrapper. No agent should simulate a terminal or supply interactive answers.

The fresh preparation checked by this release task is in
`/tmp/aegis-judge-vkUjlWvC`, with `prepared/{baseline,shield,mirage}` manifests,
fresh Ghidra reports and `approval.DRAFT.json` for baseline. It is a concrete
offline review artifact, **not a queued paid request** and not a judge dependency.
Proposed cap for one separately selected request: $0.10; conservative reservation
at observed catalogue caps: $0.064881. Actual cost is unknown until usage, then
estimated from reported prompt/completion tokens and approved prices, separately
from actual billing. Further approval must not duplicate Claude's reserved work.

## Explicit thinking control in the final runtime

The final production provider supports an optional hash-bound
`chat_template_kwargs.enable_thinking=false`, exposed as `--disable-thinking`
on controlled Lab draft/preflight/run and `scripts/live_evaluate.py prepare/run`.
Do not add the flag to an old manifest/approval or to the ImageLab preparation
helper above: prepare a matching new request using the production wrapper and
review its exact request body first. Omission preserves historical request bytes.
See [thinking-control](../../attack_lab/docs/thinking-control.md) and
[the genuine final demonstration](../../benchmarks/reconstruction/NVIDIA_DEMO.md).
No returned candidate is executed by inference-only approval.
