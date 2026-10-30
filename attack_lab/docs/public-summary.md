# Public Lab summary contract for Agent 3

The executable contract is [`public_summary.py`](../src/aegis_lab/public_summary.py).
The exact generated JSON Schemas and three import fixtures are in
[`tests/fixtures/public-summary/`](../tests/fixtures/public-summary/).
`schema.json` maps the two `kind` values to standalone JSON Schemas; it is not
itself a standalone JSON Schema. Every object rejects additional properties.
Every original field below is required, including nullable fields. The optional
`completion_parser` and `post_hoc_review` additions preserve old v2 imports.
Integers must be
nonnegative JavaScript safe integers (at most 9007199254740991).

The exporter now emits `aegis.product.evidence.v2` for reconstruction and its
comparison. Mirage and benchmark exports remain v1. Keep the existing v1 reader
for historical offline imports; do not interpret v1 as this contract.

## Envelope

Exactly five keys:

```ts
type LabEvidence = {
  schema: "aegis.product.evidence.v2";
  kind: "reconstruction" | "reconstruction_comparison";
  source_sha256: string; // lowercase 64 hex, the private source JSON bytes
  verification: "offline_hash_bindings_checked";
  summary: ReconstructionSummary | ComparisonSummary; // selected by kind
};
```

The importer must compare SHA-256 of the exact uploaded summary bytes with the
separately supplied exporter digest, validate the matching schema, reject unknown
fields recursively, and keep imports local. Do not upload evidence or contact
Nebius. These hashes establish consistency of unsigned local files. They are
not a signature, proof of provider contact, verified model weights, or independent
attestation of token usage. An external-provider test double can produce a
structurally identical private archive; archive verification cannot distinguish
one from a real account response. The operator must establish evidence origin.

## ReconstructionSummary

| Fields | Type / semantics |
| --- | --- |
| `evidence_label` | `offline_scripted`, `external_provider_record`, or `synthetic_fixture`. Always display prominently. The exporter chooses the first two from the verified provider record. |
| `trial_id`, `pair_id` | lowercase 32 hex |
| `artifact_sha256` | lowercase 64 hex |
| `candidate_sha256` | lowercase 64 hex or null; candidate text only, never behavioral success |
| `generation_status` | Closed enumeration `GenerationStatus` in schema; never arbitrary diagnostic text. Includes `generated_but_behaviorally_unscored`, refusals, usage overruns, model verification failures, budget/deadline stops and interruptions. |
| `behavioral_scoring` | exactly `pending_authorized_core_runtime` |
| `provider` | `FakeOffline` or `Nebius` |
| `requested_model` | ≤200 ASCII characters; model-name syntax in schema; Nebius requires `nvidia/` prefix |
| `reported_model` | requested model only when every step reports that exact value; otherwise null. Arbitrary mismatching provider text is excluded. |
| `reported_model_status` | `matched`, `missing`, `mismatch`, or `mixed` |
| `reported_identity_sha256` | lowercase 64 hex or null. SHA-256 of canonical JSON `[[reported_model, system_fingerprint]]` only when every step has the same nonempty pair. Raw fingerprints are excluded. |
| `steps` | request attempts, including unsuccessful ones |
| `charged_tokens` | conservative ledger charge; **not measured token use** |
| `known_reported_tokens` | sum of provider-reported totals where usage is present; zero can mean no known usage |
| `reported_tokens`, `prompt_tokens`, `completion_tokens` | provider-reported totals only if usage is present for every attempted request; otherwise all null |
| `usage_status` | `complete`, `partial`, `unknown`, or `no_requests` |
| `cost_microusd` | null for Nebius; zero for FakeOffline. Actual live invoice unknown. |
| `cost_basis` | `provider_invoice_unknown` or `offline_no_inference_charge` respectively |
| `reserved_spend_microusd` | conservative worst-case reservation; not an invoice or refund claim |
| `estimated_reported_cost_microusd` | approved-price estimate from reported usage; null if any usage is missing; never actual billed cost |
| `execution_performed` | exactly false |
| `attack_effectiveness` | exactly `not_established` |
| `limitations` | array of fixed codes from schema, never private record prose. All four common codes below are mandatory. |
| `completion_parser` | optional/null, or `aegis.lab.completion-parser.v1` / `aegis.lab.nebius-reasoning-text.v2`; the parser used for the historical record |
| `post_hoc_review` | optional/null, or the separately verified projection below; never replaces historical state |

The optional post-hoc object contains exactly these required fields:

```ts
type PostHocReview = {
  analysis_kind: "post_hoc_parser_compatibility_review";
  report_sha256: string;
  historical_experiment_sha256: string;
  response_sha256: string;
  historical_generation_status: "invalid_output";
  historical_completion_parser: "aegis.lab.completion-parser.v1";
  revalidation_completion_parser: "aegis.lab.nebius-reasoning-text.v2";
  post_hoc_status: "candidate_text_revalidated_but_behaviorally_unscored" | "rejected";
  candidate_envelope_valid: boolean;
  candidate_sha256: string | null;
};
```

All hash fields are lowercase 64 hex. Before export the complete supplied
sidecar is independently recomputed against the immutable experiment; edits to
its hashes, usage, model, state or limitations are rejected. Only this nested
projection enters the public summary. The original parent retains
`generation_status=invalid_output`, `candidate_sha256=null`, provider Nebius and
parser v1. `historical_experiment_sha256` must equal the envelope source digest
(or the containing comparison row's digest). The nested candidate digest is
non-null exactly when the post-hoc status is accepted, which also requires
`candidate_envelope_valid=true`. That validates envelope text only. A rejected
review can still have a structurally valid envelope while other response checks
fail. Display the original and post-hoc states separately; never replace an
original failure or imply successful reverse engineering.

For complete usage, prompt + completion = total = known total and `steps > 0`.
For every other usage state, the three aggregate totals are null.
`no_requests` requires `steps === 0`; every other state requires `steps > 0`.
`matched` requires `reported_model === requested_model`; other states require
null. Generation of candidate text requires a candidate digest, and grants no
success score. Provider identity and usage remain reported observations.

Mandatory common limitations:

- `unsigned_local_evidence_not_provider_attestation`
- `candidate_text_is_not_reconstruction_success`
- `no_candidate_compilation_execution_or_behavioral_score`
- `no_established_protection_effect`

Other fixed codes describe offline scripting, provider-reported identity/usage,
unknown billing, selected-function scope, operator-declared build provenance,
and synthetic fixtures. The JSON Schema lists every allowed code. Display the
meaning of these codes in plain language; do not replace them with a success badge.

## ComparisonSummary

```ts
type ComparisonSummary = {
  evidence_label: "external_provider_record" | "synthetic_fixture";
  order: ("baseline" | "shield" | "mirage")[]; // exactly 3 unique variants
  order_seed: number;
  experiments: {
    variant: "baseline" | "shield" | "mirage"; // exactly one row each
    source_sha256: string | null;
    generation_status: GenerationStatus;
    summary: ReconstructionSummary | null;
  }[];
  reported_identity_comparable: boolean;
  behavioral_scoring: "pending_authorized_core_runtime";
  execution_performed: false;
  protection_effect: "not_established";
  limitations: Limitation[];
};
```

`mirage` means **Shield+Mirage**, not Mirage alone. Missing experiment archives
stay visible with null summary/source and an operational failure, interruption
or `not_started` state. If a row has a summary, source must be non-null and the
row generation state must equal its summary. Identity is comparable only when
all three summaries exist and their non-null `reported_identity_sha256` matches.
This says nothing about behavioral correctness or model-weight identity.

Private comparison verification rechecks each available experiment, input
bindings, manifest pair comparability, unique trial IDs/artifact hashes, equal
approved limits, provider identity, seeded execution order, result digests and
outcome fields. It never opens paths from the archived plan. An absent archive
cannot establish the outcome of any attempted network request.

The prepared ImageLab prompt sends only the selected function. Its three-way
comparison cannot measure whether a model discovers or is distracted by the
retained Mirage decoy inventory. Show this scope limit with every comparison.

## Fixtures and exact export commands

- `offline-scripted.json`: illustrative FakeOffline text generation, no model call.
- `synthetic-nebius.json`: **synthetic UI fixture**, no provider call or billing.
- `synthetic-comparison.json`: **synthetic UI fixture**, all three rows synthetic.
- `synthetic-post-hoc.json`: **synthetic UI fixture**, original failure and a separately revalidated candidate.
- `schema.json`: schemas generated from the Python models; regression tests detect drift.

Fixture digests and measurements are invented for contract tests, not evidence.
Importing fixtures must display their offline/synthetic label. Do not relabel a
synthetic fixture as a genuine experiment.

From repository root, with an operator-supplied private experiment directory:

```sh
PYTHONPATH=attack_lab/src .venv/bin/python scripts/export-product-evidence.py \
  reconstruction /tmp/OPERATOR_PRIVATE_EXPERIMENT --output /tmp/lab-summary.json
PYTHONPATH=attack_lab/src .venv/bin/python scripts/export-product-evidence.py \
  reconstruction /tmp/OPERATOR_PRIVATE_EXPERIMENT \
  --post-hoc-report /tmp/OPERATOR_POST_HOC_REPORT.json --output /tmp/lab-review-summary.json
PYTHONPATH=attack_lab/src .venv/bin/python -m aegis_lab.live_trial verify \
  /tmp/OPERATOR_PRIVATE_COMPARISON
PYTHONPATH=attack_lab/src .venv/bin/python scripts/export-product-evidence.py \
  reconstruction_comparison /tmp/OPERATOR_PRIVATE_COMPARISON \
  --output /tmp/lab-comparison-summary.json
```

Outputs are new private files; an existing output is refused. Export failure
prints a fixed diagnostic without private record values. Only public projections
should be imported into React; do not import `experiment.json`, `live-trial.json`,
approvals, `.request-review.json`, private evidence blobs or candidate code.

Root architecture synchronization belongs to Agent 1 under this task's explicit
ownership restriction. No Core, API, storage, execution or backend contract was
changed by this Lab summary contract.
