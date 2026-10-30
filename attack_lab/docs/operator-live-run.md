# Operator-only NVIDIA/Nebius inference runbook

These commands are for the operator after independent approval. Agent 2 has no
authority to approve or send them. No genuine inference was conducted during this
validation. Run from `/home/youss/Projects/aegis` with its existing `.venv`.
Do not enable candidate execution or Firecracker. No generated candidate is to be
compiled or executed by these instructions.

## Inspect and prepare one request

The existing `/tmp/aegis-live-imagelab-ready/plan.json` was inspected read-only.
Its SHA-256 is
`37fae93210ab83ba411a9fe1df038318de5476eed3ab51c392f3c848fff7b1b0`.
All three approval fields are null. Existing drafts are unapproved and expired;
do not treat them as permission. Keep the prepared plan unchanged.

```sh
PYTHONPATH=attack_lab/src .venv/bin/python -m aegis_lab.live_trial preflight \
  /tmp/aegis-live-imagelab-ready/plan.json
mkdir -m 700 /tmp/aegis-operator-review-1
PYTHONPATH=attack_lab/src .venv/bin/python -m aegis_lab.live draft \
  /tmp/aegis-live-imagelab-ready/baseline/manifest.json \
  /tmp/aegis-live-imagelab-ready/baseline/ghidra/ghidra-analysis.json \
  /tmp/aegis-role-b-imagelab/ir-baseline/imagelab-cli \
  --max-output-tokens 2048 --steps 1 \
  --context-tokens 1048576 --input-microusd-per-million 60000 \
  --output-microusd-per-million 240000 --max-spend-microusd 100000 \
  --request-timeout 120 \
  --output /tmp/aegis-operator-review-1/baseline-single.DRAFT.json
```

The context and prices above are **review proposals**, not verified current
catalogue values. The model bound by these manifests is
`nvidia/Nemotron-3_5-Lightning`. If account availability, context or prices differ,
the live check refuses the POST; do not bypass that check. A different model or
request configuration requires newly prepared manifests and approval bindings.
No tokenization or billing guarantee follows from this conservative reservation.

Privately inspect both the draft and
`baseline-single.DRAFT.json.request-review.json`, which contains the exact initial
provider body including controlled workflow instructions and selected Ghidra text.
Do not copy that private body into the dashboard, tickets or public summaries.

Only the operator may create `baseline-single.json` from the reviewed draft.
Preserve artifact/evidence/prompt/manifest/workflow hashes and approved limits;
set an actual reviewer/reference and reviewed retention terms, refresh
`disclosure.created_at`, `valid_from`, `expires_at`, `request_deadline` and
`private_archive_delete_after`, and deliberately set `operator_approved` and
`provider_retention_reviewed` to JSON **true**. The request deadline must fall
inside the disclosure approval window and archive deletion must follow it.
Keep the file owner-only (0600). This permits inference only, not code execution.
The credential must already be configured in the operator's private environment;
never print it or put it in approvals, source, command arguments or archives.

Run this local check on the approved file; it consumes no approval and performs
no networking. Credential presence means only that the environment variable name
exists; its value and validity are not inspected by preflight.

```sh
PYTHONPATH=attack_lab/src .venv/bin/python -m aegis_lab.live preflight \
  /tmp/aegis-live-imagelab-ready/baseline/manifest.json \
  /tmp/aegis-live-imagelab-ready/baseline/ghidra/ghidra-analysis.json \
  /tmp/aegis-role-b-imagelab/ir-baseline/imagelab-cli \
  --max-output-tokens 2048 --steps 1 \
  --approval /tmp/aegis-operator-review-1/baseline-single.json
```

## One authorized live request

Only after that review, the operator runs:

```sh
PYTHONPATH=attack_lab/src .venv/bin/python -m aegis_lab.live run \
  /tmp/aegis-live-imagelab-ready/baseline/manifest.json \
  /tmp/aegis-live-imagelab-ready/baseline/ghidra/ghidra-analysis.json \
  /tmp/aegis-role-b-imagelab/ir-baseline/imagelab-cli \
  --max-output-tokens 2048 --steps 1 \
  --approval /tmp/aegis-operator-review-1/baseline-single.json \
  --output-dir /tmp/aegis-live-operator-single-1 --approve-live-inference
```

The runner reserves the approval once before catalogue verification. It makes
fresh authenticated account-model and public-catalogue GETs, then **at most one**
inference POST. The proposed maximum approved spend is 100000 micro-USD ($0.10).
Provider rejection or a request that may have been processed is never retried.
Preserve `.inference-uses/` beside the approval, including after failure or a crash.
Deleting reservations or editing an approval to reuse it is not a valid retry.
A new request needs a new independent operator decision and fresh approval.

Exit 0 means a candidate envelope was accepted as text; it does not mean correct
reverse engineering. A failure may have spent credits. Inspect private
`experiment.json` or `failure.json` locally; never infer zero cost from failure.
Actual invoice cost is unknown. `store=false` is not a zero-retention guarantee;
the operator must follow the reviewed provider terms and local deletion date.

Verify and export locally after the command, including when generation failed:

```sh
PYTHONPATH=attack_lab/src .venv/bin/python scripts/export-product-evidence.py \
  reconstruction /tmp/aegis-live-operator-single-1 \
  --output /tmp/aegis-operator-review-1/baseline-single-public.json
```

The exporter invokes `verify_experiment` and prints the public file's SHA-256.
If only an operational failure exists with no experiment archive, export refuses;
retain that absence and its failure state. Supply private evidence to a trusted
local verifier only. Share the allowlisted public JSON and its separate hash with
the UI. Hash checks are unsigned consistency checks, not proof of provider origin.

## Fresh three-way comparison, only if separately approved

The single baseline approval is consumed. A subsequent comparison requires
**three fresh approvals, including a fresh baseline approval**, with equal
model/request/token/context/price/spending/timeout limits. The comparison is three
additional requests at most: four requests including the earlier smoke. With
these proposals the aggregate approved maxima are $0.30 for the comparison and
$0.40 including the smoke. These are not invoice estimates.

Generate a new invalid draft for each variant. The loop below performs no network
access, consumes no approval and does not change the prepared plan:

```sh
for variant in baseline shield mirage; do
  case "$variant" in
    baseline) artifact=/tmp/aegis-role-b-imagelab/ir-baseline/imagelab-cli ;;
    shield) artifact=/tmp/aegis-role-b-imagelab/shield/imagelab-cli ;;
    mirage) artifact=/tmp/aegis-role-b-imagelab/external/imagelab-cli ;;
  esac
  PYTHONPATH=attack_lab/src .venv/bin/python -m aegis_lab.live draft \
    "/tmp/aegis-live-imagelab-ready/$variant/manifest.json" \
    "/tmp/aegis-live-imagelab-ready/$variant/ghidra/ghidra-analysis.json" "$artifact" \
    --max-output-tokens 2048 --steps 1 \
    --context-tokens 1048576 --input-microusd-per-million 60000 \
    --output-microusd-per-million 240000 --max-spend-microusd 100000 \
    --request-timeout 120 \
    --output "/tmp/aegis-operator-review-1/$variant-comparison.DRAFT.json"
done
```

Review every request body and create private, newly approved
`baseline-comparison.json`, `shield-comparison.json`, and `mirage-comparison.json`
using the same independent process as above. `mirage` here is **Shield+Mirage**.
Only after approving all three, create a new plan that references those files:

```sh
.venv/bin/python - <<'PY'
import json, os
from pathlib import Path
prepared = Path('/tmp/aegis-live-imagelab-ready/plan.json')
review = Path('/tmp/aegis-operator-review-1')
plan = json.loads(prepared.read_bytes())
for variant in ('baseline', 'shield', 'mirage'):
    plan[variant]['approval'] = str(review / (variant + '-comparison.json'))
fd = os.open(review / 'comparison-plan.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as stream:
    json.dump(plan, stream)
PY
PYTHONPATH=attack_lab/src .venv/bin/python -m aegis_lab.live_trial preflight \
  /tmp/aegis-operator-review-1/comparison-plan.json
PYTHONPATH=attack_lab/src .venv/bin/python -m aegis_lab.live_trial run \
  /tmp/aegis-operator-review-1/comparison-plan.json \
  --output-dir /tmp/aegis-live-operator-comparison-1 --approve-live-inference
```

Order is randomized with the plan's recorded seed; every target gets a fresh
provider. Failure states and unstarted targets remain visible. Missing or changing
reported identities prevent identity comparability. A shared reported fingerprint
does not establish identical weights, correctness or protection effectiveness.

Afterward, verify all available archives and export the three-way summary:

```sh
PYTHONPATH=attack_lab/src .venv/bin/python -m aegis_lab.live_trial verify \
  /tmp/aegis-live-operator-comparison-1
PYTHONPATH=attack_lab/src .venv/bin/python scripts/export-product-evidence.py \
  reconstruction_comparison /tmp/aegis-live-operator-comparison-1 \
  --output /tmp/aegis-operator-review-1/comparison-public.json
```

The prepared artifacts have distinct hashes and successful Ghidra exports
(151/151/154 functions). Baseline selected text differs from Shield, while Shield
and Shield+Mirage selected text is identical. Only that selected function enters
the request. Thus the experiment does not expose the decoy inventory and cannot
measure a Mirage distraction effect. Behavioral success and attack resistance
remain **not established** without separately authorized independent scoring.
