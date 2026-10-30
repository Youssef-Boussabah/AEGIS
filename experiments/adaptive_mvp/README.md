# Adaptive protection experiment

An experimental consumer of existing Core, Shield, Mirage and Lab code. It
registers no production backend and changes no production contract. All task
source changes stay in this directory; builds and private evidence go outside Git.

The working loop is **probe → production adapter → independent correctness →
final ELF inspection → measurement → selection → next probe**. Resistance is
**UNMEASURED** without separately verified behavioral evidence. There is no
numeric resistance score.

## Run and reproduce

Requires the repository `.venv`, Linux x86-64, matching Clang/LLVM 22 and an already
built Shield plugin. Lab preparation additionally requires Lab and Ghidra 12.1.4.
Nothing installs dependencies.

```sh
.venv/bin/python experiments/adaptive_mvp/controller.py \
  --plugin /tmp/aegis-shield-build/AegisShield.so \
  --output-dir /tmp/aegis-adaptive-run --samples 9
.venv/bin/python experiments/adaptive_mvp/verify.py \
  /tmp/aegis-adaptive-run/report.json
```

Use a **new** output directory. Exit 0 means a verified candidate was selected,
including when a budget stopped further probes. Exit 2 means refusal, experiment
failure, failed final verification or no eligible candidate. Always read
`stop_reason`: an earlier selectable artifact does not make an incomplete probe
successful.

The target is a byte-exact copy of the existing trusted
`protectors/mirage/tests/fixtures/signal.c`, pinned to SHA-256
`72c5204be63165e63311ea47456f2145410ed399f3bb44fc0007336707bd8f83`.
An independent Python u32 reference checks the million-input checksum. The
controller refuses edited source and accepts no arbitrary source, IR, native
executable or reconstruction input.

Runs capture the target, experiment/production sources, adapter schemas and
plugin under `inputs/`, plus tool hashes/versions, Python/dependency versions,
hardware, exact commands, raw samples, private logs and Core reports. Captured
inputs can reproduce the binaries independently of later source edits:

```sh
.venv/bin/python \
  /tmp/aegis-adaptive-run/inputs/repository/experiments/adaptive_mvp/controller.py \
  --plugin /tmp/aegis-adaptive-run/inputs/AegisShield.so \
  --output-dir /tmp/aegis-adaptive-reproduction --samples 9
```

The recorded host toolchain and dependencies are still required; this is not a
hermetic compiler distribution. Binary hashes reproduce on the tested host.
Timings and random Core job IDs can differ. Read-only verification rechecks
local hashes, ELF bytes, logged outputs, lineage, measurements and selection.
Unsigned local consistency cannot authenticate authorship or remeasure behavior.

## Feedback, selection and bounds

The first probe is Shield, seed 42, at most two sites. Final code observations
explain the next three-decoy Mirage probe. Subsequent probes reduce decoys to one
and Shield to one site, measuring again. A separately verified successful
reconstruction can trigger a six-decoy hypothesis, without claiming improved
resistance. Build failures take a bounded one-decoy fallback; configurations are
never repeated.

Every candidate starts from the same baseline input IR. `parent_candidate_id`
records the feedback/decision lineage, not repeated transformation of the previous
candidate. Core's per-job input hashes record the actual artifact derivation.

Defaults require correctness, completed measurements, observed final retention,
ELF size ≤1.10× baseline and paired median process wall time ≤3× baseline.
Eligible candidates rank by ELF size, measured time ratio, then candidate ID.
Identical binaries can have different noisy timings; a chosen configuration is
not evidence of a performance improvement. Baseline is only a comparator.

ELF64 inspection extracts nonempty executable function bytes. It compares
`signal_mix` against baseline and checks Mirage definitions/code and their absence
in baseline. Shield `NOT_OBSERVED` means target bytes matched baseline.
`MACHINE_CODE_CHANGED` is an observation, not proof of a retained arithmetic
identity. Neither establishes security.

Default budgets are four attempts, 180 seconds, 30 seconds per command, 100 native
launches, nine samples and one warmup. `--max-candidates` accepts 0–5. Attempts and
launches consume budget before starting; failed/incomplete probes cannot win.
In-progress lineage is saved before adapter invocation. Cleanup and verification
add operational overhead; this is not a real-time or aggregate CPU/memory quota.

Processes use argv arrays, private paths, a minimal environment, file-backed
bounded capture and process-group kill on timeout, interruption and exit. Core
still validates production protocol results and hashes outputs. No Lab execution
gate is enabled. The supervisor is **not** validated isolation for hostile or
model-generated programs. No generated reconstruction is compiled or executed.

## Separately verified attack evidence

Pass `--evidence-index /absolute/index.json`:

```json
{
  "schema_version": "aegis.adaptive.evidence-index.v1",
  "entries": [{
    "receipt": "receipt.json",
    "evidence": "evidence.json",
    "trusted_receipt_sha256": "<operator-pinned SHA-256 of exact receipt bytes>"
  }]
}
```

Paths are relative to the index; symlinks and escapes are refused. Receipt fields:

| Field | Meaning |
| --- | --- |
| `schema_version` | `aegis.adaptive.attack-receipt.v1` |
| `artifact_sha256` | Exact final ELF, not IR or another target |
| `evidence_sha256` | Exact separately verified evidence file hash |
| `attack_id` | Named attack/version |
| `protocol_sha256`, `suite_sha256` | Attack controls/budget and suite identities |
| `outcome` | `reconstruction_succeeded`, `reconstruction_failed`, `inconclusive`, `unscored` |
| `verification_kind` | `independent_behavioral`, `structural_only`, `unscored` |
| `runtime_attestation_sha256` | Required for either decisive outcome; otherwise nullable |
| `verifier`, `verified_at` | Separate verifier identity and timezone-aware timestamp |
| `limitations` | Nonempty actual limitations |

The pin trusts an **external attestation**; it is not a signature or independent
behavioral proof by this controller. A `verified: true` flag is not accepted.
The external verifier must actually check authorization, containment, runtime
integrity, scoring provenance, target binding and controls before issuing a
decisive receipt. A digest string does not perform those checks. Never pin a
synthetic test receipt as real evidence.

Conflicting/duplicate results for one target/attack/protocol/suite require external
reconciliation. Exact imported bytes/pins are archived. Unmatched target hashes
are explicit and cannot affect selection. A verified successful reconstruction
vetoes its candidate. A failed reconstruction is limited to its named attempt;
it is not a security guarantee or an ordered score. Unscored/inconclusive evidence
leaves resistance UNMEASURED. `--require-attack-evidence` refuses selection without
decisive evidence.

## Lab, REA and the operator runtime

Prepare fresh Ghidra evidence and exact **unapproved** production Lab drafts:

```sh
.venv/bin/python experiments/adaptive_mvp/lab_bridge.py prepare \
  /tmp/aegis-adaptive-run/report.json \
  --ghidra-headless /absolute/ghidra_12.1.4_PUBLIC/support/analyzeHeadless \
  --model nvidia/Nemotron-3_5-Lightning \
  --output-dir /tmp/aegis-adaptive-live-prepared
```

`preparation.json` contains exact bindings, draft hashes and production CLI
`preflight_argv`/`run_argv`. Preparation reads no credential, sends no request and
consumes no reservation. Duplicate ELF hashes share one request. The production
three-way runner correctly refuses this fixture's identical baseline/Shield pair;
the bridge preserves that refusal and prepares individual unique-artifact requests.
Selected-function prompts omit Mirage's decoy inventory, so they cannot measure
decoy target-selection effects.

Paid requests run in the operator's separate **Fish terminal** at the repository
root, with its already exported credential. The operator centrally coordinates
the **$20 total** cap and exact single-use approvals; no agent-accessible global
ledger exists. The operator reviews disclosure, retention, limits and dates,
saves fresh private `approval.json`, then runs recorded commands. Preserve
`.inference-uses/` after failures. Follow the production
[safeguards](../../attack_lab/docs/live-inference.md) and
[operator runbook](../../attack_lab/docs/operator-live-run.md).

Each proposed draft permits one request, 8192 completion tokens, context 1048576,
price caps 60000/240000 micro-USD per million input/output tokens and $0.10 total.
At those caps, conservative reservation is 64881 micro-USD ($0.064881) per request.
These are review bounds; production checks fresh account/catalogue data. Reported
token estimates, conservative reservations and actual billing remain separate.

Import a production generation archive without executing its candidate:

```sh
.venv/bin/python experiments/adaptive_mvp/lab_bridge.py import-generation \
  /absolute/fresh-live-run --output-dir /tmp/aegis-adaptive-import
.venv/bin/python experiments/adaptive_mvp/controller.py \
  --plugin /tmp/aegis-shield-build/AegisShield.so \
  --output-dir /tmp/aegis-adaptive-with-evidence \
  --evidence-index /tmp/aegis-adaptive-import/index.json
```

This calls production `aegis_lab.experiment.verify_experiment`, preserves actual
recorded usage/accounting and emits **only** `unscored`. Parser validity or failure
cannot become behavioral success or failure. Scoring still needs existing Core
gates/grants and independently validated isolation/integrity, followed by a
separate verifier issuing a decisive receipt. Current Lab v1 scoring does not
establish behavioral evidence; `aegis_lab.scoring verify` alone does not remove
those limitations.

Direct REA execution is **not implemented**. REA can use the same receipt after
independent verification binds final-artifact hash, exact model/tool/request/budget
protocol, candidate digest, suite, runtime, outcome and limitations. Evidence for
another program remains context and cannot score these candidates.

## Tests

```sh
AEGIS_ADAPTIVE_PLUGIN=/tmp/aegis-shield-build/AegisShield.so \
AEGIS_GHIDRA_HEADLESS=/absolute/ghidra_12.1.4_PUBLIC/support/analyzeHeadless \
  .venv/bin/python -m pytest experiments/adaptive_mvp/tests -q
```

Missing native/Ghidra prerequisites fail explicitly. Tests include real adapters,
ELF-tool cross-checks, captured-source reproduction, real Ghidra, non-executing
Lab generation doubles, evidence tampering, failures and exhausted budgets.
Synthetic fixtures are labeled and are never security evidence.
See [RESULTS.md](RESULTS.md) for actual commands, measurements and limitations.
