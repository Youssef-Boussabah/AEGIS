# Independent reconstruction benchmark

An optional offline tool, isolated to this directory. No Core, Shield, Mirage,
Lab, dashboard, release, authorization or storage contract is changed. Nothing
registers a backend, enables attack-lab gates, contacts a provider automatically,
or executes a candidate. The local formats below are benchmark formats only.

`benchmark.py` and the REA/receipt readers need Python 3.11+ standard library.
The native demo additionally needs Linux pidfds, matching installed LLVM **22**
tools (`/usr/bin/clang`, `opt`, `llvm-link`), a trusted Shield plugin and the
existing Mirage source. Ghidra/Nemotron/production-Lab import and live preparation
use the existing repository `.venv` and strict Lab parsers; they install nothing.
Real Ghidra analysis is optional and requires explicit `--analyze-owned`.

## Reproduce the measurements

From the repository root (choose a **new**, private scratch directory):

```sh
.venv/bin/python -B benchmarks/reconstruction/benchmark.py demo \
  --plugin /tmp/aegis-shield-build/AegisShield.so \
  --output-dir /tmp/aegis-reconstruction-reproduce \
  --samples 9 --iterations 2000000
.venv/bin/python -B benchmarks/reconstruction/benchmark.py verify \
  /tmp/aegis-reconstruction-reproduce/comparison.json
.venv/bin/python -B benchmarks/reconstruction/benchmark.py report \
  /tmp/aegis-reconstruction-reproduce/measurements.json \
  --output /tmp/aegis-reconstruction-reproduce/rechecked-results.md
```

The default checks both `recon_gate` and `recon_mix`. Add `--target recon_mix`
when preparing the existing production Lab pipeline, which evaluates **one**
function per trial. This selects 12 existing frozen cases without changing any
answers. Different selected-function sets require separate comparisons. Timing
still runs both functions per iteration, as recorded in the report.

The demo compiles only the pinned owned `fixtures/target.c` and `runner.c`, with
defined unsigned 32-bit arithmetic. It checks the predefined `oracle.json`
against a separate Python reference, then checks **each variant** against those
answers; a broken baseline cannot become the oracle. The cases cover wraparound,
zero, high bits, and both branch paths. The timing loop's final checksum is also
computed independently. Finite public cases do not prove equivalence and are
unsuitable as a hidden attack suite.

Each run snapshots the plugin and Mirage Python source into its own scratch
directory, hashes the actual tool executables, records the triple, flags, source
hashes, exact argv arrays, CPU, platform, date, warmups, order and raw timings.
The final compilation is `-O2`, with section GC and no build ID. Native timing
uses process completion pidfds rather than polling; it includes process startup.
Samples rotate and reverse variant order. The shared host is unpinned; small
differences are noisy observations, not performance guarantees.

The ELF64 little-endian reader measures final file size, `.text` size, defined
function symbol counts, selected symbol binding/visibility and dynamic exports,
and selected function body hashes. Stripped/missing target symbols give
`unavailable`, never a guessed function identity. Other binary formats are
explicitly unsupported. Mirage retention requires the exact reported names to
have nonempty executable function bodies in the final ELF. Shield's site counts
remain plugin claims. Different bytes are structural evidence requiring further
attribution; identical bytes provide no distinguishable retained change. Neither
case establishes reverse-engineering resistance.

The demo never accepts a candidate or a caller-supplied target source. `verify`,
`report`, `render` and evidence imports never execute artifacts. Subprocesses used
for the demo receive a minimal environment, bounded outputs, a deadline and
process-group cleanup. They inherit no credentials. Scratch directories are
owner-only; same-user concurrent tampering is outside this local trust model.

## Comparison and evidence rules

The complete local formats and trust boundaries are in [FORMATS.md](FORMATS.md).
`comparison.json` binds one baseline and one or more protected artifacts to exact
hashes and sizes, source/oracle hashes, common build conditions, identical target
sets, protection settings and permitted attacker capabilities. Shield+Mirage must
consume the compared Shield IR; seeds and Shield settings must agree. A combined
comparison therefore includes the intermediate Shield variant as well.

Records bind the comparison's canonical JSON SHA-256 and their own artifact ID
and digest, even if two variants happen to have identical binary bytes. File
hashes use exact bytes; record identities use sorted-key UTF-8 JSON with no spaces
and finite numbers. Duplicate JSON keys, unknown fields, symlinks, path escapes,
missing files, invalid types, different prompts/functions/settings and evidence
outside the comparison window are rejected. A comparison window is at most seven
days. Freshness timestamps are operator declarations, not attested clocks.

`verify --as-of TIMESTAMP` explicitly checks a historical archive at that UTC time;
it prints `retrospective`. `render` reproduces a recorded snapshot without
claiming a new measurement or filesystem verification. Use `report` to re-read
actual artifacts and verify imported records. Recorded files and build metadata
are unsigned consistency evidence; they do not prove origin or source-to-binary
provenance. The reviewed source and installed compiler/protectors remain trusted.

## Claude's Ghidra and REA handoff

Do not restart or inspect another analyst's active jobs. Use completed reports in
a separate handoff directory. Predeclare the same artifact hashes, target names,
Ghidra/REA executable/version/configuration hashes, model, prompt template, system
instructions, request parameters, workflow, budgets and access policy for all
variants. A `not_scheduled` measurement manifest cannot accept unrelated live
evidence unchanged. Create a separate, accurate comparison declaration before
inference; do not relabel or patch an old attack result to fit a new build.

For Ghidra, import the actual `aegis.lab.ghidra.v1` **worker report**, not just
decompiled C. The reader uses `aegis_lab.evidence.parse_ghidra_report`, checks
Ghidra's own executable digest, report binary size/hash, the launcher's declared
identity, all bound export settings, and exactly one match per selected function.
A timeout or failed decompilation remains an analysis observation, not a failed
behavioral attack. Ghidra's existing unsupported failure cases remain invalid.

REA has no assumed native schema here. Preserve its raw output byte-for-byte,
then create the small `aegis.reconstruction.rea-observation.v1` projection in
FORMATS.md, pointing to the raw file's exact hash. That projection is explicitly
operator supplied and unsigned. Numeric complexity/CFG counts stay structural.
The framework cannot prove an operator's projection accurately describes raw
REA output; a trusted reviewer must check it. No numeric score becomes resistance.

Create and verify a new sidecar (all referenced files must be under its directory):

```sh
.venv/bin/python -B benchmarks/reconstruction/evidence.py wrap \
  --comparison /tmp/comparison/comparison.json --artifact-id shield \
  --kind ghidra --source /tmp/handoff/shield-ghidra.json \
  --controls /tmp/handoff/actual-controls.json --recorded-at 2026-10-30T13:00:00Z \
  --output /tmp/handoff/shield.evidence.json
.venv/bin/python -B benchmarks/reconstruction/evidence.py verify \
  /tmp/handoff/shield.evidence.json --comparison /tmp/comparison/comparison.json
```

Use real observation times, not the example time. `wrap` verifies before writing;
it does not approve an attack. Shared tool declarations can include both Ghidra
and REA. Plain prompt bindings hold exact template/system/context/rendered files.
The template must contain exactly one `{{CONTEXT}}`; only the artifact digest and
ordered selected-function decompilations vary. For Ghidra/REA, those decompilations
are compared to the imported observations. This checks declared prompt inputs;
only a bound production archive additionally establishes which request was saved.

## Existing Nemotron research summaries and production archives

The `nemotron_summary` reader uses the current strict `ReconstructionEvidence` or
`ComparisonEvidence` models for `aegis.product.evidence.v2`. It preserves
synthetic/offline/external labels, original failure status, candidate hashes and
separate post-hoc parser status. The historical `mirage` comparison row maps to
`shield_mirage` **only after checking the exact final artifact hash**. Public
summaries omit target/prompt/settings details; supplied sidecars therefore remain
operator-declared comparability and never become behavioral evidence.

For full production request verification use `kind=lab_experiment`, source set to
the actual `live-results/VARIANT/experiment.json`, and the `aegis_lab` prompt
bindings emitted by `prepare_live.py`. This calls `verify_experiment` over the
private archive, rebuilds the actual production messages, checks the saved
request, trial/pair/artifact/report/manifest/workflow bindings, sampling and
context/token/spend limits, and derives the safe research summary. It records
actual **provider-reported** token counts and approved-price cost estimates,
separately from conservative reservations and unknown invoice costs. It does not
prove provider origin, model weights, billing, or candidate correctness.

Add one or more verified records to an actual archive:

```sh
.venv/bin/python -B benchmarks/reconstruction/benchmark.py report \
  /tmp/comparison/measurements.json \
  --evidence /tmp/handoff/baseline.evidence.json \
  --evidence /tmp/handoff/shield.evidence.json \
  --evidence /tmp/handoff/combined.evidence.json \
  --output /tmp/handoff/RESULTS.md --json-output /tmp/handoff/results.json
```

## Optional fresh NVIDIA preparation

The existing production inference/approval pipeline remains authoritative.
Preparation never creates a provider, reads a credential, grants an approval,
reserves usage, or performs inference. For a new owned single-function demo:

```sh
.venv/bin/python -B benchmarks/reconstruction/benchmark.py demo \
  --plugin /tmp/aegis-shield-build/AegisShield.so \
  --target recon_mix --output-dir /tmp/reconstruction-single
.venv/bin/python -B benchmarks/reconstruction/prepare_live.py \
  /tmp/reconstruction-single/measurements.json \
  --output-dir /tmp/reconstruction-nvidia-review \
  --ghidra-headless /home/youss/Applications/ghidra_12.1.4_PUBLIC/support/analyzeHeadless \
  --reports /tmp/completed/baseline.json /tmp/completed/shield.json /tmp/completed/combined.json
```

The supplied reports must match the exact binaries, installed Ghidra/exporter
identity and a common export configuration. The helper derives that configuration
from the completed baseline report and checks every variant against it.
Only if there are no matching active jobs, replace `--reports ...` with
`--analyze-owned` to run three new serial static analyses at lower process
priority (`*`, 64 functions, 20000 C chars, existing default timeouts). It never
executes those artifacts. Do not duplicate Claude's jobs.

The output contains a strict production `plan.DRAFT.json`, three deliberately
unapproved single-use approval drafts, exact private request-review bodies,
`controls.json`, benchmark comparison/measurements, prompt bindings and
`handoff.json` with exact runtime argv. Proposed maxima are **$0.10 per request,
$0.30 aggregate**, one attempt each, 8192 output tokens. Model/context/prices are
proposals: the live pipeline checks its current catalogue/account before POST.
This is a local proposal, not a shared-budget reservation or spending authority.

The operator's designated credential-enabled **Fish terminal** at the repository
root executes reviewed commands and centrally tracks the shared **$20 total**,
including prior usage. No agent-accessible ledger was supplied. Claude owns the
active baseline/Shield live requests; reuse those completed records instead of
launching overlapping trials. No credential belongs in this module, a prompt, an
approval, argv, a report, or agent-visible output.

The production pipeline requires per-request approval of exact content, current
validity/retention terms and the existing single-use reservation. The general
project budget authorization does not fill those artifact-specific approvals.
Only the operator should save reviewed `approval.json` files and a new
`plan.APPROVED.json` referencing all three; the helper never flips review booleans.
Run the exact `preflight_argv` then `run_argv` from `handoff.json` in that runtime,
preserving `.inference-uses/`. Do not retry or reuse a consumed approval. Verify
and import completed archives even when generation fails. This tool prepares
work; it cannot operate the operator's separate terminal.

## Behavioral outcomes

No validated candidate-isolation runtime is integrated here. Local behavioral
scoring is **unavailable**. Generated/untrusted source is never imported as Python,
compiled, linked, loaded, or executed, including through a host fallback.

The `behavioral_receipt` format can consume future outcomes from an independent
isolated evaluator. Require an exact candidate hash, artifact/target/comparison,
oracle and control bindings, compiler identity, containment-validation and runtime
attestation digests, and case observations. The caller must additionally supply
`--trust-receipt SHA256` obtained separately from a trusted reviewer who actually
verified the isolation and replay. A JSON `verified: true` is not accepted as
independence. Trusting an arbitrary local file's hash cannot establish that it
came from that reviewer. No real receipt is included in the recorded results.

The reader recomputes the finite-suite match/mismatch classification from case
outputs. Candidate rejection/crash/timeout is an `attack_failed` observation for
that one attempt. Infrastructure failures and unrun cases are `inconclusive`;
missing evidence stays absent. Even a trusted finite-suite match does not prove
general reconstruction, and failed attempts never become security guarantees.

## Regression tests

```sh
env AEGIS_RECONSTRUCTION_PLUGIN=/tmp/aegis-shield-build/AegisShield.so \
  .venv/bin/python -B -m unittest discover -s benchmarks/reconstruction/tests -v
```

Without that environment variable, the native suite is explicitly **not run**.
All parser fixtures are synthetic, clearly labeled, created in private temporary
directories, and never included as research evidence. Native tests build/run
only the pinned owned sources. They check final retention, fixed oracles,
repeat-build binary hashes and read-only archive reporting. The tests exercise
invalid/missing data, artifact/config/target/prompt mismatch, staleness, unsafe
paths, non-finite/duplicate-key JSON, unsupported claims, missing isolation,
independent-receipt trust, and Ghidra/Nemotron compatibility without provider calls.
