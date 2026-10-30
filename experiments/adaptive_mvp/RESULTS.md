# Adaptive MVP — executed results, 30 October 2026

The controller completed a real bounded feedback loop through the existing
production `llvm-shield` and `llvm-shield-mirage` adapters and Core orchestrator.
It selected a verified single-decoy candidate using measured size and process
wall time. **Resistance is UNMEASURED. No security improvement is established.**

All source changes are under `experiments/adaptive_mvp/`. No production Shield,
Mirage, Lab, Core, API or dashboard source was modified by this task. No package
installation, commit, push or publication was performed. No model-generated
native code was compiled or executed.

## Reproducible final experiment

Run from `/home/youss/Projects/aegis`:

```sh
.venv/bin/python experiments/adaptive_mvp/controller.py \
  --output-dir /tmp/aegis-adaptive-final \
  --plugin /tmp/aegis-shield-build/AegisShield.so --samples 9

.venv/bin/python experiments/adaptive_mvp/verify.py \
  /tmp/aegis-adaptive-final/report.json \
  --expected-sha256 fda9703194f08d69b71d65aad83fc6c101165a45f66bc92f31f4a05d6d7e1a67
```

Use new output paths for reproduction. The immutable private run is
`/tmp/aegis-adaptive-final/`; final report SHA-256 is
`fda9703194f08d69b71d65aad83fc6c101165a45f66bc92f31f4a05d6d7e1a67`.
Independent read-only verification passed **269 artifact/log/source hash checks**,
recomputed final ELF observations and replayed decisions/selection.

Conditions: 2026-10-30, experiment started 12:38:05 UTC / 08:38:05 Toronto;
Intel Core Ultra 9 185H; Linux 7.2.3-1-cachyos x86-64, glibc 2.44;
Python 3.14.7; Clang/LLVM 22.1.8; existing Shield plugin SHA-256
`ed3002eef080e2b178d33d294a0497d5126d0c395b6cb6733ecad6f8a1d2b214`.
The source is the exact trusted, AEGIS-owned Mirage `signal.c` fixture, copied
without modification and pinned to
`72c5204be63165e63311ea47456f2145410ed399f3bb44fc0007336707bd8f83`.

Build: `clang -O1 -g0 -S -emit-llvm target.c`; production protection adapter;
then `clang -O2 -g0 -ffunction-sections -fdata-sections -Wl,--gc-sections
-Wl,--build-id=none`. Exact argv, tool hashes, dependency source copies, input
IR, plugin, Core reports, all samples and private logs are in the run directory.
The captured-source reproduction regression rebuilt identical final hashes.
The host toolchain/dependencies remain prerequisites; this is not hermetic.

One warmup and nine samples were taken for each candidate, with alternating
baseline/candidate order and nine fresh paired baseline controls. Each native
launch processes one million deterministic input tuples; an independent Python
unsigned-32 reference expects `bf283ea0\n`. All **86 native launches** passed
their checksum checks. This is finite, aggregated correctness evidence, not an
equivalence proof; the 32-bit checksum can collide.

| Candidate | Actual configuration, seed 42 | ELF bytes | Median wall ms | Paired time ratio | Final observation | Decision |
| --- | --- | ---: | ---: | ---: | --- | --- |
| baseline | No protection | 15864 | 4.988670 | comparator | Reference bytes | Excluded from protected selection |
| c001 | Shield, max-sites 2 | 15864 | 5.141961 | 0.995986 | Target/binary equal baseline; no decoys | Rejected: no final transformation observed |
| c002 | Shield 2 + Mirage 3 | 16032 | 5.259673 | 1.007529 | Three decoy code definitions retained | First eligible incumbent |
| c003 | Shield 2 + Mirage 1 | 15920 | 6.173724 | 1.077136 | One decoy retained | Smaller incumbent |
| c004 | Shield 1 + Mirage 1 | 15920 | 5.266082 | 1.022202 | One decoy; identical final ELF to c003 | Selected by declared time tie-break |

Process wall times include startup, supervision, private log I/O, scheduling and
frequency noise. The shared host was unpinned and other engineering work was
running. **c003 and c004 are the same binary**: their timing difference is not
evidence that changing the site budget improved performance. These observations
apply only to this target, compiler, seed, host and samples.

Final ELF SHA-256 values:

| Artifacts | SHA-256 |
| --- | --- |
| baseline, c001 | `237480ee41d33496db3aa68e9e8bafe3411e88c72727a833266accdcfbc1e424` |
| c002 | `edc04a6d8e3af803c1c0db311fdcf0b4c6de801078273617800a23bca1d91574` |
| c003, c004 | `13c449c061c38049818b42c90df1b279a822365d18f898b43be202f6a27f0f7c` |

The selected ELF is `/tmp/aegis-adaptive-final/candidates/c004/target.elf`.
It is 56 bytes larger than baseline and 112 bytes smaller than the three-decoy
candidate. Its one retained decoy has 45 executable bytes. Independent test
cross-checks used `llvm-nm` and `llvm-objdump` on the actual linked artifacts.
Shield's target bytes matched baseline for **all** candidates. Reported IR
expansions were recorded as adapter claims, never as retained security evidence.

## What the autonomous loop actually did

1. Checked the fixed owned source and snapshotted inputs/dependencies.
2. Built baseline IR/ELF and independently checked its million-input checksum.
3. Executed four production adapter jobs, built their final native artifacts,
   independently checked correctness, hashed outputs, inspected final function
   bytes/retained decoys and measured paired process timings.
4. Rejected c001 after observing its final bytes matched baseline. This measured
   outcome caused the three-decoy probe. The next cost-reduction probes reduced
   decoys and Shield sites; each decision names its observed predecessor and
   incumbent in the structured report. All candidates derive from the same
   original input IR; parent IDs are feedback lineage, not repeated protection.
5. Applied declared constraints: correctness, completed measurement, observed
   retention, size ≤1.10× baseline and time ≤3× paired baseline. Ranked feasible
   artifacts by bytes, then measured time, then ID.
6. Stopped at `FEEDBACK_PLAN_COMPLETE` and verified the persisted result. It
   neither looped indefinitely nor fabricated an attack score.

Budgets were four attempts, 180 seconds, 30 seconds per command, 100 native
launches and nine samples. The final persisted usage was 86 native launches and
2.680 seconds including final report handling. Budget exhaustion and failures
are separately exercised: incomplete candidates fail, prior verified incumbents
remain available, and absence of a qualifying candidate produces no selection.

## What remains unmeasured

No adversarial reconstruction was behaviorally scored for these final ELF hashes.
No attack was run before/after protection by this controller. The demonstrated
feedback is correctness/retention/cost feedback. Attack-evidence ingestion and its
selection veto are implemented and regression tested with explicitly synthetic
receipts, not demonstrated with real decisive behavioral receipts.

The six-decoy response to verified reconstruction success is a bounded policy
hypothesis tested using synthetic evidence, not a measured resistance improvement.
General reverse-engineering resistance, Mirage steering, malicious-code isolation,
large-program behavior, direct REA execution, release/publishing and a verified
adversarial autonomous improvement cycle are **not established or not implemented**.

## Fresh Lab/NVIDIA handoff and connection

Fresh static preparation was actually executed through production Ghidra/Lab:

```sh
.venv/bin/python experiments/adaptive_mvp/lab_bridge.py prepare \
  /tmp/aegis-adaptive-lab-input/report.json \
  --output-dir /tmp/aegis-adaptive-live-prepared \
  --ghidra-headless /home/youss/Applications/ghidra_12.1.4_PUBLIC/support/analyzeHeadless \
  --model nvidia/Nemotron-3_5-Lightning
```

That earlier retained run has the same final ELF hashes above. Its report hash
is `0536299da1ab96d8960778c108aee7396120600dc348fec206952fa988d87e17`.
`/tmp/aegis-adaptive-live-prepared/preparation.json` contains three distinct
artifact requests, exact production CLI preflight/run argv, private request
reviews and invalid single-use approval drafts. Baseline/c001 and c003/c004 are
deduplicated by ELF hash. Real Ghidra exported 17/20/18 functions respectively.
The selected-function decompilation hash was identical for all three:
`526060832b49372d1e4ae4d35cd771f55ea09dd33efad43185d161d3331b9b25`.
Its target-only model prompt does not disclose the decoy inventory, so a Mirage
steering effect cannot be inferred from these requests.

The operator resolved the designated runtime: their separate Fish terminal at
`/home/youss/Projects/aegis`, with the credential already exported. The operator
centrally owns the **$20 total** spending ceiling and single-use approvals; there
is no agent-accessible shared ledger. Claude owns current baseline/Shield live
evaluation, and the independent evaluation engineer coordinates a more informative
fresh three-way benchmark. These signal requests were explicitly deferred to
avoid duplication. **This task made zero NVIDIA/API requests, consumed zero
inference approvals/reservations and incurred $0 in new inference cost.** Shared
account totals and actual billing are operator-managed and are not asserted here.

If the operator later chooses these exact requests, each draft proposes one
8192-completion-token request, at most $0.10; three total caps are $0.30. At
the proposed context and price ceilings, reservations are $0.064881 each /
$0.194643 aggregate. Those are conservative bounds, not invoices. The existing
runner checks fresh availability/context/prices and consumes each independently
reviewed approval once. Agents do not turn the drafts into approvals.

The exact connection is implemented in `lab_bridge.py import-generation`: it
calls production `aegis_lab.experiment.verify_experiment`, binds the actual final
artifact, archives the generation record, preserves reported tokens/cost
estimates/reservations, and emits an **unscored** receipt/index usable by the
controller's `--evidence-index`. Real and fake unexecuted generations both remain
UNMEASURED. This path was tested with production archive validation and an
explicit FakeOffline test provider; no fake record is evidence of inference.

For decisive results, independently validate Lab/REA behavioral evidence under
the existing Core gates/grant and validated containment/runtime integrity. Issue
the exact receipt described in [README.md](README.md): final ELF hash, evidence
hash, named attack, protocol/suite hashes, explicit outcome, runtime attestation,
verifier/date/limitations and an operator-pinned receipt digest. Only then can
the controller veto a successful reconstruction or satisfy its optional measured
attack constraint. Infrastructure refusal, test doubles, Ghidra complexity,
parser validity and generated text cannot be relabeled as success/failure.
Evidence from Claude's ImageLab or `benchmarks/reconstruction` targets may support
product integration reporting but cannot score these different ELF hashes.

## Validation actually run

| Check | Result |
| --- | --- |
| `.venv/bin/python -m pytest experiments/adaptive_mvp/tests -q` | **96 passed**, 37.65 s; no skips/warnings; real LLVM/Core/adapters and Ghidra included |
| Complete Core/API/CLI/real adapter suite below, outside sandbox | **675 passed**, 37.58 s; **1** Starlette/httpx deprecation warning; no skips |
| `ctest --test-dir /tmp/aegis-shield-build --output-on-failure` | **1/1 passed**, 1.18 s |
| `ctest --test-dir /tmp/aegis-imagelab-build --output-on-failure` | **12/12 passed**, 3.01 s; this existing build has no optional external variant |
| Final read-only report verification, pinned digest above | **Passed**, 269 hash checks and selection/lineage/ELF checks |
| `.venv/bin/python -m compileall -q experiments/adaptive_mvp` | **Passed** |
| Paid NVIDIA signal requests / behavioral scoring / direct REA | **Not run**: coordinated operator-owned requests deferred; no validated candidate execution/scoring used here |

Complete Python command:

```sh
.venv/bin/python -m pytest core/tests platform/api/tests platform/cli/tests \
  protectors/llvm/adapter/tests -q \
  --shield-plugin /tmp/aegis-shield-build/AegisShield.so \
  --shield-opt /usr/bin/opt --shield-clang /usr/bin/clang \
  --shield-llvm-link /usr/bin/llvm-link --maxfail=1
```

Logs: `/tmp/aegis-adaptive-validation/focused.log`, `python-complete.log`, and
`final-verification.json`. Full Lab, dashboard, provenance and Sentinel suites
were not rerun for this isolated experiment; production modules were not edited.
An initial sandboxed broad Python attempt reported failures and was interrupted
(exit 130; no final counts). The specified suites subsequently passed outside
the sandbox without production edits. A development test run had 3 failures,
74 passes and 11 setup errors: the local supervisor's inherited 64 MiB hard file
limit prevented production adapters setting their 128 MiB limit. The experiment
supervisor now matches that limit; final focused/native checks passed. No existing
test was deleted, skipped or weakened.

## Files added

- `experiments/adaptive_mvp/__init__.py`
- `experiments/adaptive_mvp/controller.py`
- `experiments/adaptive_mvp/evidence.py`
- `experiments/adaptive_mvp/policy.py`
- `experiments/adaptive_mvp/verify.py`
- `experiments/adaptive_mvp/lab_bridge.py`
- `experiments/adaptive_mvp/target/signal.c` (unchanged copy of the existing owned fixture)
- `experiments/adaptive_mvp/tests/test_controller.py`
- `experiments/adaptive_mvp/tests/test_evidence.py`
- `experiments/adaptive_mvp/tests/test_policy.py`
- `experiments/adaptive_mvp/tests/test_native.py`
- `experiments/adaptive_mvp/tests/test_lab_bridge.py`
- `experiments/adaptive_mvp/README.md`
- `experiments/adaptive_mvp/RESULTS.md`
