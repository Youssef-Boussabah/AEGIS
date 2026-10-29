# Role B integration handoff — 29 October 2026

The existing scoring/reconstruction implementation is preserved. Role B now has
private Core execution archives, corrected cgroup accounting, strict dependency
profiles, an offline-tested Nebius transport, controlled iterative reconstruction,
paired generation, and a working retained-decoy Mirage mechanism. No generated
candidate was compiled or executed. No live inference, VM boot, package installation,
commit, push, merge or branch change occurred.

## Reproduce

Use the existing repository `.venv` (Python 3.11+, Pydantic 2, pytest). For Phase 4,
use Role A's execution-contract Core, not an older `aegis-core` with the same package
version. The optional `attack_lab[scoring]` dependency declares the package; the
strict profile checks that the required modules actually exist.

```sh
export PYTHONPATH="/home/youss/Projects/aegis-core-lab-execution/core/src:$PWD/attack_lab/src:$PWD/protectors/mirage/src"
# Offline profile: optional Core/Ghidra tests may be NOT RUN; skips are labeled.
.venv/bin/python -m pytest attack_lab/tests --lab-profile offline -q
# Integration profile: missing Core/Ghidra/compiler/nm or ANY skip fails the run.
AEGIS_GHIDRA_HEADLESS="$HOME/Applications/ghidra_12.1.4_PUBLIC/support/analyzeHeadless" \
  .venv/bin/python -m pytest attack_lab/tests --lab-profile integration -q
.venv/bin/python -m pytest protectors/mirage/tests -q
```

Strict integration needs permission for a trusted Unix-socket fixture and Ghidra's
local subprocesses. It does not need model credentials or candidate execution.
Tests inject Core's non-executing scripted runtime. The explicit real-Ghidra timeout
case can legitimately skip on faster hosts; strict integration then fails instead
of silently counting that case as passed.

```sh
PYTHONPATH=attack_lab/src:protectors/mirage/src .venv/bin/python attack_lab/scripts/role_b_demo.py \
  --output-dir /tmp/aegis-role-b-demo-reproduction \
  --ghidra-headless "$HOME/Applications/ghidra_12.1.4_PUBLIC/support/analyzeHeadless" \
  --shield-plugin /tmp/aegis-shield-build/AegisShield.so --authorized-owned-fixture
```

Requires an existing matching LLVM 22 Shield build and Ghidra 12.1.4. Every output
directory must be new. This runs only the checked-in trusted `signal.c` fixture.
For one preconfigured target with existing trial manifest, real Ghidra report,
matching binary and a scripted response file:

```sh
PYTHONPATH=attack_lab/src .venv/bin/python -m aegis_lab.experiment \
  TRIAL.json GHIDRA.json TARGET.elf --reply FAKE_REPLY.json --steps 4 --output-dir /tmp/controlled-trial
```

`FAKE_REPLY.json` is either the existing `aegis.lab.candidate.v1` envelope or a
controlled action. The allowlist contains only `inspect_target`; revisions use
`{"action":"revise_candidate","source":"...","analysis":"..."}` and finish uses
`{"action":"finish"}`. The Python provider factory can script different replies
per step (see the demo). Steps, requests, context bytes, tool calls, tokens and wall
time are bounded; exhausted budgets and provider/refusal/infrastructure errors are
separate generation outcomes. No compiler, runtime, file access, shell, network,
repository retrieval, hidden test, reference implementation or oracle tool exists.

## Inputs, records and trust

The engine checks the authorized artifact's SHA-256 before creating a provider;
it reuses existing strict manifest/Ghidra binding and prompt construction. The
prompt contains only the allowlisted task and bound decompilation. Private files,
original source, hidden-suite contents and expected outputs are never prompt
inputs. Source/build/auth/scorer metadata stays outside the prompt.

`experiment.json` (`aegis.lab.controlled-experiment.v1`) records the model,
provider identity, configuration, per-step latency, provider usage when supplied,
conservative token reservations, candidate references and pending scoring. Exact
request/response bodies, analysis text, candidate revisions, the binary, manifest
and Ghidra report live in `private-evidence/<sha256>`. Directories are 0700, files
0600. No authorization headers/API keys enter the archive. Oversized bodies are
rejected rather than retained. `aegis_lab.experiment.verify_experiment(Path(...))`
reloads hashes, input bindings, response provenance and candidate linkage offline;
this is an audit, not a replay falsely attributed to a live model.

Paired runs reuse existing `prepare_pair` validation: same objective, model,
sampling configuration, access and equal budgets; fresh providers and seeded
order. Both reported model ID and fingerprint must match to mark reported identity
comparable. `controlled-pair.json` references both records; failures never become
protection evidence. All generated candidates remain behaviorally unscored.
The established one-shot record format remains compatible with the existing
Phase 4 scorer. The demonstration's pending suite/scorer placeholders must be
replaced with actual declared scoring inputs before a new experiment is prepared;
the placeholder-bound demo records cannot be scored as-is.

Scoring retains its existing v1 JSON interfaces. Full canonical Core records are
also available as `score.private_core_records` and paired scoring publishes them
in `<variant>-core-records/<sha256>.json`, verified on reload. Direct API callers
must archive that property privately when saving a standalone score. Archives may
contain hidden case arguments and observed bytes; expected answers and evaluator
state are never copied into them. Earlier scores with references but no archives
fail the new strict archive verification and must not be treated as full evidence.

Granted limits, enforced cgroup/VM limits and host accounting remain separate.
`memory.peak > memory.max` is allowed; nonnegative strict accounting types and all
other enforcement checks remain. Guest outputs are observations, not independently
verified truth. A guest-held HMAC key cannot prove guest integrity. The current
scorer therefore never establishes independently verified behavioral success.

## Nebius and REA

Verified the endpoint and authentication against the official [Nebius quickstart](https://docs.tokenfactory.nebius.com/quickstart)
and [OpenAI-compatible API documentation](https://api.tokenfactory.nebius.com/docs):
`POST https://api.tokenfactory.nebius.com/v1/chat/completions`, Bearer API key from
`NEBIUS_API_KEY`, configurable model and chat messages. The existing conservative
completion parser is preserved. No live endpoint/schema round-trip was performed.
The transport handles bounded responses, typed HTTP errors, malformed usage,
timeouts and rate limits. Only provably not-submitted failures can be retried by
the existing one-shot runner; an answered or uncertain POST is never automatically
repeated. Exact bodies can be privately retained through `evidence_sink`.

`NebiusProvider` defaults to refusing requests without `allow_live=True`. Public
Lab entry points remain fail-closed even with disclosure approval. Before live use:
operator approval for the exact artifacts/model/spending, scoped disclosure approval,
a verified model token bound and a hard transport deadline are still required.
The existing public live gate also retains its Core-authorization blocker. Merely
setting an environment variable does not enable live inference. Offline cost is
exactly zero; provider usage is reported or unknown, never invented. No prices or
supported model/version guarantees are guessed from a convenience default ID.

An actual [REA project](https://github.com/morluto/rea) documents MCP and Ghidra
support. Neither `rea` nor `rea-agents` is installed here; no package was installed
and no external REA runtime was audited or invoked. The delivered optional workflow
is explicitly **REA-style controlled iterative reconstruction**, not REA itself.
Its private transcripts contain model-returned text only, not claimed access to
unexposed internal model reasoning.

## Evidence and measurements

Final private demo: `/tmp/aegis-role-b-delivery-demo/analysis-comparison.json`.
It includes commands, hardware/date, hashes, all samples, actual Ghidra inventories,
paired generation records and no-decoy control. Its `baseline-vs-shield` and
`shield-vs-mirage` directories each include compatible one-shot and iterative pairs.
All four iterative trials generated parsed candidates; behavioral scoring is pending.

Measured 2026-10-29 on Intel Core Ultra 9 185H, Linux 7.2.3-1-cachyos x86-64,
Clang/LLVM 22.1.8, Ghidra 12.1.4. Nine timed processes plus warmup per variant,
one million deterministic fixture inputs per process:

| Final artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| baseline | 15944 | `c592942a07310794ae523d1506695a09be499578428861cf67fa5ac8ec68b860` |
| Shield | 15944 | `c592942a07310794ae523d1506695a09be499578428861cf67fa5ac8ec68b860` |
| Shield+Mirage | 16120 | `02ade37bc9648325461c7a4d4b20bbc95db16932841f5676d6b887fa4dd42f37` |

Three Mirage functions survive O2 + linker GC and are present in real Ghidra
exports; disabled IR is byte-identical to input. All fixture output digests match.
Shield's two IR changes optimize away in this fixture. Mirage adds 176 executable
bytes. Final-run median process times were 4.845/4.807/5.280 ms (baseline/Shield/Mirage),
including process startup and scheduling; do not infer a stable slowdown from nine
samples. A separate repeat varied, as expected for such short process measurements.

ImageLab: `/tmp/aegis-role-b-imagelab`, external input
`/tmp/aegis-role-b-imagelab-mirage/module.ll`. All three decoys remain in
`external/imagelab-cli`; 14/14 CTests passed. Exact benchmark command and reproduction
are in [Mirage README](../../protectors/mirage/README.md). Private measurement file:
`/tmp/aegis-role-b-imagelab-measurements.json`, 256x256, seed 42, four rounds,
five samples, one warmup, two repeats. Outputs match. Kernel-object code grows
1482→1617 bytes; observed external/Shield timing ratios were 1.010 tone, 0.992 color,
1.040 enhance on this host in powersave governor mode. No extrapolation to other
inputs, platforms, compiler flags or seeds is justified.

These results establish static effects and sampled correctness only. Fixed-target
reconstruction prompts do not expose decoy inventory; AI target selection, real
model candidate quality and attack resistance are **not measured**.

## Validation and dependencies

Final strict Lab suite: **1901 passed, zero failures, zero skips**, 161.22 seconds,
log `/tmp/aegis-role-b-integration.log`. Mirage: **11 passed**, 0.78 seconds,
log `/tmp/aegis-role-b-mirage-tests.log`. ImageLab: **14/14 CTests passed**, 4.12
seconds, log `/tmp/aegis-role-b-imagelab-tests.log`. No warnings were emitted.
All four retained iterative experiment records passed independent reload verification.
The initial baseline was 1847 passed / 23 NOT RUN under the restricted offline
profile, including one sandbox-denied Unix-socket case. Final strict validation
used the authorized unrestricted test environment and exercised that case.

Live inference, third-party REA execution, VM containment tests and execution of
generated candidates were **not run**, per approval/runtime/dependency boundaries.
Separate Core/API/CLI/Shield suites were not rerun: their implementations were
read-only and unchanged; the complete Lab suite exercises the imported Core
contract through its scripted test double, and ImageLab tests real LLVM artifacts.

Core snapshot: `/tmp/aegis-role-b-core-snapshot/src`, copied read-only from Role A's
uncommitted worktree at HEAD `597f7472c361f910b5e9acfcb37ed441c7bb7e96`; HEAD alone
is insufficient to reproduce it. Full source digest inventory:
`/tmp/aegis-role-b-core-snapshot/source-digests.json`, SHA-256
`e411d81710132553473c16c01d985c0322187e3e155c020781481066c077d54c`.
All snapshot Python files still matched the owner's worktree at delivery validation.

Role A dependency: merge the matching execution-contract Core before Phase 4.
The existing record interface is sufficient; no additional Core record API is
required for private archives. Owner-delivered containment validation, runtime
approval and explicit execution authorization remain required for real scoring.
No Core/VM changes or ADR 0004 approval are part of this delivery.

Shared root documentation was intentionally not edited under the explicit Role B
scope restriction. Role A must update `ARCHITECTURE.md` sections 1/2/9 at integration:
Lab consumes Core execution sessions (still disabled), retains private Core records,
provides controlled offline reconstruction; Mirage is a standalone LLVM 22 ELF
side-module transformer with no established security property. Shared APIs, Core
storage, protocol and authorization gates are unchanged.

## Files and suggested commit groups

No commits were made. Suggested review groups:

1. **Scoring stabilization** — changed existing uncommitted Phase 4 files:
   `attack_lab/src/aegis_lab/{scoring_worker,core_execution,behavior_score,scoring}.py`,
   `attack_lab/tests/{test_behavior_score,test_scoring,test_scoring_policy}.py`,
   `attack_lab/docs/phase4-isolation-proposal.md`; new `attack_lab/tests/conftest.py`,
   `attack_lab/tests/test_profiles.py`; updated `attack_lab/pyproject.toml`.
2. **Provider and controlled experiments** — updated
   `attack_lab/src/aegis_lab/{provider,fake_provider}.py`,
   `attack_lab/tests/{test_provider,test_reconstruction}.py`; new
   `attack_lab/src/aegis_lab/{experiment,private_evidence}.py`,
   `attack_lab/tests/test_experiment.py`, `attack_lab/scripts/role_b_demo.py`.
3. **Mirage and delivery documentation** — updated `protectors/mirage/README.md`,
   `attack_lab/README.md`; new `protectors/mirage/pyproject.toml`,
   `protectors/mirage/src/aegis_mirage/{__init__,__main__,transform}.py`,
   `protectors/mirage/tests/test_transform.py`,
   `protectors/mirage/tests/fixtures/signal.c`, and this handoff file.

Claude's other pre-existing uncommitted files were preserved unchanged:
`attack_lab/src/aegis_lab/{c_abi,hidden_suite,scoring_policy}.py`,
`attack_lab/tests/{scoring_fixtures,test_c_abi,test_hidden_suite}.py`.
Include them in the appropriate Phase 4 review group. Generated evidence stays
private under `/tmp`; no private reports or benchmark JSON were added to Git.
