# Core execution and native Shield review — 2026-10-29

The existing implementation was repaired in place on `feat/core-lab-execution`,
based on `597f747`. All prior uncommitted work was preserved. Nothing was
committed, pushed, merged, rebased, reset, cleaned or switched. Role B and
dashboard files were not edited. This is a review of an unmerged working tree,
not a claim that integration has been completed.

Core authorization, persistent budgets and audit record interfaces remain in
place. All seven reported issues were confirmed in the starting implementation
and addressed. Normal configured candidate execution remains disabled:
`ADR_0004_ACCEPTED = False`. The implementation is fixture-tested; **no real VM,
guest image build/download, package installation, host configuration change,
provider call or AI-generated candidate execution occurred**.

## Repairs and their verification

| Confirmed issue | Change | Regression evidence |
| --- | --- | --- |
| Supervisor stopped after `waitpid` with unread pipe data | Kill descendants after leader exit; drain both streams to EOF under the wall deadline and cap+1 bound | Scripted child/waitpid with real pipes and forced short reads; overflow detected after reap; pipe failures kill/reap |
| Aggregate CPU checked only after execution | Poll aggregate job `cpu.stat` every 10 ms; kill at budget; missing/invalid accounting fails closed | Live scripted child killed by increasing aggregate usage before wall deadline; accounting failure cleans up; no host candidate executed |
| Cleanup lost tracking when termination/verification failed | Retain process/scope references, directories and asset descriptors; stop further runs; retry cleanup on runtime/session `close()` | Stuck fake VM, verification exception and recovery; existing directory preserved; successful cleanup remains idempotent |
| Support sources and unit selection were recorded but not authorized | Per-candidate `compilation_bundle_sha256` binds all exact file names/digests and ordered units before reservation | File changes/additions/removal/rename, unit selection/order, no budget consumed on refusal; no test-double exception |
| Minimal guest Python omitted required stdlib components | Request full Debian `python3` and its dependency closure | Package-spec regression; actual imports/boot still require built-image C0 validation |
| Mutable host paths could change the launched VMM/image | Hash copies of all four pinned assets and seal anonymous files; launch held `/proc/<Core pid>/fd` aliases | Actual memfd sealing, rejected writes, path replacement and in-place modification with restored mtime, mutation during copy, descriptor release |
| Guest success could contradict host OOM/deadline observations | Check host OOM/deadline before and after parsing RESULT; host observation wins; discard claimed binary | Fake guest returns success/binary while host cgroup records OOM; existing host timeout tests |

Request-owned sources and limits are copied/revalidated. Invalid mutated limits
and wrong argument containers fail with `INVALID_REQUEST` before reserving a
stage. Compiler flags, ceilings, all three authorization gates, same-session
binary binding and persistent reservation semantics remain enforced.

CPU polling is an implemented control with possible scheduling/polling
overshoot, not a precise zero-overshoot quota. The guest's CPU/accounting claims
are not authoritative evidence of isolation. A compromised guest kernel can
forge guest reports; the host retains its own scope limits and wall deadline.

Sealed asset copies add up to **2 GiB of host memory outside VM scopes**, held
until verified close. The plan reports that separately. Actual smoke assets sum
to 359,112,512 bytes (about 342.5 MiB). No real asset copies were created during
the static prerequisite review. Host systemd and OS libraries remain trusted
dependencies. The new `host_asset_binding=sealed-memfd-v1` report identity
invalidates older reports. Namespace access, dynamic loading and real boot from
these aliases remain unvalidated; failures must surface as infrastructure errors.

## Exact Python results

This checkout has no `.venv`. The existing sibling environment was used without
installing or changing packages. Explicit `PYTHONPATH` selects this checkout's
source, not the sibling Core implementation. Python is 3.14.7.

Baseline:

```sh
PYTHONPATH=core/src:platform/api/src:platform/cli/src:provenance/src:sentinel/src \
  /home/youss/Projects/aegis/.venv/bin/python -m pytest -q
```

**489 passed, 1 warning, 15.27 s.** Initial tool-sandbox attempts stalled in
socket tests and were interrupted (exit 130); they were not counted as passes.
The baseline and complete final suite ran with approved execution outside that
socket-restricted tool sandbox. This changed no candidate isolation controls.

Final:

```sh
PYTHONPATH=core/src:platform/api/src:platform/cli/src:provenance/src:sentinel/src \
  /home/youss/Projects/aegis/.venv/bin/python -m pytest \
  core/tests platform/api/tests platform/cli/tests \
  protectors/llvm/adapter/tests provenance/tests sentinel/tests \
  --shield-plugin /tmp/aegis-agent1-review/shield/AegisShield.so \
  --junitxml=/tmp/aegis-agent1-review/final-tests.xml -q
```

**612 passed, 1 warning, 25.13 s; no skipped tests.** Counts:

| Suite | Passed |
| --- | ---: |
| Core (including grant, ledger, guest, protocol and containment fixtures) | 447 |
| API | 17 |
| CLI | 18 |
| Real LLVM adapter | 94 |
| Provenance | 25 |
| Sentinel | 11 |

The sole warning is the existing `StarletteDeprecationWarning` about the
FastAPI test client using httpx. No dependencies were installed to suppress it.
The native adapter tests use the freshly built real Shield plugin; the
isolation tests use trusted fixtures and fake runtimes, and do not demonstrate
real containment. Final log and JUnit are under `/tmp/aegis-agent1-review/`.

## Merged Role B compatibility and required migration

The locally cached `origin/dev/integration` is `470f96a` (merged Role B). It was
inspected with `git show` and exported to `/tmp/aegis-agent1-review/merged/`
with `git archive`; this checkout was not merged or updated. This verifies that
cached merged revision, not a fresh network fetch of GitHub's current state.

The worker already accepts Firecracker, validates host enforcement observations,
checks grant/record/source/unit identities, uses Core's persistent ledger, and
retains canonical Core records as private evidence with public digest references.
Those worker/record interfaces were preserved.

Its current grant fixture/issuer omits support-file binding. One unchanged
representative test,
`test_behavior_score.py::test_matching_candidate_satisfies_the_criterion`, was
run and **failed (1 failed, 0.74 s)** because Core safely refused the multi-file
request (`compilation_bundle_required`), returning an incomplete scoring record.
The unchanged merged scoring suites are therefore **not claimed compatible or
green** with their existing grants.

The supplemental `/tmp/aegis-agent1-review/review_bundle_grants.py` supplies
reviewed bundle digests at grant issuance, including the actual blinded or
unblinded function's harness. It changes no worker, runtime output or assertion,
and modifies no Role B file. With that issuer migration, both unmodified suite
files passed:

```sh
PYTHONPATH=core/src:/tmp/aegis-agent1-review/merged/attack_lab/src:/tmp/aegis-agent1-review \
  /home/youss/Projects/aegis/.venv/bin/python -m pytest -p review_bundle_grants \
  /tmp/aegis-agent1-review/merged/attack_lab/tests/test_behavior_score.py \
  /tmp/aegis-agent1-review/merged/attack_lab/tests/test_scoring.py -q
```

**209 passed, 4.12 s; no warnings or skipped tests.** This covers fake execution,
private records, enforcement mapping and ledger behavior. It is migration
verification, not real execution or a pass for the original grant issuer.
The initial supplemental run had one failure because the review helper used
the blinded symbol for an unblinded fixture; the helper now derives the symbol
from the reconstruction task. No production exception was added.

**Integration requirement:** the operator/Role B grant issuer and its fixtures
must include `compilation_bundle_sha256`, computed from the reviewed files and
ordered units before grant issuance. See the Core integration contract for the
canonical algorithm and example. Old single-source grant digests and ledger
usage are preserved. A migrated grant has a changed digest, so reusing an old
ledger id is refused. Never remove ledgers to reset usage; reissued grants
require review accounting for previous consumption. This coordination remains
outstanding; a merge claiming all existing Role B tests pass would be premature.

## Real Shield and ImageLab validation

Fresh builds from this working tree, not reused binaries:

```sh
cmake -S protectors/llvm -B /tmp/aegis-agent1-review/shield -G Ninja \
  -DLLVM_DIR=/usr/lib/cmake/llvm -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/aegis-agent1-review/shield
ctest --test-dir /tmp/aegis-agent1-review/shield --output-on-failure

cmake -S demo/image_processor -B /tmp/aegis-agent1-review/imagelab -G Ninja \
  -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Release \
  -DIMAGELAB_WERROR=ON \
  -DIMAGELAB_SHIELD_PLUGIN=/tmp/aegis-agent1-review/shield/AegisShield.so
cmake --build /tmp/aegis-agent1-review/imagelab
ctest --test-dir /tmp/aegis-agent1-review/imagelab --output-on-failure
```

**Shield: 1/1 CTest passed (1.25 s). ImageLab: 12/12 CTests passed (3.22 s).**
ImageLab checks fixtures, CLI errors, exhaustive/random kernel properties,
independent references, variant equivalence and the Shield report. These execute
repository-owned trusted native programs, not generated reconstruction candidates.
No protector or ImageLab source change was necessary.

The report records 43 static transformation sites (9 tone, 24 colour, 10
enhance). The ELF byte inspection script
`/tmp/aegis-agent1-review/verify_retention.py` independently reads symbol bytes
from kernel objects **and the final optimized CLI and benchmark executables**;
all three functions differ in size and SHA-256 in all three artifact classes.
Raw paths, sizes and digests are in `retention.json` under the same scratch root.

| Kernel | Baseline bytes | Shield bytes |
| --- | ---: | ---: |
| tone | 336 | 374 |
| colour | 577 | 649 |
| enhance | 407 | 442 |

Executable CLI SHA-256: baseline
`f5090a8da14f21da10f1516184d51d9c6dc650861c618461a552f511b8f598df`;
Shield `a08a1b42ba50769db9e829437cf36c1cca8ef25850d6be3c9c5ce79acb26dc2c`.
The small Role B fixture's previously reported optimizer cancellation is not
generalized to ImageLab: ImageLab retained changes in this fresh build.

Benchmark command:

```sh
taskset -c 3 python3 demo/image_processor/tools/compare_variants.py \
  --build /tmp/aegis-agent1-review/imagelab --rounds 5 \
  --output /tmp/aegis-agent1-review/imagelab-compare.json
python3 /tmp/aegis-agent1-review/verify_retention.py
```

Conditions: 2026-10-29 23:37:21 UTC; Intel Core Ultra 9 185H, Linux
7.2.3-1-cachyos x86-64, glibc 2.44; Clang/LLVM 22.1.8; CMake/Ninja;
Release build; IR backend `-O2`, seed 42, max-sites 64. CPU affinity fixed to
logical CPU 3, powersave governor, turbo/frequency and other load uncontrolled.
One deterministic 1024×768 image, image seed 1; 5 rotating rounds × 9 samples =
45 samples per operation/variant; each sample is 4 calls; 1 warmup per round.
Baseline and Shield use the same IR pipeline. Native `-O3` is not the fair
protection-overhead baseline.

Medians below are **per call**, dividing the JSON's four-call sample by four:

| Operation | IR baseline ms | Shield ms | Measured overhead |
| --- | ---: | ---: | ---: |
| tone | 6.761669 | 7.012170 | +3.70% |
| colour | 7.524749 | 8.274924 | +9.97% |
| enhance | 26.059686 | 27.414623 | +5.20% |

All 150 CLI fixture/parameter combinations per variant were byte-identical;
all benchmark fingerprints matched. Per-call min–max ranges were 5.96–8.35 ms
baseline / 6.05–14.63 ms Shield for tone; 6.62–8.63 / 7.29–12.33 ms for colour;
22.26–34.18 / 24.27–37.86 ms for enhance. Small timing differences lie within
substantial uncontrolled variation. Raw samples and artifact identities remain
in the scratch JSON; no raw benchmark report containing function names was
added to the repository.

These are static transformation, optimized-code retention, correctness and
overhead results for this workload/toolchain/seed only. No reverse-engineering
attack was run; no measured attack resistance or security property is claimed.

## Prerequisites and exact operator-only validation path

Read-only host probe and pinned-asset hashes were checked outside the tool
sandbox. Static prerequisites are present: bwrap and systemd-run, cgroup v2,
delegated cpu/memory/pids, user namespaces and readable/writable KVM device
metadata. **KVM was not opened and enforcement was not tested.** `io` is not
delegated. All four smoke asset pins in `validation-smoke.toml.example` match
the actual host files; their paths and sizes are in
`/tmp/aegis-agent1-review/prerequisites.json`. Inside the tool sandbox, KVM is
hidden and system file owners are remapped; those sandbox-only blockers do not
describe the actual host.

The existing smoke config was copied with this operator's paths into
`/tmp/aegis-agent1-review/smoke.toml`, with candidate gates still false. The
following **plan** command was run; it starts nothing:

```sh
PYTHONPATH=core/src /home/youss/Projects/aegis/.venv/bin/python \
  -m aegis_core.lab_containment plan \
  --config /tmp/aegis-agent1-review/smoke.toml --target smoke_fixture
```

Prepared plans: `plan-smoke_fixture.json`, `plan-candidate_guest.json` and
`plan-smoke-cli.json` under the scratch root. Smoke: **3 sequential VMs**,
385 MiB maximum scope memory, 179 s stated upper bound. Candidate validation:
**33 sequential VMs**, 768 MiB maximum scope memory, 1656 s stated upper bound.
Both plans additionally report the 2 GiB asset-copy bound. Candidate numbers
are a resource estimate using the smoke config's controls; its asset pins are
**not** a candidate config and must be replaced before candidate validation.

After explicit operator approval, the first proposed command is:

```sh
PYTHONPATH=core/src /home/youss/Projects/aegis/.venv/bin/python \
  -m aegis_core.lab_containment run \
  --config /tmp/aegis-agent1-review/smoke.toml --target smoke_fixture \
  --report /tmp/aegis-agent1-review/smoke-report.json --approve-vm-launch
```

Expected smoke result: `overall=incomplete`, exit 3; host jail/seccomp/network,
teardown/backstop, readback/pin/report refusal, no-leftovers and unchanged-image
checks pass, guest checks remain not run. Exit 0 is impossible for smoke. Any
failed/error case is a blocker. Verify original rootfs SHA-256 remains
`a7df8e9130314087d0c65a13635e3b9c1c72092300f3ca791c5d506118e144e5`,
no `aegis-fc-*` scopes remain, and `/run/user/1000/aegis-fc` is empty.
The report path must not already exist.

Candidate assets require a **separate approved build/download step**. Neither
guest nor builder package snapshot is pinned; an operator must supply a verified
Debian keyring/fingerprint, snapshot timestamp, Linux 6.1.y source version and
signed-source digest, and the pinned Firecracker guest-config digest. Commands
after those reviewed values are supplied (not run here):

```sh
KEYRING=/path/to/approved/debian-archive.gpg FPR=<verified-signing-fingerprint> \
  core/guest/build-guest-image.sh /tmp/aegis-candidate-guest
KVER=<approved-6.1.y> KSHA=<verified-kernel-source-sha256> \
  FCCFG_SHA=<reviewed-firecracker-config-sha256> \
  KEYRING=/path/to/approved/debian-archive.gpg FPR=<verified-signing-fingerprint> \
  core/guest/build-guest-kernel.sh /tmp/aegis-candidate-kernel
```

Those placeholders are approval inputs, not executable verified values. Pin the
resulting kernel, full guest image, agent and compiler digests in an operator
candidate TOML (plus unchanged reviewed VMM/bwrap pins and host controls). Then,
with separate explicit launch approval:

```sh
PYTHONPATH=core/src /home/youss/Projects/aegis/.venv/bin/python \
  -m aegis_core.lab_containment plan --config /path/to/approved/candidate.toml \
  --target candidate_guest
PYTHONPATH=core/src /home/youss/Projects/aegis/.venv/bin/python \
  -m aegis_core.lab_containment run --config /path/to/approved/candidate.toml \
  --target candidate_guest --report /tmp/aegis-candidate-containment.json \
  --approve-vm-launch
```

Expected: C0 and all F1–F5/V1–V11 checks pass; exit 0; no leftover scopes or
state; unchanged image; enforced CPU/wall/memory/process/output/scratch bounds,
denied filesystem/network/privilege access, and protocol fuzz rejection. Only
that report may be pinned for its exact configuration. ADR acceptance still
requires a reviewed change. See `core/guest/README.md` for the case matrix.

Remaining safety/integration blockers are: approved candidate assets and actual
guest startup; real sealed-asset launch/containment validation; C0/F1–F5/V1–V11
success; reviewed ADR 0004 acceptance; and the Role B grant-issuer migration.
No real-VM suite is reported passed. Real reverse-engineering resistance was
not tested. No whole-repository merge/conflict resolution was attempted.

## Files changed during this review

These are changes relative to the preserved starting working tree, not every
file already modified before this task. The prior `config.py`, `models.py`,
`orchestrator.py`, testing helpers, conftest, guest builders/canaries and other
uncommitted work were retained. The complete review changed these 19 files:

- `ARCHITECTURE.md`
- `core/README.md`
- `core/docs/lab-execution-contract.md`
- `core/guest/README.md`
- `core/guest/guest-packages.json`
- `core/src/aegis_core/lab_authorization.py`
- `core/src/aegis_core/lab_containment.py`
- `core/src/aegis_core/lab_execution.py`
- `core/src/aegis_core/lab_firecracker.py`
- `core/src/aegis_core/lab_guest_agent.py`
- `core/src/aegis_core/lab_host.py`
- `core/tests/lab_fixtures.py`
- `core/tests/test_lab_authorization.py`
- `core/tests/test_lab_execution.py`
- `core/tests/test_lab_firecracker.py`
- `core/tests/test_lab_guest_build.py`
- `docs/CORE_EXECUTION_REVIEW.md` (new)
- `docs/PROJECT_STATUS.md`
- `docs/adr/0004-isolated-candidate-execution.md`

Scratch logs, plans, supplemental issuer, retention script, raw benchmarks and
pre-task source copies are under `/tmp/aegis-agent1-review/`; they are not
repository source changes. `git diff --check` passes.
