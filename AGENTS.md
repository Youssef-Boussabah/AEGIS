# AGENTS.md: rules for contributors and coding agents

This file is authoritative for everyone working in this repository, human or
agent. Read it first, then [ARCHITECTURE.md](ARCHITECTURE.md), then the README
of the module you will touch. A module README may add stricter rules for that
module, but it may not loosen these.

## 1. Module ownership (four active workstreams)

See [docs/TEAM_WORKSTREAMS.md](docs/TEAM_WORKSTREAMS.md) and the four current umbrella issues [#9](https://github.com/Youssef-Boussabah/AEGIS/issues/9), [#10](https://github.com/Youssef-Boussabah/AEGIS/issues/10), [#11](https://github.com/Youssef-Boussabah/AEGIS/issues/11), and [#12](https://github.com/Youssef-Boussabah/AEGIS/issues/12). Both PDFs use these same four roles. Roles describe technical responsibility, not named people or availability. The reorganization does not change technical contracts.

| Path | Primary workstream | Notes |
| --- | --- | --- |
| `core/`, `platform/api/`, `platform/cli/` | **A — Core Platform, Shield & Integration** | strict models, jobs, API and CLI |
| `protectors/llvm/` (including `adapter/`) | **A** | Shield plugin and LLVM adapter |
| `demo/image_processor/` | **A** | ImageLab benchmark and integration harness |
| root, `.github/`, `docs/` | **A** | CI, architecture, ADRs, cross-stream coordination |
| `attack_lab/`, `protectors/mirage/` | **B — Adversarial AI Lab & Mirage** | independent scoring and defensive decoys |
| `platform/dashboard/` | **C — Frontend & Product Experience** | UI and frontend tests; API changes coordinated with A |
| `provenance/`, `sentinel/` | **D — Signature, Sentinel & Verification** | signed manifests first; policy/watermark later |

Do not edit outside assigned paths without explicit approval. Shared changes to `aegis_core.models`, `core/docs/adapter-protocol.md`, Core storage/authorization, backend local schemas, or public API need approval by A and the affected owner. Team members and coding agents must never weaken the dual attack-lab authorization gates, invent security evidence, or silently add test-specific special cases.

The four workstream branches are `feat/core-shield`, `feat/lab-mirage`, `feat/frontend`, and `feat/signature-sentinel`. Historical branch names in ADRs describe earlier work. Follow [CONTRIBUTING.md](CONTRIBUTING.md) for checkout, synchronization and PR instructions.

## 2. Branches and commits

- `dev/integration` is the public default integration branch. Prefer reviewed PRs for new work; earlier milestones also used cherry-picks. A release branch is not yet defined.
- Use the existing workstream branch for its coordinated work, or a short task
  branch created from current `origin/dev/integration`. Both target `dev/integration`
  through a PR. Name task branches:
  - `feat/<area>` for features
  - `fix/<area>` for fixes
  - `docs/<topic>` for documentation
- Never commit to, rebase, reset, or force-push another agent's branch, and
  never rewrite `dev/integration` history.
- Every worktree shares one git stash stack, so don't use bare `git stash` or
  `git stash pop`. Use a temporary WIP commit instead.
- Commit subjects follow Conventional Commits with the module as scope:
  `feat(core): …`, `feat(shield): …`, `docs(root): …`, `fix(api): …`.
- One logical change per commit. Commit only when every affected suite passes
  (§4), or say in the commit body which ones fail and why.
- Commit, push, or open a PR only when the task asks you to. Never push
  without being asked.

## 3. Environment and safety

- **No `sudo`.** Don't install system or user packages without asking first.
  Python dependencies go into the repository-local `.venv/` only (see
  README.md#setup).
- **No secrets** in code, tests, logs, commit messages, reports, or fixtures.
  `.env` files are git-ignored; only `.env.example` (with no values) may be
  committed.
- **No `shell=True`** (or any shell string) with untrusted values: user input,
  file names, options, or request data. Build argv arrays.
- Subprocesses that run backends must keep the guarantees in
  ARCHITECTURE.md §6: timeout with process-group kill, minimal environment,
  path containment, and orchestrator-side hashing.
- **Attack-lab work requires explicit authorization.** Never weaken, bypass,
  or default-enable the two gates (`[attack_lab] enabled` and
  `AttackLabAuthorization`). Never write tests or fixtures that attack systems
  or artifacts you are not authorized to test.
- Don't add infrastructure (databases, queues, containers, cloud services)
  without an ADR. Local files under the store root are the current design.
- Put generated files (builds, benchmark scratch, `.aegis/` stores) outside
  the source tree, in `/tmp` or a scratch directory, or under a git-ignored
  path.

## 4. Testing rules

All existing tests must keep passing. Never delete, skip, or weaken a test to
get green; fix the code or report the failure. New behaviour needs tests,
including tests for its error paths.

| Suite | Command (from repository root) | Notes |
| --- | --- | --- |
| default Python | `.venv/bin/pytest` | root `pyproject.toml` selects Core, API, CLI only (currently 105 tests at baseline) |
| complete Python + real adapter suite | `.venv/bin/python -m pytest core/tests platform/api/tests platform/cli/tests protectors/llvm/adapter/tests -q` | includes LLVM adapter cases (199 total at recorded baseline); requires working LLVM 22 tools and plugin |
| one package | `(cd core && ../.venv/bin/pytest)`, and likewise for `platform/api` and `platform/cli` | uses the package's own pytest config |
| LLVM Shield | `cmake -S protectors/llvm -B /tmp/aegis-shield-build -G Ninja -DLLVM_DIR="$(llvm-config --cmakedir)" -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Release && cmake --build /tmp/aegis-shield-build && ctest --test-dir /tmp/aegis-shield-build --output-on-failure` | needs LLVM ≥22 (verified 22.1.8) with matching `opt` and `clang`; driven by CTest, **not** pytest |

- Run every suite your change can affect. For root and docs changes, run the complete Python suite, LLVM CTest and ImageLab CTest where the required toolchain is available. Missing prerequisites must be reported as **not run**, never passed. See the detailed commands in `docs/AEGIS_TECHNICAL_DOCUMENTATION.pdf` §09.
- Python tests use `aegis_core.testing.fake_adapter`, which applies no
  protection. Never register it as a real backend or cite its output as
  evidence of protection.
- If a toolchain is missing (for example, LLVM), say the suite was **not
  run**. Never report it as passed.

## 5. Artifacts and evidence

- Artifacts are identified by SHA-256 computed by the orchestrator.
  `EvidenceRecord.source` must stay truthful: `orchestrator` only for things
  the orchestrator observed or verified, and `adapter` for adapter claims.
- Benchmark results may be committed only together with a write-up of the exact
  command, toolchain, hardware, date, sample counts and limitations, as in
  `protectors/llvm/benchmarks/RESULTS.md`.
- Shield reports can reveal function names. Treat them as build artifacts,
  not public documents.

## 6. Truthful reporting

These rules apply to code (status values, report text), documentation, commit
messages, and every summary an agent gives:

- **Never claim a feature exists unless it is implemented and tested.** Label
  planned work "planned" or "not implemented".
- Report test results exactly: suites run, pass/fail counts, warnings, and
  suites not run (with the reason).
- Never turn a failure into a success. Unsupported backends, missing tools,
  timeouts and invalid output must surface as explicit errors (the `ErrorCode`
  values), never as fake success or empty output.
- Don't overstate security. The LLVM Shield has no established security
  property. Changed IR, changed machine code, or matching outputs are not
  evidence of protection. Any report of attack resistance must name the
  attacks run and their limitations.
- Name every file you changed. Surface open issues, assumptions and anything
  skipped. Don't bury them.
- Mark measurements with their conditions, and never extrapolate them to other
  programs, seeds, compilers or hardware.

## 7. Documentation duties

- Changing a contract, the adapter protocol, the storage layout, a security
  control or a module boundary requires an update to `ARCHITECTURE.md`
  (and to the relevant module README) in the same change.
- Record significant structural decisions as ADRs in `docs/adr/NNNN-title.md`
  (Status / Context / Decision / Consequences).
