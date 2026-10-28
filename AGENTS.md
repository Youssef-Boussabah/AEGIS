# AGENTS.md: rules for contributors and coding agents

This file is authoritative for everyone working in this repository, human or
agent. Read it first, then [ARCHITECTURE.md](ARCHITECTURE.md), then the README
of the module you will touch. A module README may add stricter rules for that
module, but it may not loosen these.

## 1. Module ownership

Work only inside the paths your task assigns you. Anything outside them is
read-only unless the task explicitly says otherwise.

| Path | Owner (feature branch / worktree) | Notes |
| --- | --- | --- |
| `core/` | core platform (`feat/core-platform`, `aegis-claude`) | `aegis_core`: contracts, store, orchestrator, adapter runner |
| `platform/api/` | core platform | `aegis_api`: FastAPI service |
| `platform/cli/` | core platform | `aegis_cli`: `aegis` command |
| `protectors/llvm/` | LLVM Shield (`feat/llvm-shield`, `aegis-codex`) | C++ LLVM pass plugin, CMake, its own tests and benchmarks |
| root files, `docs/` | repository governance (`docs/*` branches) | `AGENTS.md`, `ARCHITECTURE.md`, `README.md`, `.gitignore`, `pyproject.toml`, ADRs |

- Changing a shared contract means changing anything in
  `aegis_core.models`, the adapter protocol (`core/docs/adapter-protocol.md`,
  `aegis_core.adapter`), or a schema under `protectors/llvm/schemas/`. That
  needs a change in the owning module plus an update to `ARCHITECTURE.md`. It
  may also need an ADR.
- Do not edit another module to make your own work pass. Report the
  incompatibility instead.
- The LLVM Shield adapter (ARCHITECTURE.md §7) has no owner yet. Don't create
  it without a task that assigns it.

## 2. Branches and commits

- `dev/integration` is the integration branch. Feature work is combined there
  (so far by cherry-picking each feature branch's commits). There is no `main`
  branch yet (ARCHITECTURE.md, A6).
- Do feature work on a new branch created from `dev/integration` (or from the
  commit the task names), named:
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
| all Python | `.venv/bin/pytest` | root `pyproject.toml` runs `core/tests`, `platform/api/tests`, `platform/cli/tests` |
| one package | `(cd core && ../.venv/bin/pytest)`, and likewise for `platform/api` and `platform/cli` | uses the package's own pytest config |
| LLVM Shield | `cmake -S protectors/llvm -B /tmp/aegis-shield-build -G Ninja -DLLVM_DIR="$(llvm-config --cmakedir)" -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Release && cmake --build /tmp/aegis-shield-build && ctest --test-dir /tmp/aegis-shield-build --output-on-failure` | needs LLVM ≥22 (verified 22.1.8) with matching `opt` and `clang`; driven by CTest, **not** pytest |

- Run every suite your change can affect. For root and docs changes, run all
  of them.
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
