# ADR 0001: Monorepo with independently built components

- **Status:** Accepted
- **Date:** 2026-10-27
- **Scope:** repository structure, build and integration boundaries

## Context

AEGIS combines components written in different languages with different
toolchains:

- a Python orchestration platform (`core/`, `platform/api/`, `platform/cli/`)
- a C++ LLVM pass plugin (`protectors/llvm/`) that depends on one LLVM major
  version's ABI

These components were developed in parallel by separate agents on separate
branches (`feat/core-platform`, `feat/llvm-shield`), each confined to its own
paths, and were then combined on `dev/integration`. Neither needed to change
the other's files. A shared build would couple a Python release to an LLVM
toolchain, and would make every contributor install LLVM 22 to run Python
tests.

## Decision

1. **One repository** holds every AEGIS component, its tests and its
   documentation. Root files (`AGENTS.md`, `ARCHITECTURE.md`, `README.md`,
   ADRs) govern the whole repository.
2. **Each component builds and tests on its own, with no root build:**
   - Each Python package has its own `pyproject.toml` (hatchling, `src/`
     layout). The three packages are installed together in editable mode into
     one repository-local `.venv`.
   - `protectors/llvm` is a standalone CMake project tested with CTest.
   - The root `pyproject.toml` holds tooling configuration only (pytest
     `testpaths`). It has no `[project]` table.
3. **Protection backends are integrated by process boundary, not by
   linking or importing.** `aegis_core` runs backends through the
   `aegis.adapter.v1` subprocess protocol (JSON request file in, JSON result
   on stdout). Backends keep their own local schemas.
4. **Path ownership.** Each top-level component directory has one owning
   branch or stream of work (see `AGENTS.md` §1). Cross-component changes go
   through the owners or a governance change.
5. **Python package names are prefixed `aegis_`**, because a top-level
   package named `platform` would hide the standard-library `platform` module.

## Consequences

- Python contributors don't need LLVM, and Shield contributors don't need
  the Python packages. Each suite runs on its own.
- A backend can be rewritten or replaced (any language) without touching
  `aegis_core`, as long as it speaks the adapter protocol.
- Process isolation gives the orchestrator a place to enforce timeouts, a
  minimal environment, path containment and its own hashing (ARCHITECTURE.md
  §6). The cost is a process launch per job and JSON serialization.
- Without a root build, nothing enforces cross-component compatibility
  automatically. There is no CI yet, so contributors must run every affected
  suite by hand (`AGENTS.md` §4).
- Schema conventions can drift between components. They already differ:
  string vs integer `schema_version`, and different id styles. They must be
  reconciled explicitly (ARCHITECTURE.md, open issue A2).
- The Shield is not reachable from AEGIS until an adapter executable exists
  (ARCHITECTURE.md §7, open issue A1).
