# AEGIS project status

**Snapshot:** 2026-10-28 · **Integration reference:** `dev/integration`. Update the commit hash and task status after merges; this is a tracked coordination note, not a substitute for tests or Git history.

## Verified milestone 002 (historical results)

- Current baseline source before the documentation merger was `c995857`.
- Core, API, CLI and LLVM adapter: **199 combined Python tests passed** in a user-reported run (one Starlette/httpx warning).
- LLVM Shield: one CTest entry incorporating **14 internal cases**, user-reported passed.
- Real ImageLab job `4001e5aceb144882a21a2f6653e52fb3`: **43 reported arithmetic transformation sites across three kernels**; reconstructed application using the CLI job's external IR and **11/11 ImageLab CTests passed**, as reported in user terminal output.
- The current real backend only handles selected textual LLVM 22 IR and outputs `protected.ll` plus `shield-report.json`. The tool does **not** protect arbitrary software or demonstrate attacker resistance.

## Four-role revision validation (28 October 2026)

- `.venv/bin/pytest -q`: **105 passed**, one existing Starlette/httpx deprecation warning, Python 3.12.14 with the repository dependency constraints. This covers Core/API/CLI only.
- LLVM Shield CTest, the real adapter suite and ImageLab CTest: **not run** in the documentation workspace because matching LLVM/Clang, CMake and Ninja are unavailable. The historical 199-test result above is not a new result.
- Revised PDFs were rendered and inspected; four-role references, local Markdown links and whitespace were checked. No runtime implementation was changed.

## In progress / planned

| Workstream | Issue | State |
|---|---|---|
| A Core, Shield, Integration | #9 | Phase 4 (branch `feat/core-lab-execution`, unmerged): Core grants, sessions, ledger, Firecracker backend and containment tooling implemented and fixture-tested; isolation **not real-VM-validated or approved**. [ADR 0004](adr/0004-isolated-candidate-execution.md) and its Firecracker amendment remain **proposed**. Complete bundle binding requires a grant-issuer migration. Fresh ImageLab builds retain optimized machine-code differences; see the execution review below |
| B Adversarial Lab and Mirage | #10 | Scope defined; no real reconstruction backend yet |
| C Frontend and UI | #11 | Scope defined; implementation status not established |
| D Signature and Sentinel | #12 | Implemented; offline signed provenance, Sentinel policies, watermark research (36 tests passed) |
| External benchmark profiles | #7 | PhotoCraft, reVC and Mattermost selected; integrations not demonstrated |

## Immediate integration blockers

- CI and protected-branch rules have not been demonstrated as enabled.
- The four-role revision aligns root guidance, the two PDFs, contribution instructions and issues #9–#12. The feature branches must receive the accepted revision before engineering begins; follow CONTRIBUTING.md without resetting branches containing work.
- Shared API enhancements for artifact retrieval/listing require deliberate review and safe path handling.
- A genuine reconstruction comparison is needed before advertising effective reverse-engineering resistance.
- Phase 4 candidate execution is blocked on approved pinned candidate assets, C0/F1–F5/V1–V11 validation and ADR 0004 approval. The implemented Firecracker path needs no `runsc`; gVisor remains unimplemented. Core refuses configured execution (`SANDBOX_UNAVAILABLE`).

## Core execution review (2026-10-29; unmerged working tree)

The Firecracker backend and containment tooling are implemented and fixture-tested,
but remain unapproved and have no real-VM containment result. Complete bundle
binding, live guest CPU supervision, pipe draining, retryable cleanup, immutable
launch asset copies and host-observation precedence are covered by regressions.
Normal execution remains disabled (`ADR_0004_ACCEPTED = False`). Multi-file grant
issuers need a reviewed migration; Role B code was not modified.
Fresh Shield/ImageLab builds retain changed optimized kernel code and pass their
native tests. Exact Python/native results, benchmark conditions, files changed
and operator-only validation commands are in [CORE_EXECUTION_REVIEW.md](CORE_EXECUTION_REVIEW.md).

## Keeping this record trustworthy

On each accepted PR, record merge commit, owner, actual test commands/counts, new limitations, and next work. Update workstream issues and this status file together. Avoid copying transient agent claims into product capability statements. The recorded technical evidence predates this reorganization; read the current four-workstream revisions alongside repository code and tests for later implementation state.
