# AEGIS: four-person engineering workstreams

**Active plan — 28 October 2026.** This file supersedes the six-person *assignment split* in the PDFs under `docs/`. The PDFs remain the product and architecture baseline at `c995857`; they are not evidence that future work has been implemented. The current branch, source, tests and accepted ADRs determine current behavior.

## Four owners

| Stream | Availability | Owner | GitHub issue | Owned implementation paths |
|---|---|---|---|---|
| A — Core Platform, Shield & Integration | High | Youssef (integration lead) | [#9](https://github.com/Youssef-Boussabah/AEGIS/issues/9) | `core/`, `platform/api/`, `platform/cli/`, `protectors/llvm/`, `demo/image_processor/`, root, `docs/`, `.github/` |
| B — Adversarial AI Lab & Mirage | High | To assign | [#10](https://github.com/Youssef-Boussabah/AEGIS/issues/10) | `attack_lab/`, `protectors/mirage/` |
| C — Frontend & Product Experience | High | Frontend teammate (GitHub identity pending) | [#11](https://github.com/Youssef-Boussabah/AEGIS/issues/11) | `platform/dashboard/`, frontend-owned assets/tests |
| D — Signature, Sentinel & Verification | Limited | To assign | [#12](https://github.com/Youssef-Boussabah/AEGIS/issues/12) | `provenance/`, `sentinel/` |

Ownership means first reviewer and primary editor, not permission to break shared contracts. Shared model, adapter, API, security, storage or deployment changes need Stream A review. Stream B does not independently edit `protectors/llvm/`; Stream C does not independently change `platform/api/`; Stream D does not independently change Core. Engineers may use any coding agent. No agent receives push/merge authority without explicit task authorization.

## What to deliver first

- **A — Integration foundation and stronger Shield:** get clean-clone CI and actual LLVM/ImageLab cross-component tests running; fix stale repository governance; measure final-binary retention and optimized-build performance; add a tested semantics-preserving defense; integrate others' outputs. Adaptive optimization only after valid resistance and overhead evidence.
- **B — Actual attack evidence, then Mirage:** build authorized paired Ghidra/model reconstruction trials; isolate execution of generated candidates, score against independent hidden tests, record identical budgets and all failures. Then implement a harmless deterministic decoy with a no-decoy control and measured retention.
- **C — Real usable frontend:** use implemented API status/report/job submission endpoints to build upload/configuration, progress, error states and artifact evidence UI; request extra endpoints via A; no fabricated demo results.
- **D — Offline signed provenance first:** signed artifact manifest, public-key verification, tamper/invalid-key tests and no committed secrets. Sentinel policy records and watermark research only after signing works.

## Cross-stream contracts

1. The existing `aegis.adapter.v1` wire contract is authoritative. A new proposed field in a research manifest does not automatically belong in Core's strict models.
2. A Shield job producing changed LLVM IR is **not** proof of reverse-engineering resistance. Record final artifact functionality, retained transformations, and performance against both matched IR and normal optimized baselines.
3. Lab attack tasks remain disabled by default and require both operator enablement and per-request authorization. The adapter subprocess runner is not an isolation sandbox.
4. Signing binds an explicit artifact digest after final artifact bytes are fixed. UI must distinguish orchestrator-verified hashes, backend assertions and independent checks.
5. ImageLab remains an internal regression target; [external benchmark #7](https://github.com/Youssef-Boussabah/AEGIS/issues/7) covers PhotoCraft, reVC and Mattermost. Never recognize names, symbols or expected answers inside generic defenses. Hold out unseen targets.

## Contribution and first-day workflow

1. Read [User Guide](AEGIS_USER_GUIDE.pdf), [Technical Documentation](AEGIS_TECHNICAL_DOCUMENTATION.pdf), `AGENTS.md`, `ARCHITECTURE.md` and your issue.
2. Confirm branch and `git status`, then branch from current `origin/dev/integration`. Do not work directly on the integration branch.
3. Reproduce existing tests for relevant modules. A plain root pytest run does **not** select the LLVM adapter's 94 tests. Explicitly run `core/tests platform/api/tests platform/cli/tests protectors/llvm/adapter/tests` for the Python integration suite with the required LLVM tools.
4. Propose minimal affected files/interfaces before changing shared contracts. Keep build outputs, `.aegis/` and secrets out of commits.
5. PR to `dev/integration` with exact commands, results and warnings, test cases not run, artifact hashes where relevant, and an explicit handoff.

## Legacy task mapping

- Previous [#1](https://github.com/Youssef-Boussabah/AEGIS/issues/1) and [#2](https://github.com/Youssef-Boussabah/AEGIS/issues/2) → **A / #9**
- Previous [#3](https://github.com/Youssef-Boussabah/AEGIS/issues/3) and [#4](https://github.com/Youssef-Boussabah/AEGIS/issues/4) → **B / #10**
- Previous [#6](https://github.com/Youssef-Boussabah/AEGIS/issues/6) → **C / #11**
- Previous [#5](https://github.com/Youssef-Boussabah/AEGIS/issues/5) → **D / #12**
- [#7](https://github.com/Youssef-Boussabah/AEGIS/issues/7) stays open as the independent cross-ecosystem benchmark shared task, coordinated by A.

The team and integration lead can reassign owners in issues after GitHub usernames are known; do not infer identities.