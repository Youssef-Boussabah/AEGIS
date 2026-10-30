# Devpost draft and operator checklist

## Project name and tagline

**AEGIS — traceable LLVM transformation and reconstruction research**

A local workspace that pairs a real compiler transformation pipeline with honest,
inspectable artifact evidence and bounded reconstruction experiments.

## Inspiration

Software-protection demos often mix transformed code, security claims and
illustrative dashboards. We wanted to make the boundary visible: what code was
submitted, what tool ran, what artifacts resulted, what an experiment actually
measured, and what remains unknown.

## What it does

AEGIS accepts owned textual LLVM 22 IR through a React dashboard, a local FastAPI
service or a CLI. Core invokes an explicitly registered Shield adapter, records
pending/running/succeeded/failed states, computes artifact SHA-256 digests and
produces a terminal report even when a job fails. The UI shows those real states,
reports, digests and transformation counts with evidence-source labels.

The owned ImageLab application supplies reference-model tests and comparable
native, IR-baseline and Shield variants. Separate Mirage tooling inserts retained
unreachable arithmetic decoys. The Lab binds Ghidra evidence to authorized trial
records and supports bounded, scripted offline reconstruction with privately
archived evidence. Verified local exports let the dashboard present summaries
without uploading hidden suites, request transcripts or candidate source.
Offline provenance signing and cooperating policy tools are available as separate
CLIs; they are not automatic job-signing or live-license services.

## How we built it

Python/Pydantic contracts, local filesystem storage and a subprocess adapter
protocol connect FastAPI/CLI clients to a C++ LLVM 22 plugin. React, TypeScript
and Vite supply the local dashboard. CMake/CTest and pytest cover the native and
Python components; real Chromium tests submit the owned fixture through the
built UI and verify both successful reports and honest failures.

## NVIDIA and Nebius — verified scope

The merged Role B implementation includes a Nebius Token Factory chat-completion
transport, bounded response parsing and offline tests for HTTP, usage, timeout,
rate-limit and malformed-response behavior. Credentials are server-side runtime
inputs; the public Lab workflow remains fail-closed for live inference.

The transport’s configurable convenience model identifier names an NVIDIA
Nemotron model family. A string is not evidence that the model was available,
queried or executed. **No live Nebius request, NVIDIA model inference, NVIDIA GPU
execution or hardware acceleration is verified by the handoff.** The retained
experiments use `FakeOffline`, identify their scripted model, incur zero inference
cost and never execute generated candidates. Do not claim an NVIDIA/Nebius
integration prize criterion is satisfied without the organizer’s applicable rules
and additional verified evidence. No live inference is enabled by this release.

Source: [merged Role B handoff](../../attack_lab/docs/role-b-delivery.md#nebius-and-rea)
and the merged provider implementation. Any later Agent 2 evidence must name the
exact artifact, model identity, authorization, endpoint, date, usage/cost and
limitations before this section or the UI changes.

## Challenges and results

Registering the real LLVM adapter and exercising it through the UI closed the
previous successful-job integration gap. Explicit failure handling, digest checks
and removal of simulated security statistics make the product testable without
inventing security evidence. The [validation record](VALIDATION.md) records the
exact local test results and remaining unrun suites.

Shield remains a prototype with no established security property. In Role B’s
owned fixture experiment its IR changes optimized away and final baseline/Shield
binary hashes matched. Mirage’s decoys survived the tested O2/linker-GC pipeline,
but model target selection and reconstruction resistance were not measured.
Candidate generation is distinct from behavioral scoring; matching Core scoring
contracts are not merged into this checkout. The next milestones are that
integration, owner-approved runtime containment and authorized live experiments.

## Built with

Python, Pydantic, FastAPI, uvicorn, C++, LLVM 22, CMake, React, TypeScript, Vite,
pytest, CTest, Playwright, Ghidra (research workflow), Ed25519/cryptography.
Nebius transport is offline-tested; NVIDIA inference remains unverified.

## Operator submission checklist

- [ ] Review the exact branch diff and [validation](VALIDATION.md); reconcile Agent 1 architecture/status notes at integration.
- [ ] Reproduce [the runbook](RUNBOOK.md) from a fresh checkout or extracted package on supported tools.
- [ ] Review owner-approved artifact rights and ensure only the owned fixture appears publicly.
- [ ] Review and approve a final [license](LICENSE-MIT-DRAFT.md); the draft does not grant rights or finalize the choice.
- [ ] Run required tests/build and inspect the local package’s SHA-256 inventory.
- [ ] Record and edit the [≤3-minute sequence](DEMO-SCRIPT.md); redact private reports/credentials. No video has been recorded by this task.
- [ ] Replace submission placeholders with operator-approved repository, package and video links.
- [ ] Confirm event eligibility, deadlines, team attribution and NVIDIA/Nebius track requirements from the actual organizer rules. No event-specific eligibility is asserted here.
- [ ] Approve commit/push/PR and public release separately. Nothing has been committed, deployed or published by this task.
- [ ] Upload only the reviewed package/public assets and complete Devpost after explicit operator approval.

Public repository: **operator to supply approved release URL**. Testable artifact:
local review package generated by `scripts/product.py package`. Video:
**operator to record/publish after review**. These are pending submission actions,
not fabricated public links.
