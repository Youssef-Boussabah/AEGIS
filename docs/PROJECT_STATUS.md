# AEGIS project status

**Snapshot:** 2026-10-28 · **Integration reference:** `dev/integration`. Update the commit hash and task status after merges; this is a tracked coordination note, not a substitute for tests or Git history.

## Verified milestone 002 (historical results)

- Current baseline source before the documentation merger was `c995857`.
- Core, API, CLI and LLVM adapter: **199 combined Python tests passed** in a user-reported run (one Starlette/httpx warning).
- LLVM Shield: one CTest entry incorporating **14 internal cases**, user-reported passed.
- Real ImageLab job `4001e5aceb144882a21a2f6653e52fb3`: **43 reported arithmetic transformation sites across three kernels**; reconstructed application using the CLI job's external IR and **11/11 ImageLab CTests passed**, as reported in user terminal output.
- The current real backend only handles selected textual LLVM 22 IR and outputs `protected.ll` plus `shield-report.json`. The tool does **not** protect arbitrary software or demonstrate attacker resistance.

## In progress / planned

| Workstream | Issue | State |
|---|---|---|
| A Core, Shield, Integration | #9 | Ready to assign/implement; CI, governance, final-binary retention and Shield v2 remain work |
| B Adversarial Lab and Mirage | #10 | Ready to assign; no real reconstruction backend yet |
| C Frontend and UI | #11 | Teammate selected; implementation status not established |
| D Signature and Sentinel | #12 | Limited-availability owner to assign; signing not established |
| External benchmark profiles | #7 | PhotoCraft, reVC and Mattermost selected; integrations not demonstrated |

## Immediate integration blockers

- CI and protected-branch rules have not been demonstrated as enabled.
- Root `AGENTS.md`, `ARCHITECTURE.md` and README require updated ownership and module listings (address in the four-person governance PR).
- Shared API enhancements for artifact retrieval/listing require deliberate review and safe path handling.
- A genuine reconstruction comparison is needed before advertising effective reverse-engineering resistance.

## Keeping this record trustworthy

On each accepted PR, record merge commit, owner, actual test commands/counts, new limitations, and next work. Update workstream issues and this status file together. Avoid copying transient agent claims into product capability statements. The User Guide and Technical Documentation are a frozen `c995857` reference; use repository code and tests for newer state.