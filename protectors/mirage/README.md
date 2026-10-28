# Mirage

**Status: planned; no implementation in this directory yet.**

Role: B — Adversarial AI Lab & Mirage. Branch: `feat/lab-mirage`. Tracking: [#10](https://github.com/Youssef-Boussabah/AEGIS/issues/10). This describes responsibility, not a person assignment.

## First delivery

After the first Lab comparison works, implement one deterministic harmless decoy and a matched disabled control.

## Acceptance and boundaries

Verify functional equivalence, final-artifact retention and overhead before evaluating reconstruction effects. Role A owns shared LLVM implementation changes. Keep application-specific setup outside generic decoy logic.

Read [AGENTS.md](../../AGENTS.md), [architecture](../../ARCHITECTURE.md), [the four-role plan](../../docs/TEAM_WORKSTREAMS.md) and [contribution instructions](../../CONTRIBUTING.md). Detailed requirements are in section 10 of [Technical Documentation](../../docs/AEGIS_TECHNICAL_DOCUMENTATION.pdf). Choose and document implementation tooling as part of the first scoped change; this scaffold does not establish a backend, API or UI implementation.
