# Adversarial Lab

**Status: planned; no implementation in this directory yet.**

Role: B — Adversarial AI Lab & Mirage. Branch: `feat/lab-mirage`. Tracking: [#10](https://github.com/Youssef-Boussabah/AEGIS/issues/10). This describes responsibility, not a person assignment.

## First delivery

Build an authorized, reproducible baseline/protected reconstruction comparison using Ghidra and a recorded model configuration. Keep hidden tests separate, use equal attacker budgets, and isolate compilation/execution of generated candidates.

## Acceptance and boundaries

Both Core authorization gates must stay enforced. Record hashes, tool/model versions, budgets, outcomes, errors and independent scoring. Coordinate trial manifests and adapter integration with role A. The Core adapter runner is not an execution sandbox.

Read [AGENTS.md](../AGENTS.md), [architecture](../ARCHITECTURE.md), [the four-role plan](../docs/TEAM_WORKSTREAMS.md) and [contribution instructions](../CONTRIBUTING.md). Detailed requirements are in section 10 of [Technical Documentation](../docs/AEGIS_TECHNICAL_DOCUMENTATION.pdf). Choose and document implementation tooling as part of the first scoped change; this scaffold does not establish a backend, API or UI implementation.
