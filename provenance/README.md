# Signature

**Status: planned; no implementation in this directory yet.**

Role: D — Signature, Sentinel & Verification. Branch: `feat/signature-sentinel`. Tracking: [#12](https://github.com/Youssef-Boussabah/AEGIS/issues/12). This describes responsibility, not a person assignment.

## First delivery

Implement an offline signed, versioned artifact manifest and verification against an explicitly trusted public key.

## Acceptance and boundaries

Use a maintained cryptographic library. Test altered artifacts/manifests, wrong keys, malformed envelopes and unsupported versions. Keep private keys outside Git and logs. Sign after artifact bytes are final. Coordinate Core linkage with role A; watermark research is separate.

Read [AGENTS.md](../AGENTS.md), [architecture](../ARCHITECTURE.md), [the four-role plan](../docs/TEAM_WORKSTREAMS.md) and [contribution instructions](../CONTRIBUTING.md). Detailed requirements are in section 10 of [Technical Documentation](../docs/AEGIS_TECHNICAL_DOCUMENTATION.pdf). Choose and document implementation tooling as part of the first scoped change; this scaffold does not establish a backend, API or UI implementation.
