# ADR 0002: LLVM Shield integration through the existing adapter protocol

- **Status:** Accepted
- **Date:** 2026-10-27
- **Scope:** milestone 002; LLVM integration boundary and success semantics

## Context

Core runs registered executables through `aegis.adapter.v1`. Shield is an LLVM
plugin with independent integer-versioned config/report schemas and no established
security property. A successful opt exit can mean no annotated or eligible sites
were transformed. Core's v1 contract has no protection-effectiveness field.

## Decision

1. Own the integration under `protectors/llvm/adapter/` in the LLVM integration
   module. Ship a standalone stdlib Python protocol executable; core/API/CLI
   never import it. Registration remains an explicit operator action.
2. Preserve both existing schemas and the protocol. Explicitly translate core
   `seed`, `max-sites`, `enabled` into a version-1 Shield config. Require a
   decimal uint64 **string** seed and reject unknown or mistyped options.
3. Limit inputs to textual IR. Stage a hash-checked copy and config under fixed
   relative names so untrusted paths/options cannot enter a pass pipeline.
   Accept only operator-configured LLVM 22 tools and plugins. Never compile or
   execute a submitted native binary.
4. Require a locally schema-validated, invocation-consistent report with
   nonzero transformation sites, nonempty bounded artifacts, changed IR bytes,
   and a separate LLVM verifier invocation. Zero transformations fail with
   adapter code `NO_TRANSFORMATIONS_APPLIED`, preserved in core's existing
   `ADAPTER_FAILED` error details. Success makes no security claim.
5. Keep LLVM in the core-owned process group so the existing timeout kills all
   descendants. Use minimal tool environments, bounded file-backed diagnostics,
   POSIX per-file limits, safe paths and exclusive artifact publication.
6. Publish original Shield JSON and transformed IR as separate outputs. Core
   computes all artifact hashes. Shield facts remain adapter-source evidence.

## Consequences

No changes to core models, protocol, API, CLI or backend schemas are needed.
The new suite exercises the real orchestrator/CLI/backend together, separately
from the standalone Shield CTest suite. LLVM major versions other than 22,
bitcode input, native execution and attack-lab are unsupported. Operators must
keep the store private and provide isolation beyond this adapter when processing
hostile IR; the adapter is not a compiler sandbox or an aggregate resource quota.
