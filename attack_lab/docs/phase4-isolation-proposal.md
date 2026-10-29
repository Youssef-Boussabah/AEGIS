# Phase 4: Lab-side execution integration and requirements on Core's isolation runtime

- **Status:** Role B integration implemented against Role A's **uncommitted** Core contract
  (`feat/core-lab-execution`, `core/docs/lab-execution-contract.md`,
  `docs/adr/0004-isolated-candidate-execution.md`, ADR status **Proposed**). Nothing is compiled or run.
- **Date:** 2026-10-29. Branch `feat/lab-behavior-scoring`, base `597f747`.
- **Supersedes:** the earlier revision of this file, which proposed a Lab-owned worker and a Lab
  authorization record. Both moved to Core, as follows:
  - The isolation runtime (gVisor `runsc`, systrap, rootless, one transient systemd user scope per
    sandbox) is now **Role A's**, specified in ADR 0004.
  - Execution authorization is now **Core's grant** only.

## 1. What the Lab does now

| Concern | Owner | Lab implementation |
| --- | --- | --- |
| Hidden suite, expectations, comparison, scoring | Lab (trusted coordinator) | `hidden_suite`, `behavior_score`; expectations never leave the coordinator |
| Execution permission | **Core** (gates 1–3 plus `CandidateExecutionGrant`, re-checked before every stage) | none; the Lab's former `aegis.lab.candidate-execution-authorization.v1` is **removed** |
| Grant describes the Lab's inputs | Lab (Core cannot see Lab files) | `core_execution.check_grant_binding`; see §2 |
| Session, budgets, hashing, binary provenance | Core (`open_session`, `CandidateExecutionSession`) | `core_execution.CoreSessionWorker` forwards each stage and cross-checks every returned record |
| Isolation runtime | Core (planned; refuses with `SANDBOX_UNAVAILABLE`) | none; `runtime=None` always means Core's configured runtime |

### Checks the Lab applies before contacting Core

These checks run before any Core session is opened, and for a pair before the output directory exists.
Each failure raises `ExecutionRefused` with a `grant_*` code.

- `authorization.reference` equals the manifest's authorization reference.
- `lab_bindings` equal what the Lab computes: pair id, the hidden-suite file SHA-256,
  `policy.sha256()` and `scorer_configuration_sha256(policy)`. Core records these but cannot verify them.
- Each scored trial is listed:
  - `candidate_id = trial_id`;
  - `candidate_sha256` = SHA-256 of the exact candidate source in the verified reconstruction record;
  - `target_sha256` = that trial's manifest `final_artifact_sha256`. Core cannot verify the target.
- Stages include `compile` and `execute`. The flags equal the policy flags exactly. The grant's compile and
  execute limits equal the policy's limits exactly, so the scored limits are the policy's.
- `max_executions_per_candidate` covers the whole suite. `max_total_wall_ms` covers one compilation plus
  every case for **all** scored trials.

Then Core decides: `authorize_candidate_execution` (gates, window, ceilings), then `open_session`
(binding and runtime preflight). Core refusals become `ExecutionRefused("core_refused", (reason,))` or
`ExecutionRefused("sandbox_unavailable", blockers)`.

### During a run

- One Core session per scored trial, each with its own runtime instance.
- A runtime injected by the caller must attest `test_double` (`injected_runtime_not_test_double`). Only
  Core's configured runtime may attest isolation. Reusing one runtime instance for both trials is refused
  (`runtime_reused`).
- The attestation must match the policy's runtime, including the runtime and **rootfs** digests (now
  pinned in `aegis.lab.sandbox-policy.v1`), and its compiler. A mismatch is `worker_preflight_failed`.
- Every Core record is re-checked: stage, candidate id and digest, grant digest, session, binary digest,
  exact arguments and attestation. A mismatch is the infrastructure failure `core_record_mismatch`.
- Infrastructure outcomes are recorded, never scored:
  - Core `SANDBOX_FAILED` becomes `infrastructure_failure`, carrying the same failure code.
  - A Core refusal in mid-run (for example, the grant expired between cases) becomes `incomplete`, with
    `stop_reason: core_refused` and `refusal_reason`.
  - A failed session close is a failed cleanup and overrides any match.
- Score records carry the grant id, digest and authorization reference, and the Core session id. They
  carry each Core record's id and canonical digest, not the full record: full records contain the hidden
  case arguments, observed outputs and unbounded diagnostics.

## 2. Interface items with Role A (resolved in Role A's current worktree)

1. **Translation units: resolved.** `session.compile` now takes an explicit `translation_units` list.
   - The Lab passes `["aegis_harness.c", "aegis_candidate_unit.c"]`. `candidate.c` is staged, and the
     candidate unit includes it after the interface prototype; it is never compiled on its own.
   - `CompileRequest` refuses any selection that lists the candidate.
   - Every compile record must report exactly these units, or it is `core_record_mismatch`.
2. **Grant-wide budgets: resolved.** Core keeps a persistent, file-locked ledger per grant
   (`lab-grants/<grant_id>/` under the store root), and it binds an id to the first grant contents that
   used it.
   - The Lab reads it before opening any session. A grant whose remaining budget cannot cover the trials
     is refused upfront (`grant_budget_insufficient` with `compilations_already_used`,
     `executions_already_used` or `wall_already_reserved`). A reused id with other contents is refused
     with `core_refused (grant_ledger_conflict)`.
   - Budget consumed by another holder mid-run becomes `incomplete` / `core_refused` with Core's reason.
   - Interrupted runs keep their reservations. The Lab never resets or bypasses the ledger.
   - A ledger storage failure mid-run is the infrastructure failure `core_storage_failed`.
3. **Interrupted preflight: resolved.** Core now releases the runtime on any failure or interruption.
4. **Record binding.** Every Core record is rejected unless it matches the request exactly:
   - the authorized candidate (id and digest);
   - the grant (id, digest, Lab bindings, budget counters within the grant);
   - the run (session, attestation, binary digest, arguments);
   - the policy (limits, flags, translation units, support-file digests).
5. **Firecracker backend: supported.**
   - The Lab policy accepts `runtime.name = "firecracker"` (`platform: kvm`, rootless, systemd user
     scope). It pins every attested identity:
     - the Firecracker binary;
     - the read-only guest rootfs;
     - the guest kernel;
     - the guest agent;
     - the containment-verification report.
   - Each identity is compared exactly with Core's attestation; any difference is
     `worker_preflight_failed` / `runtime_mismatch`. gVisor pins no guest kernel or agent. The test
     double pins nothing.
   - A caller-injected runtime may still only attest `test_double`.
6. **Host enforcement: validated and recorded separately.** Score records keep three quantities apart.
   - **Granted** (`granted_*_limits`): what the grant allows, which equals the policy. This is the request.
   - **Enforced** (`enforced_*_limits`): the cgroup read-back and microVM configuration from Core's
     `host_enforcement`, in the deterministic result.
   - **Measured** (`run.host_accounting`): host CPU, memory peak and OOM kills, one entry per Core record.

   The Lab never equates enforced with granted, and rejects as `host_enforcement_invalid`:
   - a missing observation from an isolating runtime;
   - any enforcement claim from a test double;
   - swap other than 0;
   - a scope smaller than the microVM;
   - a CPU quota above the vCPUs;
   - a microVM without room for the granted memory plus scratch;
   - enforced values that change between invocations of the same stage.

   Linux cgroup v2 `memory.peak` may exceed `memory.max`, including during OOM.
   Peaks remain measured accounting and are never used as proof of fabricated limits.
   Guest-reported process results remain distinct from host CPU/memory/OOM observations.
   A guest-held vsock HMAC key authenticates a channel; it does not prove guest integrity.
   Scores therefore do not establish independently verified reconstruction success.

   Full canonical Core records now remain available privately on score objects and
   in paired score directories (`<variant>-core-records/<sha256>.json`, directories
   0700, files 0600). Reload verification checks them against existing score references.
   They include case arguments and observed bytes, never hidden expected answers or
   the suite/reference implementation. Keep these archives out of attacker workspaces.

   A pair whose enforced limits differ between variants is `not_comparable`
   (`enforced_*_limits_differ`).
7. **Still open, not blocking:** Core's attestation still carries no limit values of its own; per-stage
   enforcement arrives only in `host_enforcement`.
8. **Answers to the contract's questions:**
   - `candidate_id = trial_id` is sufficient.
   - Bytes *captured* is the right meaning for stderr.
   - `aegis_lab` imports `aegis_core` directly, so the Role B PR merges after the Core PR.

## 4. Gates still closed

Execution is refused by Core's configured runtime (`SANDBOX_UNAVAILABLE`). Its blockers are
`isolation_adr_not_accepted`, plus `containment_unverified` for Firecracker, or
`isolated_runtime_not_implemented` and `runsc_not_installed` for gVisor. Before any candidate is compiled or run:

- ADR 0004 approvals A1–A5: design, `runsc` installation, rootfs choice, residual risk, and the V1–V11
  canary verification;
- Role A's runtime implementation.

Phase 4 acceptance additionally needs one end-to-end run with trusted canary candidates in the approved
runtime: a matching candidate, a mismatching one, and a failing compile.
