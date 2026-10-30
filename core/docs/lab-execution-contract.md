# Lab candidate execution: Core integration contract

Contract `aegis.core.isolated-worker.v1`, grant `aegis.core.candidate-execution-grant.v1`, record `aegis.core.candidate-execution-record.v1`.
Owner: Role A (Core). Consumer: Role B (`attack_lab/`). Design: [ADR 0004](../../docs/adr/0004-isolated-candidate-execution.md), status **Proposed**.

## Status in this revision

| Part | State |
|---|---|
| Gates 1–3, grant model, strict grant parsing, authorization decision | implemented and tested (`aegis_core.lab_authorization`) |
| Session: per-stage re-authorization, binding, budgets, hashing, records, fail-closed error handling | implemented and tested against a scripted double (`aegis_core.lab_execution`) |
| Static host prerequisite probe | implemented (`aegis_core.lab_host`, `python -m aegis_core.lab_host`) |
| Firecracker backend, guest agent, containment driver | implemented and fixture-tested; **no real VM validation**. Configured execution refuses until ADR 0004 is accepted and a matching passing report is pinned. gVisor remains unimplemented. |

Normal configured candidate execution remains disabled. Validation mode is separate and requires explicit operator approval to launch VMs with trusted canaries.

## Dependency direction

`aegis_lab` may import `aegis_core` (pydantic and stdlib only). Core never imports `aegis_lab`. All values cross as the Core types below. Core does not read Lab files (manifest, suite, policy).

## Lifecycle

```python
from aegis_core.config import load_config
from aegis_core.lab_authorization import LabBindings, load_grant
from aegis_core.lab_execution import SourceFile, open_session
from aegis_core.lab_limits import CompileLimits, SandboxLimits

config = load_config(path)                        # operator's aegis.toml
grant = load_grant(grant_path)                    # strict: bounded, no dup keys, no NaN
bindings = LabBindings(pair_id=..., hidden_test_suite_sha256=..., sandbox_policy_sha256=..., scorer_configuration_sha256=...)

with open_session(config, grant, lab_bindings=bindings) as session:   # gates 1-3, window, ceilings, runtime preflight
    session.attestation                           # RuntimeAttestation: what the runtime established
    result = session.compile(trial_id, SourceFile(name="candidate.c", data=src),
                             support_files=[SourceFile(name="aegis_harness.c", data=h),
                                            SourceFile(name="aegis_candidate_unit.c", data=u)],
                             # explicit and ordered; candidate.c is only #included by the unit
                             translation_units=["aegis_harness.c", "aegis_candidate_unit.c"],
                             flags=policy.compiler.flags, limits=CompileLimits(...))
    if result.binary is not None:
        for case in suite.cases:                  # expectations stay in the Lab coordinator
            record = session.execute(trial_id, result.binary, args=[str(a) for a in case.arguments],
                                     limits=SandboxLimits(...))
            record.observation.stdout             # compare in the coordinator, never in Core
```

A session serves one grant; a grant may have several sessions (the Lab opens one per trial). **Budgets are per grant**, summed over all its sessions and processes in a persistent ledger under the store root (`lab-grants/<grant_id>/`); a new session or a restart never resets them. A grant id is bound to the first grant digest that used it: a different grant with the same id is refused (`grant_ledger_conflict`). Before **every** stage, Core re-checks all three gates and the grant window. After `close()`, or after any `SANDBOX_FAILED`, the session refuses all further work (`session_closed` or `session_failed`).

If `open_session` fails or is interrupted (`KeyboardInterrupt`, `SystemExit`) after it has touched the runtime, Core closes the runtime before the exception propagates unchanged. A refusal before the preflight (gates, bindings, ledger conflict) never touches the runtime.

### Translation units

`compile` requires `translation_units`: an ordered list of 1–16 names chosen from the submitted files, `.c` only, each listed once. All submitted files are staged under their own names; **only the listed units are passed to the compiler** (`CompileJob.compiler_arguments()` = `[*flags, -o, candidate, *translation_units]`). With the Lab's layout, list `aegis_harness.c` and `aegis_candidate_unit.c` and **not** `candidate.c`, which the unit includes. Core does not parse `#include`; a candidate both included and listed is defined twice and fails as an ordinary compile observation. The candidate is digest-bound either way. Invalid selections are `INVALID_REQUEST` and reserve no budget.

### Complete compilation binding

Each `candidates[]` entry may include `compilation_bundle_sha256`. For multi-file
compilation it is required. The operator's grant issuer computes it from the
reviewed files and unit selection **before** issuing the grant:

```python
from aegis_core.lab_authorization import compilation_bundle_sha256
bundle_digest = compilation_bundle_sha256(
    {"candidate.c": candidate_bytes, "aegis_harness.c": harness_bytes,
     "aegis_candidate_unit.c": unit_bytes},
    ["aegis_harness.c", "aegis_candidate_unit.c"],
)
# Include bundle_digest in that candidate's compilation_bundle_sha256 field.
```

The digest is SHA-256 of sorted-key compact UTF-8 JSON (no ASCII escaping) with
`files` mapping each exact name to the SHA-256 of its bytes, and
`translation_units` holding the exact ordered list. File submission order does
not affect it. Adding/removing/renaming/changing any file, or changing the unit
selection/order, refuses with `compilation_bundle_mismatch` before budget
reservation or runtime invocation. Missing digests allow only `candidate.c`
compiled alone, with no support files; other layouts refuse with
`compilation_bundle_required`. There is no test-runtime exception.

Absent/null bundle fields are omitted only from grant digest canonicalization,
preserving legacy v1 grant identities and ledger usage. Adding a digest changes
the grant identity: reusing its old id fails with `grant_ledger_conflict`. Never
delete a ledger to migrate a grant; the operator must review any reissued grant
and account for already-consumed budgets.

## Grant (`CandidateExecutionGrant`)

The grant replaces nothing in the Lab. It is the **Core gate** for execution. The Lab's `CandidateExecutionAuthorization` remains Lab-side audit metadata. Derive the grant from the same reviewed decision:

| Grant field | Source in the Lab | Checked by Core |
|---|---|---|
| `authorization` (`AttackLabAuthorization`, `attested_at` explicit) | approver; `reference` should equal `manifest.authorization.reference` (Lab checks) | gate 2: present, unexpired; `attested_at ≤ valid_from`; grant must not outlive it |
| `permitted_targets` | `manifest.target.final_artifact_sha256` of each trial | every target used by a candidate and every candidate target listed |
| `candidates[]`: `candidate_id`, `candidate_sha256`, `target_sha256`, `compilation_bundle_sha256` | `trial_id`, exact source digest, target, reviewed bundle digest | Core compares source bytes, every named file and the ordered units |
| `stages` | `["compile", "execute"]` (`execute` requires `compile`) | per call |
| `compile_flags` | `policy.compiler.flags` (same allowlist as the Lab's) | exact list equality, including order |
| `compile_limits`, `execute_limits` | `policy.compile`, `policy.execute` (same field names and ranges) | ≤ operator ceilings in config; requests ≤ grant |
| `max_compilations_per_candidate` (1–16), `max_executions_per_candidate` (≥ 1 with execute), `max_total_wall_ms` | policy `max_cases` and `max_total_wall_ms` | per candidate **across all sessions of the grant**; the wall budget is the sum of requested `wall_ms` over all sessions, reserved before a run and kept on failure |
| `lab_bindings` | `pair_id`, suite digest, `policy.sha256()`, `scorer_configuration_sha256(policy)` | must equal the `lab_bindings` passed to `open_session`; **not verifiable by Core**, recorded as Lab declarations |
| `valid_from`, `expires_at` | review decision | `≤ 7 days`, re-checked per stage |

`grant_sha256(grant)` is SHA-256 over sorted-key compact UTF-8 JSON. It identifies the grant; it does not authenticate it. A grant is operator-attested, not signed.

Operator config, which must be enabled explicitly:

```toml
[attack_lab]
enabled = true                      # gate 1 (strict boolean)
[attack_lab.candidate_execution]
enabled = true                      # gate 3 (strict boolean), off by default
# compile_ceiling / execute_ceiling default to conservative values (aegis_core.lab_limits)
```

## Mapping onto the Lab worker protocol (`aegis.lab.candidate-worker.v1`)

A Lab-side adapter class implementing the Lab's worker interface over a Core session needs no Core change:

| Lab | Core |
|---|---|
| `preflight(policy) -> WorkerPreflight` | `session.attestation`: `compiler_*`, `network`; `limits_enforcement`: `verified_by_cgroup_readback` ↔ `verified_by_runtime`, `not_enforced_test_double` ↔ `not_enforced_test_double`; `identity_observed` ↔ `attestation.isolation_verified` |
| `CompileRequest(files, argv, output, limits)` | `session.compile(trial_id, candidate, support_files=..., translation_units=..., flags=..., limits=...)`. Core builds argv (`[compiler, *flags, -o, candidate, *translation_units]`) and fixes the output name; non-unit files are staged only. Names match `^[A-Za-z0-9][A-Za-z0-9_-]{0,62}\.[ch]$`; the candidate is the single `.c` file passed as `candidate`; up to 15 support files, at most 1 MiB each and 4 MiB total. |
| `CompileObservation` | `result.record.observation` (`status`, `exit_code`, `signal`, `limit`); `diagnostics` = `observation.stderr`, `diagnostics_truncated` = `stderr_truncated`; `binary` = `result.binary` |
| `ExecuteRequest(binary, argv, limits)` | `session.execute(trial_id, binary, args=argv[1:], limits=...)`. `argv[0]` is fixed by Core. Arguments match `^[A-Za-z0-9_.+:=,-]{1,256}$`, at most 64, and are never echoed in errors. |
| `ExecuteObservation` | `record.observation`: `stdout`, `stdout_truncated`; `stderr_bytes` = `len(observation.stderr)` (bytes captured, at most the limit) |
| `WorkerError(code)` | `AegisError` `SANDBOX_FAILED`, `details.failure` ∈ `sandbox_start_failed`, `sandbox_failed`, `resource_enforcement_failed`, `cleanup_failed`, `protocol_violation` (the same set) |
| `ExecutionRefused` | `AegisError` `AUTHORIZATION_REQUIRED`, `details.reason` ∈ `REFUSAL_REASONS`; or `SANDBOX_UNAVAILABLE`, `details.blockers` |

## Error and outcome semantics

- `AUTHORIZATION_REQUIRED` (gates, grant, binding, budgets) and `INVALID_REQUEST` (malformed sources, arguments or limit types): nothing was started.
- `SANDBOX_UNAVAILABLE`: no verified runtime. Nothing was started.
- `SANDBOX_FAILED`: infrastructure failure. **Never a candidate outcome or a score.** The session is poisoned.
- Candidate behavior is an observation: `exited` (any code), `signaled`, `timeout`, `limit_exceeded` with `limit` ∈ `cpu, memory, processes, scratch, stdout, stderr, binary` (`binary` only on compile).

## Records (`CandidateExecutionRecord`)

Each record carries the grant id and digest, the Lab bindings, the candidate id and digest, support-file digests, the translation units (compile only), flags, binary digest and size, args, limits, grant-wide budgets used (`compilations_used`, `executions_used`, `wall_ms_reserved`, summed over all sessions of the grant), the runtime attestation, the observation, and the stdout/stderr digests. Bytes serialize as base64 in JSON.

- **Computed or checked by Core:** every digest, limits, budgets, timestamps, the stage and grant binding.
- **From the runtime:** the observation. With `runtime.runtime == "test_double"`, it is scripted and **never evidence**.
- **Lab declarations:** `lab_bindings`, bound and recorded, not verified.

Core returns records; the merged Lab adapter retains canonical bytes as private
evidence and publishes their digests/references. No new public API exposes them.

## Testing against the contract

`aegis_core.testing.scripted_runtime.ScriptedIsolationRuntime` implements the runtime interface, **never compiles or runs anything**, and attests `runtime="test_double"`, `isolation_verified=False`. Pass it as `open_session(..., runtime=...)` in tests only. Records made with it must stay labeled as test-double results.

## Firecracker backend

Selected with `[attack_lab.candidate_execution] runtime = "firecracker"` and a `[attack_lab.candidate_execution.firecracker]` section. Every artifact is pinned by absolute path and SHA-256: the Firecracker binary, bwrap, the guest kernel, the read-only guest image, the guest agent and the compiler identity. The section also sets the private `state_dir` and `containment_verification_sha256`. The session, grant, ledger and record APIs are unchanged.

- **Attestation:** `runtime="firecracker"`, `platform="kvm"`, `rootless=true`, plus `guest_kernel_sha256`, `guest_agent_sha256` and `containment_verification_sha256` (all required for this runtime, `null` for others).
- **Observations:** `host_enforcement` carries the scope limits read back before the job was sent (`memory_max_bytes`, `memory_swap_max_bytes`, `pids_max`, `cpu_quota_us`/`cpu_period_us`), the VM's `vm_memory_mib`, `vcpu_count` and block rate limits, and host accounting (`host_cpu_usec`, `host_memory_peak_bytes`, `host_oom_kills`). It is `null` for the test double.
- **Host-observed outcomes:** no result within `wall_ms + host_grace_ms` gives `timeout`; a scope OOM gives `limit_exceeded`/`memory`, including when a guest returns success and a binary. Host facts take precedence. Other protocol/startup failures are `SANDBOX_FAILED`.
- **Asset identity:** preflight copies and hashes the four pinned host artifacts into sealed anonymous files; launch uses held `/proc/<Core pid>/fd` aliases. Metadata checks remain an early refusal, and replacement or in-place writes cannot change the launched bytes. The combined snapshot bound is 2 GiB of additional host memory outside the VM scope. `host_asset_binding=sealed-memfd-v1` is part of report identity, invalidating older reports. Actual namespace access and launch remain to be validated.
- **Guest CPU/output:** aggregate job `cpu.stat` is polled every 10 ms throughout supervision, killing the job at its CPU budget; polling may overshoot. Accounting/read failures fail closed. After the leader exits, descendants are killed and stdout/stderr drain to EOF with a cap+1 bound. Closed outputs do not stop wall/CPU supervision.
- **Cleanup:** failed termination, verification or state removal retains tracking and state for retry, blocks further VM runs, and surfaces `cleanup_failed`. `close()` retries incomplete cleanup, including after session close failure; successful cleanup is idempotent.
- **Guest inputs:** compile sends the staged files, translation units, flags and limits; execute sends the binary, the case arguments and limits. Nothing else, and never expectations.
- **Availability:** refused in this revision (`isolation_adr_not_accepted`). The backend's own preflight additionally requires a pinned, passing candidate-guest containment report bound to the running configuration (`containment_report_path` + `containment_verification_sha256`). Otherwise it reports `containment_unverified`, `containment_report_mismatch`, `containment_report_unreadable` or `containment_report_rejected`.

The cached merged Role B implementation at `origin/dev/integration` (`470f96a`)
already accepts Firecracker attestation and requires host enforcement records.

## Role B coordination

Role B's merged worker uses these conventions:

1. `candidate_id = trial_id` is sufficient: one candidate per trial, no retries.
2. `stderr_bytes` = bytes captured is sufficient.
3. `aegis_lab` imports `aegis_core` directly.

**Required grant-issuer migration:** supply each candidate's complete bundle
digest, including its generated harness and candidate unit. The merged worker
already passes those files and the correct units; its existing fixture grants
do not bind them and are now safely refused. Its two scoring suites pass with
reviewed bundle-bound fixture grants (see the review report). Role B source and
tests were not modified. Grant-wide budgets, private-record checks and host
enforcement mapping retain their current interfaces.
