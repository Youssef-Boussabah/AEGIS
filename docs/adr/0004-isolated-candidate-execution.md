# ADR 0004: Isolated compilation and execution of untrusted reconstruction candidates

- **Status:** Proposed. Not accepted. Nothing in this ADR authorizes compiling or running generated code.
- **Date:** 2026-10-29
- **Owner:** Role A (Core Platform, Shield & Integration). Affected owner: Role B (`attack_lab/`).
- **Scope:** Phase 4 behavioral scoring: the trust boundary, the isolation runtime, resource and process controls, cleanup and failure semantics, and Core's authorization for candidate execution.

## Review amendment (2026-10-29; still proposed, no launch approval)

The implementation review and exact validation results are in
[CORE_EXECUTION_REVIEW.md](../CORE_EXECUTION_REVIEW.md). The following changes
are implemented and fixture-tested, **not real-VM-validated**:

- Multi-file grants bind all named compilation files and the ordered units via
  `compilation_bundle_sha256`. Absent bindings permit only `candidate.c` alone;
  legacy single-source grant digests and persistent usage remain unchanged.
- Guest supervision polls aggregate job CPU usage while the job runs (10 ms,
  possible overshoot), fails closed on accounting errors, kills descendants
  after leader exit and drains bounded output through EOF.
- Failed cleanup retains process/scope tracking, directories and asset handles,
  blocks further VM runs, and retries through `close()`.
- Host OOM and deadline observations override guest-provided success/results.
- The four pinned host assets are copied, hashed and sealed in anonymous memory
  files; held `/proc/<Core pid>/fd` aliases replace mutable launch paths.
  The combined bound is 2 GiB additional host memory outside VM scopes, now
  reported by the plan. Host OS libraries and systemd are trusted dependencies.
  `host_asset_binding=sealed-memfd-v1` changes containment-report identity.
- The guest package spec requests full `python3` for the required stdlib modules.

Consequences: grant issuers need a reviewed bundle-digest migration; existing
multi-file fixture grants are refused. The updated boot path and guest runtime
must pass C0, F1–F5 and V1–V11 on the actual host with pinned assets before
acceptance. No VM was launched, no image built/downloaded, and no generated
candidate executed by this review. This amendment does not accept ADR 0004.

## Context

Phase 4 scores AI-generated reconstructions by compiling each candidate C source and running it against independent hidden tests. Candidate source is **untrusted code**: it is produced by a model from attacker-visible data, and it must be treated as hostile. It may try to read host files, use the network, exhaust memory, CPU, processes, disk or output, escape the sandbox, outlive its run, or learn the hidden test expectations.

The present Core adapter runner (`aegis_core.adapter`) is bounded execution, not a sandbox: it has a timeout, a process group, a minimal environment and argv arrays, but no filesystem, network, syscall or resource isolation. The Ghidra worker has the same property. Neither may run candidates.

### Host facts (verified 2026-10-29 on the development workstation, kernel 7.2.3-1-cachyos, x86-64)

The earlier Codex audit was re-checked from this session with read-only probes and trusted system binaries only. No generated code was compiled or run.

| Fact | Result | Notes |
|---|---|---|
| gVisor `runsc` | **not installed** | Matches the audit. |
| Docker / containerd / runc / bwrap | binaries present | Docker and containerd inactive; the user is not in the `docker` group. Not used (see Alternatives). |
| Firecracker, nsjail, minijail, podman, crun | not installed | |
| `/dev/kvm` | **usable** (`KVM_GET_API_VERSION` = 12, mode `0666`) | **Differs from the audit**, which found no KVM in its session. |
| cgroup v2 | yes | |
| Login-session scope cgroup | not writable | Matches the audit ("no writable delegated cgroup subtree" in that session). |
| `user@1000.service` | `Delegate=yes`, delegated controllers `cpu memory pids` | **`io` is not delegated.** |
| Transient `systemd-run --user --scope` | **limits enforced** | `MemoryMax=64M, MemorySwapMax=0`: a trusted 256 MiB writer was OOM-killed (exit 137); a control run without limits succeeded. `TasksMax=16`: 15 of 40 forks succeeded. `cpu.max` read back as `50000 100000` for `CPUQuota=50%`. |
| Unprivileged user namespaces | enabled (`max_user_namespaces` = 125415) | Namespace availability alone is not taken as enforcement. |
| LSMs | `capability, landlock, lockdown, yama, bpf` | Yama `ptrace_scope` = 1. No AppArmor/SELinux. |
| Seccomp | available (`kill_process`, `trap`, `user_notif`, …) | |

These facts hold for this host and this login session. They must be re-established on any other host (see *Preflight*), and `aegis_core.lab_host` reproduces the static part of the check.

## Decision

### 1. Trust boundary

```
 trusted (host, operator uid)                       │ untrusted (inside gVisor sandbox)
                                                    │
 Lab coordinator (Role B) ── hidden suite, expected │
   values, verdicts: never cross this line ──────── │
        │ CompileRequest / ExecuteRequest (bytes)   │
        ▼                                           │
 Core CandidateExecutionSession (Role A)            │
   gates 1+2+3, grant binding, budgets, hashing     │
        │                                           │
        ▼                                           │
 Core gVisor runtime (Role A, planned)              │
   systemd user scope ── runsc (sentry, gofer) ─────┼─▶ compiler + candidate source
   bounded pipes ◀──── stdout / stderr / status ────┼── candidate binary + one case's argv
```

- Trusted: the operator account, `aegis.toml`, the Lab coordinator and hidden suite, Core, the pinned `runsc` binary and the read-only sandbox root filesystem.
- Untrusted: candidate source, all compiler behavior on it, the produced binary, and every byte that comes back from a sandbox (exit status, stdout, stderr, binary).
- Hidden expectations, the suite, the manifest and verdicts never enter a sandbox. A sandbox gets the candidate source and fixed harness units (compile), or one binary and one case's arguments (execute). Comparison happens only in the Lab coordinator.

### 2. Runtime: gVisor `runsc`, systrap platform, rootless, inside a transient systemd user scope

Evaluated first as requested, gVisor is **viable on this host only with an outer cgroup**: rootless `runsc` cannot manage cgroups itself, and the session scope is not delegated. The verified `systemd-run --user --scope` mechanism supplies the cgroup.

- `runsc` from a **pinned upstream release**, installed **user-locally without sudo** (for example under `~/.local/opt/gvisor/<release>/`), with its published checksum verified at install and its SHA-256 recorded in config and in every execution record. The installation needs approval (A2 below).
- Platform **systrap** (the default). KVM is usable on this host and is an optional later alternative. It is not adopted without a separate verification.
- **Rootless** mode, with gVisor's own cgroup handling disabled. All `runsc` processes (sentry, gofer, systrap stubs) run inside one transient scope created per sandbox.
- **One fresh sandbox per compilation and per test case.** No sandbox, scratch directory or runtime state directory is reused.

### 3. Filesystem

- Root filesystem: a **dedicated, operator-built, read-only directory** that contains the compiler, its headers and libraries, and nothing else. It is identified by a content manifest digest recorded in config and records. No `/home`, no host `/etc`, no sockets, no `/sys` from the host. (Option for approval A3: an interim read-only bind of the host `/usr` with fixed symlinks. It is weaker because it exposes the host's installed toolchain and package set.)
- All writes go to **sandbox memory** (gVisor in-memory root overlay and an in-sandbox `/tmp` tmpfs with a size bound). They are charged to the scope's `MemoryMax`, so disk usage cannot grow on the host.
- **No writable host mount.** The only host inputs are the read-only rootfs and, for execution, one read-only single-file mount of the binary under test (a host file written by Core into a private 0700 directory).
- Results leave the sandbox **only through bounded pipes**: compile diagnostics on stderr; the binary on stdout of a fixed in-sandbox wrapper that runs the compiler and then emits the output file; candidate stdout and stderr on execution. The host reads at most limit + 1 bytes and kills the scope on overflow.
- Host-side runtime state (`runsc --root`, bundle, `config.json`) lives in a fresh private 0700 scratch directory per sandbox and is removed after the scope is gone.

### 4. Network

`--network=none`: the sandbox has only its own loopback. No host network namespace, DNS, Unix sockets or host FIFOs are passed. Live provider inference (Nebius) stays disabled and is unrelated to this runtime.

### 5. Process identity and capabilities

- OCI process: non-root uid/gid inside the sandbox, **empty capability sets**, `noNewPrivileges`, an **empty environment** except a fixed `PATH`, and fixed argv. The compiler argv is `[<compiler from config>, *CompileJob.compiler_arguments()]`, that is `[*flags allowed by the grant, -o, candidate, *translation_units]`. Every submitted file is staged under its own fixed name so it can be `#include`d; only the explicitly selected `.c` translation units are compiled (see *Translation units* below). Execution argv is `["candidate", *case arguments]`. Case arguments are passed in the OCI `config.json`, never on the host argv.
- The host side never uses a shell and never puts a request value on a host argv.

### 6. Resource limits: every one enforced, not just declared

| Limit | Enforcement |
|---|---|
| memory | scope `MemoryMax` with `MemorySwapMax=0` (verified on this host); covers sentry, gofer, stubs and in-memory filesystems |
| processes | scope `TasksMax` = application limit + a fixed sentry allowance; the in-sandbox application process limit is to be verified (V4) |
| CPU time | scope `CPUQuota` for rate, plus total CPU read from `cpu.stat` and polled; the scope is killed when it is exceeded |
| wall clock | host monotonic timeout, plus scope `RuntimeMaxSec` as a backstop if the Core process dies |
| scratch | in-sandbox tmpfs size bound, plus `MemoryMax` (V5) |
| stdout, stderr, binary | bounded host-side pipe reads; overflow kills the scope and records `limit_exceeded` |
| disk I/O bandwidth | **not enforceable here** (`io` is not delegated). Mitigated because nothing writes to host disk; reads come only from the read-only rootfs. Recorded as a limitation. |

Before a candidate starts, the runtime **reads the applied values back** from the scope's cgroup files (`memory.max`, `memory.swap.max`, `pids.max`, `cpu.max`). Preferred order: `runsc create` inside the scope, read back the limits, then `runsc start`. A mismatch or unreadable value is an infrastructure failure, and the candidate is never started.

### 7. Process containment and cleanup

- Normal exit, timeout, overflow, interruption and Core exceptions all end with `cgroup.kill` (via `systemctl --user kill --signal=SIGKILL` or the cgroup file) on the scope, then `runsc delete --force`, then removal of the scratch directory.
- Cleanup is **verified**: the scope's `cgroup.events` must report `populated 0`, and the scratch directory must be gone. Failed verification is `cleanup_failed`: the session is poisoned and refuses further work.
- `RuntimeMaxSec` bounds a scope's life even if the Core process is killed. A startup sweep removes stale `aegis-lab-*` scopes and scratch directories owned by the user.

### 8. Failure semantics: fail closed

- Gates, grant binding or budget fail → `AUTHORIZATION_REQUIRED` with a stable `details.reason`. Nothing is started.
- Once Core has touched a runtime while opening a session, **any** failure or interruption (including `KeyboardInterrupt` and `SystemExit`) closes that runtime before the exception propagates unchanged.
- Runtime missing, unapproved, a failed preflight or unverifiable limits → `SANDBOX_UNAVAILABLE` with `details.blockers`. Nothing is started.
- A sandbox that fails to start, crashes, violates the worker protocol, fails enforcement read-back or fails cleanup → `SANDBOX_FAILED`. The session becomes unusable. Such a run is **an infrastructure failure, never a candidate outcome or a score**.
- Candidate behavior (compile error, non-zero exit, signal, timeout, limit exceeded) is an **observation**, returned to the Lab and never mapped to success.

### 9. Authorization: three gates plus a bound grant (implemented in Core)

The two existing gates are kept unchanged and are evaluated by the same Core function for attack-lab jobs and for candidate execution:

1. `[attack_lab] enabled = true` (operator).
2. A valid, unexpired `AttackLabAuthorization`.

Candidate execution adds:

3. `[attack_lab.candidate_execution] enabled = true` (operator, off by default). Attack-lab jobs can be enabled without consenting to running generated code.

It also requires a **`CandidateExecutionGrant`** (`aegis.core.candidate-execution-grant.v1`) that embeds the gate-2 authorization and binds:

- permitted final target artifacts, by SHA-256;
- each permitted candidate (`candidate_id`, `candidate_sha256` of the exact untrusted source bytes, and its target);
- the permitted stages (`compile`, `execute`; execute requires compile) and the exact compiler flags;
- resource limits per stage (at most the operator ceilings in config);
- run budgets (compilations and executions per candidate, total wall budget);
- the Lab's declared digests (pair, hidden suite, sandbox policy, scorer configuration);
- a validity window of at most 7 days that never outlives the embedded authorization.

Core re-checks all three gates and the window before **every** stage. It hashes the candidate bytes itself, executes only binaries it produced in the same session, and hashes everything that crosses the boundary.

**Budgets belong to the grant, not to a session.** Compilations and executions per candidate and the total wall reservation are kept in a persistent per-grant ledger (`<store>/lab-grants/<grant_id>/ledger.json`, updated under an exclusive `flock`, atomic replace with fsync). Opening more sessions, or restarting the process, cannot reset them. A grant id is bound to the digest of the first grant that used it; a different grant with the same id is refused (`grant_ledger_conflict`). A missing ledger means unused; a corrupt, oversized or symlinked ledger fails closed (`STORAGE_ERROR`). Reservations are made before a run and never returned.

**Translation units.** `compile` takes an explicit, ordered `translation_units` list: names of submitted `.c` files (never headers, never paths), unique, 1–16. Every submitted file is staged; only the selected units are compiled. Core does not parse `#include`: selecting both a unit that includes the candidate and the candidate itself defines it twice, which is a compile observation, not a Core error. The candidate is bound by digest whether it is compiled directly or included. The selection is recorded in each compile record. Lab-declared digests are bound and recorded, but **Core cannot verify them**. Records say so.

A grant, like `AttackLabAuthorization`, is an **operator-attested record, not a cryptographic credential**. Anyone who can write `aegis.toml` and the grant as the operator user can authorize execution. Sentinel policies, watermarks and provenance signatures are **not** used as security controls here.

### 10. Preflight and verification before acceptance

Execution remains refused (`SANDBOX_UNAVAILABLE`, blockers `isolation_adr_not_accepted`, `isolated_runtime_not_implemented`) until all of the following are true:

1. This ADR is accepted.
2. `runsc` is installed with approval and pinned.
3. The runtime is implemented.
4. The verification suite below passes on the target host, with its exact results recorded.

The suite runs only **trusted canary programs written by Role A**, never generated reconstructions.

| ID | Property verified |
|---|---|
| V1 | no network (connect to a host loopback listener and to an external address both fail) |
| V2 | no host file visibility (`/home`, host `/etc`, the store root and the Core scratch directory are absent) |
| V3 | read-only rootfs; no write reaches the host disk |
| V4 | process limit: a fork bomb is contained, and the host is unaffected |
| V5 | memory and scratch: a memory writer and a tmpfs filler are stopped at the limits |
| V6 | CPU spin is stopped at the CPU limit; a sleep is stopped at the wall limit |
| V7 | stdout, stderr and binary floods are cut at limit + 1 bytes |
| V8 | no capabilities, `NoNewPrivs`, non-root uid inside |
| V9 | killing Core mid-run: `RuntimeMaxSec` and the sweep leave no process, scope or scratch behind |
| V10 | limit read-back mismatch, a missing runsc and a broken rootfs each fail closed without starting the candidate |
| V11 | an orphaned background process outliving the candidate is killed with the scope |

## Alternatives considered

- **Plain subprocess, or the Core adapter runner:** no filesystem, network or syscall isolation. Rejected.
- **bubblewrap + seccomp + user scope:** works rootless and isolates namespaces, but the candidate talks to the host kernel directly. Only seccomp stands between hostile code and kernel bugs. Acceptable only as a fallback if gVisor fails verification, and only with a separate ADR.
- **Docker / runc:** daemon inactive, and daemon access is root-equivalent. Rejected for this host.
- **Firecracker or another microVM (KVM is usable here):** a stronger boundary but more operator setup (kernel, rootfs image, jailer). It is the recommended path if gVisor fails V1–V11, or for a shared or production evaluation host.
- **Dedicated evaluation host or VM account:** strongest operational separation. Recommended before any evaluation that is not a local prototype (see the residual risk below).

## Consequences

- Core gains `aegis_core.lab_limits`, `aegis_core.lab_authorization`, `aegis_core.lab_execution`, `aegis_core.lab_ledger` and `aegis_core.lab_host`, and the store gains `lab-grants/`. It also gains the config section `[attack_lab.candidate_execution]` (off by default) and the error codes `SANDBOX_UNAVAILABLE` and `SANDBOX_FAILED`. The existing two-gate check for attack-lab jobs is unchanged in behavior; it is shared, not duplicated.
- Role B integrates through the contract in [core/docs/lab-execution-contract.md](../../core/docs/lab-execution-contract.md). It does not need to edit Core, and Core does not import `aegis_lab`.
- **Residual risk:** on the development workstation, a gVisor escape combined with a sentry seccomp bypass would run as the operator's user, which can read the operator's files. Accepting this for a local prototype is an explicit operator decision (A4). Anything beyond a prototype should use a dedicated user, VM or host.
- Not enforceable on this host: disk I/O bandwidth (no `io` delegation). Not provided by this design: confidentiality against timing side channels inside one host; authenticity of grants beyond operator file control.

## Approvals required before any candidate is compiled or run

- **A1** Accept this design (gVisor systrap, rootless, inside a systemd user scope; three gates plus a grant).
- **A2** Install a pinned `runsc` release user-locally (no sudo, checksum verified).
- **A3** Choose the root filesystem: a dedicated minimal directory (recommended) or the interim read-only host `/usr`.
- **A4** Accept the residual risk of running on this workstation, or provide a dedicated user, VM or host.
- **A5** Run the V1–V11 canary verification suite (trusted programs only) under the installed runtime.

---

## Amendment 1 (proposed, not accepted): Firecracker microVM backend

- **Status:** Proposed, not accepted. The Core backend is implemented (see *Implementation status* below); Firecracker v1.17.0 is installed by the operator; containment is unverified, and no candidate has run.
- **Date:** 2026-10-29

### Assessment

Firecracker gives each sandbox a KVM hardware-virtualization boundary with a minimal device model, and `/dev/kvm` is usable on this host. This is a stronger guest boundary than gVisor's user-space kernel. **Firecracker alone does not satisfy §3–§8 of this ADR.** The VMM is an ordinary host process: without the jailer it has the operator's full file access and no resource limits. The official jailer, which supplies chroot, namespaces, cgroups and privilege drop, must be started as **root**, which this workstation policy excludes.

| ADR requirement | Firecracker by itself | Required addition |
|---|---|---|
| Resource limits and containment (§6–§7) | guest RAM and vCPU count are bounded; the VMM process is not | the same transient systemd user scope as for gVisor: `MemoryMax` ≥ guest memory + VMM overhead, `MemorySwapMax=0`, `TasksMax`, `CPUQuota`, `RuntimeMaxSec`; `cgroup.kill` plus `populated 0` verification |
| Host filesystem view (§3) | VMM sees everything the operator can | rootless jail: user, mount, PID, IPC and empty network namespaces (for example the installed `bwrap`) exposing only `/dev/kvm`, the read-only kernel and rootfs images, and a private per-run directory for the vsock socket; `no_new_privs` |
| Syscall surface | built-in per-thread seccomp filters | keep them on: never `--no-seccomp`; verify `Seccomp: 2` for the VMM |
| Control surface | HTTP API on a Unix socket | `--no-api --config-file`, one config per microVM; no API socket |
| Network (§4) | no NIC unless configured | configure **no** network device; the VMM's empty network namespace as defense in depth |
| Guest filesystem (§3) | virtio-block drives | rootfs drive with `is_read_only: true`; scratch as a guest tmpfs bounded by guest memory; no writable host-backed drive (if one is ever needed: a fixed-size per-run file, deleted and verified). Firecracker has no virtio-fs or 9p, so no host directory is shared. |
| Inputs and outputs (§3) | vsock, serial | a versioned, length-prefixed vsock protocol to a trusted guest agent (PID 1); host reads at most limit + 1 bytes per stream; serial console disabled or discarded unparsed |
| Application limits (§6) | none inside the guest | the guest agent applies cgroup v2 / rlimits for memory, processes, CPU and scratch; vCPU count fixed; balloon device disabled |
| Disk I/O bandwidth | block-device rate limiter available | set a rate limiter on the read-only drive: this closes the `io`-not-delegated gap for this backend |
| Freshness (§2) | boot per run, or snapshot restore | boot a fresh microVM per stage. Snapshot restore only from a pinned, digest-recorded clean snapshot; restored clones share entropy and address-space layout, which must be recorded as a limitation |
| Observation trust (§8) | guest agent reports | still untrusted: a candidate that compromises the guest kernel controls the agent's reports. Host-observed outcomes (scope OOM, wall timeout, output overflow) take precedence over guest reports |

Residual risk: a KVM or VMM escape, a seccomp bypass and a jail escape together reach the operator account. A dedicated user, VM or host remains the recommendation beyond a prototype.

### Minimal Core adaptation (recommended; not implemented)

The session, grant, ledger, `CompileJob`/`ExecuteJob`, observations and the `IsolationRuntime` interface are runtime-agnostic and **do not change**. Only the backend selection and the attestation do:

1. `RuntimeAttestation.runtime` gains `"firecracker"`, valid only with `platform="kvm"`, `rootless=True`, `runtime_sha256` (the Firecracker binary), `rootfs_sha256` (the read-only guest image), the new fields `guest_kernel_sha256` and `guest_agent_sha256` (required for Firecracker, null otherwise), `limits_enforcement="verified_by_cgroup_readback"` and `isolation_verified=True`. Both backends should also return the read-back effective limits (Role B's request).
2. `[attack_lab.candidate_execution] runtime = "gvisor-runsc" | "firecracker"` plus operator-trusted absolute paths and SHA-256 pins for the backend's binary, kernel, rootfs and agent. Nothing comes from a request.
3. `configured_runtime` selects the backend from config and keeps refusing with `SANDBOX_UNAVAILABLE` until that backend is implemented and verified.
4. `lab_host` blockers per backend: Firecracker additionally needs `firecracker_not_installed`, `kvm_unavailable` (`/dev/kvm` not read-write), and missing or mismatched kernel, rootfs or agent. The systemd-run, delegation and user-namespace blockers stay, because the scope and the jail still need them.
5. Cross-role: Role B's `SandboxRuntime` name and resource-controller literals must accept the Firecracker attestation (`attack_lab`, not edited here).

### Additional verification before acceptance

V1–V11 apply unchanged. In addition:

| ID | Property verified |
|---|---|
| F1 | the VMM process cannot read the operator's home or the store root |
| F2 | no API socket exists; no network device is present in the guest |
| F3 | the VMM's threads run with seccomp enabled |
| F4 | guest memory cannot grow past its configuration; the host scope OOM-kills the VMM at the limit |
| F5 | malformed, oversized and truncated vsock frames become `SANDBOX_FAILED` (`protocol_violation`) |

Approvals: the Firecracker variants of A2 (a pinned Firecracker release, user-local, checksum verified) and A3 (a pinned guest kernel, read-only rootfs image and guest agent), and an explicit choice of the rootless jail over the root jailer.

### Implementation status (2026-10-29): backend implemented, containment unverified

Core now contains the Firecracker backend:

- **Host runner:** `lab_firecracker.py`.
- **Protocol:** `lab_vm_protocol.py`, `aegis.core.vm-agent.v1`: HMAC-SHA256 per frame with a per-VM key sent first over the private vsock channel, per-direction sequence numbers, size caps and strict JSON.
- **Guest agent:** `lab_guest_agent.py`.
- **Guest provisioning:** `core/guest/`.
- **Config:** `runtime = "firecracker"`.
- **Attestation:** gains `guest_kernel_sha256`, `guest_agent_sha256` and `containment_verification_sha256`.
- **Observations:** gain `host_enforcement`, the cgroup read-back values plus host CPU, peak memory and OOM accounting.

The configured runtime **still refuses**. `ADR_0004_ACCEPTED` is false, and without a pinned `containment_verification_sha256` the backend reports `containment_unverified`.

| Requirement | Status | Evidence |
|---|---|---|
| Pinned Firecracker, bwrap, kernel and image (digest, regular file, owner, not group/world-writable, no symlink); unchanged before each VM | implemented, tested | unit tests; installed Firecracker/jailer v1.17.0 match the release `SHA256SUMS` |
| Rootless jail: new user/mount/pid/ipc/uts/net/cgroup namespaces, `--clearenv`, `--cap-drop ALL`, read-only binds of exactly four files, one writable socket directory, no `/home` | argv implemented and tested; jail **capability** verified on this host by running `firecracker --version` inside it | VM-level F1 **not run** |
| Built-in seccomp kept (`--no-seccomp` and custom filters never passed) | argv tested | F3 **not run** |
| `--no-api`; no network interface, balloon, MMDS, pmem, logger or metrics; root drive read-only and rate-limited; no serial console | VM config tested against the v1.17 `FullVmConfiguration` keys | **not booted** |
| Scope limits read back before the job is sent; job sent only after READY matches the pinned agent and compiler | implemented, tested with a fake scope | scope enforcement shown on this host earlier for transient scopes; not with a VM |
| Bounded protocol: tags, sequence numbers, frame caps, output caps, binary cap, strict result fields | implemented, tested (unit tests and a fake VMM over a real Unix socket) | against real Firecracker vsock: **not run** |
| Host timeout (wall + grace), host-OOM classification, `cgroup.kill`, `populated 0` and state-removal verification; cleanup failure overrides a result; interrupts clean up | implemented, tested with fakes | V9 **not run** |
| Guest executor: per-job tmpfs, guest cgroup (memory, pids), `RLIMIT_CPU`, unprivileged uid, output caps, wall clock | implemented | **never executed** (it would run code); its parsing, classification and serve loop are tested |
| Minimal, updated, reproducible guest image and kernel | build script and requirements written | **not built**: needs `mmdebstrap` and package fetches (approval) |

**Not equivalent to the official jailer.** The jailer is started as root. It pivots into a chroot it populates (including a `mknod`'d `/dev/kvm`), switches to a dedicated per-VM uid/gid, creates the VM's cgroups as root, and can apply rlimits and a network namespace. The rootless wrapper instead:

- runs the VMM as the operator's uid (mapped to 65534 inside a user namespace);
- isolates the VMM's file view with mount namespaces rather than a root-built chroot;
- gets its cgroup from the systemd user manager;
- sets no `RLIMIT_NOFILE` or `RLIMIT_FSIZE` on the VMM.

A VMM escape therefore lands as the operator, not as a throwaway uid. Containment claims require the F1–F5 and V1–V11 results (commands in `core/guest/README.md`).

### Validation artifacts (2026-10-29): implemented, not run

- **Driver and report:** `aegis_core.lab_containment` implements the F1–F5 and V1–V11 driver and the `aegis.core.containment-report.v1` report. `plan` starts nothing; `run` requires `--approve-vm-launch`.
- **Canaries:** 12 trusted, deterministic canaries in 13 cases are listed in `core/guest/canaries/manifest.json`, together with host inspections and five vsock fuzz cases.
- **Report enforcement:** normal-mode preflight requires `containment_report_path`, whose SHA-256 must equal `containment_verification_sha256`, and whose report must be strictly valid, target `candidate_guest`, have `overall: passed` (recomputed from its cases), and carry an `identity` equal to the running configuration's pins and host controls. A failed, incomplete, smoke-fixture, foreign or tampered report keeps execution disabled, and so does no report at all. `ADR_0004_ACCEPTED` stays `False`.
- **Provisioning:** the guest image and kernel build without host package changes (`core/guest/README.md`). Neither has been built.
- **Real-VM failure paths:** reviewed and fixed. They cover teardown fallback, a launcher dying early, a stale-state sweep, non-dumpable VMM inspection, supervision after outputs close, removed setuid files plus `no_new_privs`, `TMPDIR` in scratch, and a reduced guest kernel. They are listed in `core/guest/README.md`.

The first proposed live step is the smoke-fixture, host-only run (3 VMs, about 3 minutes worst case, no candidate). Its report can never enable execution.
