# AEGIS architecture

This is a living repository architecture note. The original implementation evidence was recorded at `c995857` on `dev/integration`; the revised PDFs retain that evidence and use the current four-role organization. The current workstream organization and status are in [TEAM_WORKSTREAMS.md](docs/TEAM_WORKSTREAMS.md) and [PROJECT_STATUS.md](docs/PROJECT_STATUS.md). Planned work is marked **planned** and is not implemented. If this document and the code
disagree, the code is right and this document has a bug.

## Four active engineering streams (28 October 2026)

- **A — Core Platform, Shield & Integration:** `core/`, `platform/api/`, `platform/cli/`, `protectors/llvm/` including `adapter/`, `demo/image_processor/`, governance and CI. See issue #9.
- **B — Adversarial AI Lab & Mirage:** `attack_lab/` (partial; see attack_lab/README.md) and `protectors/mirage/` (implemented transformer; reaches Core only through the combined `llvm-shield-mirage` adapter), issue #10.
- **C — Frontend & Product Experience:** `platform/dashboard/` (implemented; existing API only), issue #11.
- **D — Signature, Sentinel & Verification:** `provenance/` (implemented) and `sentinel/` (implemented), issue #12. Offline signed provenance manifests, public-key verification, Sentinel rights policies, and watermark research.

Issue #7 separately coordinates cross-ecosystem tests using PhotoCraft, the reVC branch of re-GTA, and Mattermost. ImageLab remains the controlled internal regression target. Protectors must never use benchmark names or target-specific answer logic. See [ownership and dependencies](docs/TEAM_WORKSTREAMS.md).

## 1. Components

```
                         ┌──────────────────────┐
  HTTP client ─────────▶ │ aegis_api (FastAPI)  │──┐
                         └──────────────────────┘  │ import
                         ┌──────────────────────┐  ▼
  shell user ──────────▶ │ aegis_cli (`aegis`)  │─▶ aegis_core
                         └──────────────────────┘    ├─ models.py        contracts (Pydantic v2)
                                                     ├─ config.py        aegis.toml loader
                                                     ├─ storage.py       local artifact store
                                                     ├─ orchestrator.py  job lifecycle + reports
                                                     ├─ adapter.py       subprocess runner
                                                     ├─ health.py        health check
                                                     ├─ lab_authorization.py / lab_limits.py
                                                     │                   attack-lab gates, execution grants
                                                     ├─ lab_execution.py candidate execution session
                                                     ├─ lab_ledger.py    per-grant usage ledger
                                                     ├─ lab_firecracker.py Firecracker backend (host side)
                                                     ├─ lab_containment.py F1-F5/V1-V11 driver and report
                                                     ├─ lab_vm_protocol.py / lab_guest_agent.py
                                                     │                   vsock protocol; guest agent (in VM)
                                                     │                   (no isolation runtime yet: refuses)
                                                     └─ lab_host.py      read-only host prerequisite probe
                                                            │
                               aegis.adapter.v1             │ argv array, shell=False,
                               (request.json → stdout JSON) ▼ timeout, minimal env
                                                  ┌──────────────────────────┐
                                                  │ adapter executable       │
                                                  │ (registered in aegis.toml)│
                                                  └──────────────────────────┘
                                                            │ LLVM Shield adapter
                                                            ▼
                                                  protectors/llvm  (AegisShield.so,
                                                  run through LLVM `opt`)
```

| Path | Name | Language / build | Status |
| --- | --- | --- | --- |
| `core/` | `aegis-core` / `aegis_core` | Python ≥3.11, hatchling | implemented |
| `platform/api/` | `aegis-api` / `aegis_api` | Python, FastAPI + uvicorn | implemented |
| `platform/cli/` | `aegis-cli` / `aegis_cli` | Python, stdlib `argparse` | implemented |
| `protectors/llvm/` | AEGIS Shield (`AegisShield.so`) | C++20 LLVM pass plugin, CMake, LLVM ≥22 | prototype; connected through adapter below |
| `protectors/llvm/adapter/` | LLVM Shield adapter; Shield + Mirage adapter | Python ≥3.11, POSIX, stdlib | implemented; textual IR, LLVM 22, explicit registration of `llvm-shield` and `llvm-shield-mirage` |
| `demo/image_processor/` | ImageLab controlled application/harness | C++20, CMake, Python stdlib tests | implemented; native/IR baseline/Shield/external variants |
| `attack_lab/` | `aegis-lab` / `aegis_lab` | Python ≥3.11, pydantic; Java Ghidra post-script | partial: v2 trial manifests and pair validation; bounded local Ghidra evidence export; unsigned evidence binding; offline scripted reconstruction; approval-gated Nebius transport; one operator-supplied NVIDIA response archive verified offline, with a separate post-hoc candidate-envelope review (behaviorally unscored; provider origin/weights/billing not independently attested); scoring via Core candidate-execution grants, whose runtime refuses every request in this revision. No Core protection adapter. |
| `protectors/mirage/` | `aegis-mirage` / `aegis_mirage` | Python ≥3.11 stdlib; drives LLVM 22 `clang`/`llvm-link`/`opt` | implemented: retained unreachable arithmetic decoys in LLVM 22 IR / ELF. Standalone CLI, and the second stage of the `llvm-shield-mirage` backend (adapter in `protectors/llvm/adapter/`); no Mirage-only backend; no measured attack resistance |
| `provenance/` | `aegis-provenance` / `aegis_provenance` | Python ≥3.11, hatchling, cryptography | implemented; RFC 8785 canonical JSON, Ed25519 offline signing/verification, watermark embedding & detector; `aegis_provenance.jobs` signs Core job outputs with an operator-configured key (§8a) |
| `sentinel/` | `aegis-sentinel` / `aegis_sentinel` | Python ≥3.11, hatchling, pydantic | implemented; versioned machine-readable rights and usage policies, validation and cooperating tool evaluation; attached to Core job outputs when configured (§8a) |
| `platform/dashboard/` | Developer frontend | React 18, TypeScript, Vite 6; Playwright browser tests | implemented: uses only `/healthz` and `/v1/jobs`; research summaries are verified and kept in the browser, never uploaded |

The Python packages are named `aegis_*` because a top-level package called
`platform` would hide the standard-library `platform` module.

## 2. Package boundaries and dependency rules

These rules reflect the current imports and must stay true:

1. `aegis_core` depends only on `pydantic` (v2) and the standard library. It
   does not import `aegis_api`, `aegis_cli`, FastAPI, or anything under
   `protectors/`.
2. `aegis_api` and `aegis_cli` depend on `aegis_core`, `aegis_provenance` and
   `aegis_sentinel`, and never on each other. They hold no business logic of
   their own: validation, storage and execution live in `aegis_core`
   (`Orchestrator`, `check_health`); signing, verification and policy handling
   live in `aegis_provenance.jobs` and `aegis_sentinel`.
2a. `aegis_provenance` depends on `aegis_core` and `aegis_sentinel`;
   `aegis_sentinel` depends on `aegis_core` only. Core reaches them solely
   through the generic `Orchestrator.post_success_hooks` list, so rule 1 holds:
   Core never imports `cryptography`, Provenance or Sentinel.
3. Protection backends are **never imported or linked** by the Python
   packages. The only coupling is the subprocess adapter protocol (§4) plus the
   JSON files it exchanges.
4. `protectors/llvm/` is self-contained. Its own `README.md` says it requires
   and modifies no root build or shared contract. Its test and benchmark tooling
   uses only the Python standard library. Its adapter runtime is also stdlib;
   the separate adapter integration tests use core/CLI and pytest.
5. There is no root build. Each component is built and tested separately. The root `pyproject.toml` configures pytest for the three Python application suites; the LLVM adapter's additional 94 integration tests require an explicit path. ImageLab is its own CMake project. See the detailed commands in the technical PDF §09.

## 3. Contracts (`aegis_core.models`)

Every model sets `extra="forbid"`, so unknown fields are rejected.

| Model | Purpose |
| --- | --- |
| `ProtectionPolicy` | `backend` (`^[a-z0-9][a-z0-9_-]{0,63}$`), `task` (`protect` / `attack_lab`), `options` (≤64 keys; values `bool` / `int` / finite `float` / `str` ≤4096 chars), optional `timeout_seconds`, optional `authorization` |
| `AttackLabAuthorization` | `authorized_by`, `reference`, `scope` (all non-blank), `attested_at`, optional `expires_at` |
| `ProtectionJob` | `status`: `pending → running → succeeded \| failed`; input artifact, output artifacts, `error`, timestamps |
| `Artifact` | `name`, `role` (`input` / `output` / `log`), `sha256`, `size_bytes`, store-relative `storage_path` |
| `EvidenceRecord` | `kind` (`artifact_hash`, `adapter_invocation`, `adapter_claim`, `authorization`) and `source` (`orchestrator` = observed or verified; `adapter` = claimed, not verified) |
| `AttackEvaluation` | one attack's `outcome` (`resisted` / `bypassed` / `inconclusive` / `error`) against a target artifact hash; `source` is `adapter` |
| `ProtectionReport` | written for **every** terminal job, failed ones included; `summary` plus a `limitations` list stating what the report does not prove |
| `ErrorInfo` | `code` (`ErrorCode` enum), `message`, `details` |
| `CandidateExecutionGrant` | `aegis.core.candidate-execution-grant.v1`: embeds an `AttackLabAuthorization` and binds permitted target digests, candidates (id, source digest, target), stages, exact compiler flags, per-stage `SandboxLimits`/`CompileLimits`, run budgets, Lab-declared digests and a ≤ 7-day window (§7a) |
| `CandidateExecutionRecord` | `aegis.core.candidate-execution-record.v1`: one compile or execute invocation; Core-computed digests, limits, budgets, the runtime attestation and the runtime's observation |

Invariants enforced by validators:

- `failed` ⇔ `error` is set.
- Terminal jobs have `finished_at`.
- Only `succeeded` jobs list output artifacts.
- Reports exist only for terminal jobs.

`schema_version` is the string `"1"`. The full error-code table, with HTTP
statuses and CLI exit codes, is in [core/README.md](core/README.md#error-codes).

## 4. Adapter protocol `aegis.adapter.v1`

The full specification is [core/docs/adapter-protocol.md](core/docs/adapter-protocol.md).
In summary:

- An operator registers a backend in `aegis.toml` as `[adapters.<name>]`, with
  `command` (an argument array), `tasks`, `timeout_seconds`,
  `env_passthrough` and `max_stdout_bytes`. **No backend is registered by
  default.** A request for an unregistered backend fails with
  `UNSUPPORTED_BACKEND` before any job is created.
- The orchestrator runs `[*command, "--aegis-request", <job>/adapter/request.json]`:
  - with `shell=False`, stdin set to `/dev/null`, and the working directory set
    to `<job>/work`;
  - in a new session (process group), which is `SIGKILL`ed on timeout;
  - with a minimal environment: `PATH`, `LANG`/`LC_ALL=C.UTF-8`, `HOME` and
    `TMPDIR` set to the work directory, plus the allow-listed `env_passthrough`.
- The request JSON carries `job_id`, `task`, `backend`, `policy_name`,
  absolute `input_path` and `output_dir`, `input_sha256`, `options`, and (for
  attack-lab tasks only) `authorization`. User-controlled values travel only
  in this file, never in argv.
- The adapter prints exactly one JSON result on stdout: `protocol`, `status`,
  `outputs[].path` (relative to `output_dir`), `evidence[]`,
  `attack_evaluations[]` and `error`. stderr is captured to
  `<job>/adapter/stderr.log`, and its hash is recorded as evidence.
- The job **fails** (it is never reported as a success) on any of:
  - executable missing → `ADAPTER_UNAVAILABLE`
  - timeout → `ADAPTER_TIMEOUT`
  - nonzero exit, or `status: "failed"` → `ADAPTER_FAILED`
  - invalid, empty or oversized stdout, or output paths that are missing,
    symlinked or escaping → `ADAPTER_INVALID_OUTPUT`
  - a `protect` success with zero outputs, an `attack_lab` success with zero
    evaluations, or evaluations returned for a `protect` task →
    `ADAPTER_INVALID_OUTPUT`
  - the input file changed during the run → `ARTIFACT_INTEGRITY_ERROR`
- All artifact hashes (SHA-256) are computed by the orchestrator, not taken
  from the adapter.

The real LLVM Shield adapter is described in §7, including the combined
`llvm-shield-mirage` adapter (§7, last paragraph). The other adapter,
`aegis_core.testing.fake_adapter`, is a protocol test double that applies **no**
protection and must never be registered as a real backend.

## 5. Job lifecycle and storage

1. **Submit** (`Orchestrator.submit`):
   - validate the policy (backend registered, task supported, attack-lab
     authorization);
   - create `<store>/jobs/<job_id>/{inputs,outputs,adapter,work}`;
   - copy the input in, with a sanitized name and size limit, hashing it as
     it streams;
   - write `job.json` as `pending`.
2. **Run** (`Orchestrator.run`):
   - claim the job atomically (`O_EXCL` `.claimed` file, which works across
     processes);
   - set `running` and validate the policy again;
   - write `request.json` and invoke the adapter;
   - verify the result and hash the outputs;
   - for a succeeded job, call each post-success hook (output signing and
     Sentinel policies, §8a). A hook exception is logged and never fails the job;
   - write `report.json`, then the terminal `job.json`.
3. **API**: `POST /v1/jobs` submits and then runs the job as a FastAPI
   background task in the same process. **CLI**: `aegis protect` submits and
   runs the job in the foreground.

All JSON writes are atomic (temp file, `fsync`, `os.replace`). The store root
defaults to `.aegis/` next to `aegis.toml`. There is no database, queue or
object storage. When signing or Sentinel is configured, succeeded jobs also get
`<store>/jobs/<job_id>/attestation/` (0700; files 0600): `attestation.json`,
`<artifact_id>.manifest.json` and `<artifact_id>.policy.json` per output. Candidate execution adds `<store>/lab-grants/<grant_id>/`
(`ledger.json` plus a `flock` lock file, 0700/0600): grant-wide usage, see §7a.

## 6. Security requirements

These are implemented in the code and are **requirements** for every future
change:

- **No shell on untrusted input.** Subprocesses use argument arrays with
  `shell=False`. User-supplied names and options never become argv elements.
- **No secret inheritance.** Adapters get the minimal environment above.
  Forwarding any variable requires an explicit `env_passthrough` entry.
- **Path containment.**
  - Job ids must match `^[0-9a-f]{32}$` before they are used in a path.
  - Input names are reduced to one safe path component.
  - Output paths must resolve inside `output_dir` and must not be symlinks.
- **Bounded execution.** Every adapter run has a timeout, and the whole
  process group is killed when it is exceeded.
- **Attack-lab tasks need two independent gates:**
  `[attack_lab] enabled = true` in config (off by default), **and** an
  `AttackLabAuthorization` on the request. Both are checked at submit time and
  again at run time, and expired authorizations are rejected. One function,
  `aegis_core.lab_authorization.check_attack_lab_gates`, implements them for
  jobs and for candidate execution. The config gate accepts only a TOML boolean.
- **Untrusted candidate code needs a third gate and a grant:**
  `[attack_lab.candidate_execution] enabled = true` (off by default, strict
  boolean) plus a `CandidateExecutionGrant`, all re-checked before every stage,
  **and** an approved isolation runtime that passes its preflight. The implemented
  Firecracker backend has not passed real containment validation and is refused (§7a).
- **API exposure.** The API binds to `127.0.0.1` by default. `aegis-api`
  refuses a non-loopback host unless `AEGIS_API_TOKEN` is set; when it is set,
  `/v1/*` requires the bearer token (compared in constant time). Validation
  errors never echo request content. `/healthz` reveals no filesystem paths.
- **LLVM Shield.** Its own README states it has **no established security
  property**. Nothing in AEGIS may present Shield output as protection against
  reverse engineering or tampering.
  The adapter accepts textual IR only, never executes native inputs/outputs,
  bounds files and diagnostics, and validates local reports and emitted IR.
  This is not a sandbox for LLVM parser bugs or malicious operator plugins.

## 7. LLVM Shield integration (milestone 002)

`protectors/llvm/adapter/aegis_llvm_adapter.py` speaks `aegis.adapter.v1` and
drives the real `AegisShield.so` through LLVM 22 `opt`. It is owned by the LLVM
integration module. Neither existing schema nor core/API/CLI implementation is
changed. See [ADR 0002](docs/adr/0002-llvm-shield-adapter.md) and the
[adapter README](protectors/llvm/adapter/README.md) for registration, commands,
test invocation and operational limits.

| Concern | How the existing contracts fit |
| --- | --- |
| Registration | Operator adds `[adapters.<name>]`, command = absolute Python/script paths plus `--opt` and `--plugin`, tasks = `["protect"]`. No defaults and no attack-lab support. |
| Tool locations | Paths belong in the operator-trusted command, never request options. Plugin path is absolute; opt is absolute or a bare PATH name. Requires LLVM 22.x and a plugin built from the same LLVM installation; the loaded report's LLVM version must match opt's probe. |
| Input | Textual LLVM IR only; LLVM validates content. Only eligible functions annotated `aegis.protect` transform. Bitcode/native formats are rejected; the adapter never compiles or executes native artifacts. |
| Options | Only string decimal uint64 `seed`, integer `max-sites` (0–1,000,000), boolean `enabled`. Explicit conversion to integer-versioned local config (`max_sites_per_function`). CLI seeds need JSON quotes, e.g. `--option 'seed="42"'`. |
| Paths | Validates core's job layout, safe input name, absolute input/output paths, empty outputs, and rejects symlinks/hardlinked artifacts. Stages a hash-checked input/config in a private work subdirectory. Only fixed relative names enter LLVM arguments. Store paths may contain pipeline metacharacters. Relative storage roots resolve against config; command path arguments are not rebased by core. |
| Invocation | argv array, shell=False, fixed pipeline `aegis-shield<config=shield-config.json;report=shield-report.json>,verify`, input `shield-input.ll`, output `protected.ll`. Runs a separate plugin-free LLVM verifier after validating the report. |
| Execution bounds | LLVM inherits core's process group and wall timeout, with a minimal environment and bounded file-backed diagnostics. POSIX per-file size cap plus polling/final checks enforce output/report limits. Not an aggregate disk/memory/CPU quota or compiler sandbox. |
| Outputs | Nonempty `protected.ll` and `shield-report.json`, published exclusively. Core computes both artifact hashes. Failed jobs register no outputs. |
| Evidence | LLVM version, `transformed_sites`, effective config and counts by function reason become bounded adapter claims (`source: "adapter"`). Detailed per-function facts remain in the report artifact. No security metrics are inferred. |
| Zero transformations | `status: "failed"`, adapter code `NO_TRANSFORMATIONS_APPLIED`. Core preserves this in `ADAPTER_FAILED` details. A zero opt exit is insufficient for success. |

The report is checked against its existing local schema and invocation-specific
invariants (module, LLVM version, config, totals, ordered unique sites, selection,
budget, status and reason consistency). Success records reported arithmetic
expansions and verified IR, with **no established security property**. Private
partial files may remain after a hard timeout or failed publication; failed jobs
never register them as outputs.

**Shield + Mirage (`llvm-shield-mirage`).** `aegis_shield_mirage_adapter.py` reuses the
Shield adapter's validation, Shield stage, runner and limits, then runs Mirage on
exactly the verified Shield output with Mirage's LLVM tools kept in Core's process
group (`transform(runner=…)`), verifies the final module without the plugin, and
publishes `protected.ll`, `shield-stage.ll`, `shield-report.json` and
`mirage-report.json`. Mirage's report must bind the Shield output's and final
module's SHA-256, which Core also records. Additional options `mirage-seed`,
`mirage-count`, `mirage-enabled`; additional adapter code `MIRAGE_FAILED`. Mirage
accepts a module whose four-part target triple equals Clang's default or differs only
in the vendor field (rustc's `x86_64-unknown-linux-gnu` vs Clang's
`x86_64-pc-linux-gnu`), compiling the decoys for the module's exact triple; any
other triple fails with `target_triple_mismatch`. No contract, model or storage change. Contract:
[docs/release/NATIVE_BACKEND_CONTRACT.md](docs/release/NATIVE_BACKEND_CONTRACT.md).
No established security property.

Lab tools do not implement or bypass Core's two attack-lab authorization gates. Core's side of linking Lab execution to `AttackLabAuthorization` is the candidate execution grant (§7a); the Lab side is pending Role B.

The operator-facing `scripts/live_evaluate.py` wrapper binds an owned ImageLab
Core protection job to fresh native builds, Ghidra reports and the production
Lab inference workflow. Its `run` command accepts an **inference-only** approval:
it may verify/project the archive and record a candidate digest, but must never
automatically invoke the separate `score` command, compile a returned candidate
or execute it. The binding explicitly records candidate scoring as `not_run`.
The standalone experimental scorer is not an approved Core execution runtime;
an inference approval does not establish candidate execution authorization or
validated isolation.

Nebius requests may explicitly opt into `enable_thinking: false`, serialized as
`chat_template_kwargs.enable_thinking=false`. It is bound into the prepared
sampling/request digest, exact operator review and archival replay. Omission
preserves the historical request bytes and provider default; verification must
never retrofit this option into an existing record. The wrapper forwards the
explicit `--disable-thinking` option through preparation, preflight and run.

## 7a. Untrusted candidate execution (Phase 4; ADR 0004 **proposed**)

[ADR 0004](docs/adr/0004-isolated-candidate-execution.md) proposes gVisor `runsc` (systrap, rootless) inside a transient systemd user scope for every compilation and every test case. Its proposed Amendment 1 reviews a Firecracker microVM backend: acceptable only inside the same scope plus a rootless jail, with seccomp, no API socket, no network device, read-only drives and a bounded vsock protocol; Core's session and grant interfaces would not change. It covers trust boundaries, filesystem, network, capabilities, enforced limits, containment, cleanup and fail-closed semantics. The Role B integration contract is [core/docs/lab-execution-contract.md](core/docs/lab-execution-contract.md).

| Concern | Implemented in Core now |
| --- | --- |
| Authorization | gates 1–3 plus a `CandidateExecutionGrant`; grant limits must not exceed operator ceilings (`[attack_lab.candidate_execution] compile_ceiling/execute_ceiling`) |
| Binding | Core hashes candidate bytes against the grant; multi-file grants additionally bind every named source/support file and the ordered translation units with `compilation_bundle_sha256`. Missing bundle digests permit only `candidate.c` alone. Exact flags, requested limits ≤ grant, and session/candidate binary binding remain enforced |
| Budgets | per **grant**, not per session: compile/execute counts per candidate and the total wall reservation live in a persistent, `flock`-serialized ledger, reserved before each run and never returned. A grant id is bound to its first digest (`grant_ledger_conflict`); a corrupt ledger fails closed (`STORAGE_ERROR`) |
| Cleanup on open | if opening a session fails or is interrupted (including `KeyboardInterrupt`) after the runtime was touched, the runtime is closed before the exception propagates |
| Re-checks | gates, window and stage permission before every compile and execute |
| Failures | refusals → `AUTHORIZATION_REQUIRED` with `details.reason`; no runtime → `SANDBOX_UNAVAILABLE` with `details.blockers`; runtime failure or protocol violation → `SANDBOX_FAILED`, session poisoned; candidate behavior is an observation, never a success or a score |
| Runtime | `runtime = "firecracker"` selects the Firecracker backend (`lab_firecracker`): one microVM per stage under a systemd user scope and a rootless bwrap jail, with a read-only rate-limited image, no NIC and an authenticated vsock protocol. **Containment unverified; `configured_runtime` still refuses** (`isolation_adr_not_accepted`, `containment_unverified`). `aegis_core.testing.scripted_runtime` is a non-executing test double whose records are labeled `test_double` |
| Host check | `python -m aegis_core.lab_host`: static prerequisites only; never claims enforcement |

The guest supervisor drains bounded output after reaping the leader, kills its
descendants, and polls aggregate job cgroup CPU usage during execution (10 ms
poll interval; overshoot is possible). Missing CPU accounting is an infrastructure
failure. Host OOM/deadline observations override guest results, including a
claimed successful compilation and its binary.

Firecracker preflight creates hashed, sealed anonymous memory copies of the VMM,
bwrap, kernel and image; launch uses their held `/proc/<Core pid>/fd` aliases.
Original path replacements and in-place writes cannot alter launched bytes.
The combined asset bound is 2 GiB of additional host memory outside VM scopes;
the containment plan reports it separately. Host OS libraries/systemd remain
trusted dependencies. `host_asset_binding=sealed-memfd-v1` is bound into the
containment-report identity; older reports do not authorize this launch path.
Its namespace access and boot behavior have **not** been tested with a real VM.

Unverified teardown retains process/scope tracking, state directories and asset
descriptors, refuses further runs, and allows cleanup retries through `close()`.
Legacy v1 grants without a bundle digest retain their old digest and ledger
usage. Adding a bundle digest changes identity and cannot reuse an existing
ledger id. Role B grant issuers must migrate multi-file grants; the merged worker
already maps host enforcement and private evidence records. See
[the execution review](docs/CORE_EXECUTION_REVIEW.md) for exact tests, migration
evidence, native machine-code measurements and remaining safety blockers.

Lab-declared digests (pair, hidden suite, sandbox policy, scorer) are bound and recorded but cannot be verified by Core. Grants are operator-attested, not signed. Sentinel, watermark and provenance features are not security controls for this path.

## 8. Provenance and Sentinel architecture (Workstream D)

`aegis-provenance` and `aegis-sentinel` provide cryptographic build record verification and machine-readable rights metadata. Both modules are self-contained and run offline without coupling to the compiler plugins or attack lab.

| Concern | Contract and Implementation |
| --- | --- |
| Provenance Manifest | `ProvenanceManifest` binds final artifact SHA-256 and size, source repository, commit hash, compiler/toolchain, configuration identity, signer identity, and public key fingerprint (`key_id`). Formatted as deterministic canonical JSON (RFC 8785) and signed with Ed25519 (RFC 8032) wrapped in a `ManifestEnvelope`. |
| Offline Verification | `verify_artifact_manifest` validates against explicit trusted public keys. It fails closed on tampered artifacts (`ARTIFACT_TAMPERED`), modified manifest fields (`SIGNATURE_INVALID`), untrusted keys (`UNTRUSTED_KEY`), key ID mismatches (`KEY_ID_MISMATCH`), malformed envelopes (`MANIFEST_MALFORMED`), and unsupported schema versions (`UNSUPPORTED_VERSION`). |
| Sentinel Rights Policy | `SentinelPolicy` defines versioned machine-readable rights and usage rules. An explicit `enforcement_mode` (`advisory_notice` vs `cooperating_enforced`) distinguishes declared rights notices from actively enforced rules. |
| Policy Evaluator | Evaluates whether actions (`execute`, `analyze`, `redistribute`, `modify`, `attack_evaluate`) are permitted for cooperating tools based on artifact hash linkage, temporal window (`not_before`, `expires_at`), environment, caller ID, and watermark requirements. |
| Watermark Research | Binary framed watermark (magic sync `\x1bAEGIS_WM\x01` / `\x1bEND_WM\x1b`, uint16 length, CRC32 checksum) and textual LLVM IR metadata nodes (`!aegis.watermark`) / comments. Empirical controls establish 0.0% False Positive Rate (50 unmarked controls) and 100% True Positive Rate. |

### Trust Boundaries and Security Invariants

1. **Signer Attestation vs Authorship:** A valid signature proves the holder of the trusted private key attested to the artifact digest and manifest metadata at signing time. It does not prove originality, intellectual property ownership, or complete absence of vulnerabilities in the source code.
2. **Private Key Isolation:** Private keys are stored in PKCS#8 PEM format (with optional encryption) strictly outside Git, logs, and public artifact stores. Only public verification keys and key IDs are shared.
3. **Advisory Notice vs Enforcement:** Merely publishing a Sentinel policy document does not bind or compel non-cooperating third-party tools or external decompilers. Compliance requires an active gate in a cooperating runtime or orchestrator.
4. **Watermarking Limits:** Watermarking provides passive provenance tagging. Trailing binary frames and LLVM IR metadata nodes do not survive aggressive optimization passes that strip debug metadata (`opt -strip-debug`, `strip`).

## 8a. Signed outputs and Sentinel policies in the job lifecycle

Implemented in `aegis_provenance.jobs` (`JobAttestor`), wired into the API and
CLI as a Core post-success hook. Full contract, statuses and UI rules:
[docs/release/FINAL_API_CONTRACT.md](docs/release/FINAL_API_CONTRACT.md).

| Concern | Behaviour |
| --- | --- |
| Configuration | `[provenance]` and `[sentinel]` in `aegis.toml`, both **off by default**, strict booleans, absolute paths. Core validates shape only (`ProvenanceConfig`, `SentinelJobConfig`). |
| Signing key | Operator-provided Ed25519 PKCS#8 PEM. Refused (`CONFIG_INVALID`, API/CLI do not start) if missing, a symlink, not a regular file, group/world-accessible, inside a Git work tree (configured and resolved ancestry, including symlinked parents) or inside the store, wrong/absent password (password only via a named env var), or not Ed25519. AEGIS never generates a key; `aegis-provenance keygen` writes 0600 atomically and refuses Git work trees. |
| Signing | Inside `Orchestrator.run`, after Core hashed and registered the outputs and before the job is terminal. One `ManifestEnvelope` per output; refused if bytes changed since Core hashed them. Build reference = operator `build_repository`/`build_commit` + job id; `options_digest` = SHA-256 of canonical `{job_id, backend, task, policy_name, options, input_sha256}` (preimage stored). Failure → `signing_failed`, job stays `succeeded`, nothing is reported signed. |
| Verification | Recomputed per request: `verify_artifact_manifest` against the configured trusted keys only, plus Core-record binding (digest, size, name, job id, recorded manifest digest → else `RECORD_MISMATCH`). `verified` is the only success state; no trusted keys → `ABSENT_TRUSTED_KEYS`. |
| Sentinel | One policy per output: listed `allowed_actions` allowed, every other action explicitly denied, `manifest_reference` = signed manifest digest. Created with Sentinel's models and checked by its validator. Policy digest recorded; a modified, missing or invalid policy evaluates as denied. Missing caller/environment for a restricted policy is denied (evaluator fixed to fail closed). |
| Enforcement | Cooperating only. The one AEGIS enforcement point is `GET /v1/jobs/{id}/artifacts/{sha256}` (action `redistribute`, caller `aegis-api`): denied → 403 `POLICY_DENIED`; Sentinel configured but no valid policy → denied. `advisory_notice` policies are reported, not enforced. Sentinel never opens attack-lab gates. |
| Reads | Output bytes are read once with `O_NOFOLLOW`, size-bounded (256 MiB), re-hashed against Core's record before release (`ARTIFACT_INTEGRITY_ERROR`, 409). Only registered outputs of succeeded jobs; no caller paths. |
| Contracts | `ProtectionJob`, `ProtectionReport`, `/healthz` and `POST /v1/jobs` unchanged. Additive: error codes `ARTIFACT_NOT_FOUND`, `POLICY_DENIED`; routes `/v1/attestation`, `/v1/jobs/{id}/attestation`, `/v1/jobs/{id}/artifacts/{sha256}[/manifest|/policy|/evaluate]`; CLI `aegis verify`, `aegis evaluate`. |

Limits: a signature attests bytes and metadata by the key holder; it is not
protection evidence. Key custody is the operator's. `attestation.json` lives in
the same local store as the outputs (local filesystem trust, as for the job
records). Sentinel caller ids are asserted, not authenticated. Jobs that
predate the configuration have no record: they report unsigned, and downloads
are denied while Sentinel is configured.

### Local release inventory and licensing metadata

The local source/test-build archive includes the compiled dashboard and a
per-file SHA-256 inventory (`aegis.local-release.v1`). After the operator's
30 October 2026 approval by all four named contributors, its metadata records
`license_status: approved` and SPDX `license: MIT`. Root and package-local
LICENSE files contain the same standard notice. Inventory integrity and license
approval do not authorize publication or authenticate the publisher; committing,
pushing and publishing require separate operator approval.

## 9. Open architecture issues

| ID | Issue |
| --- | --- |
| A1 | **Resolved in milestone 002:** LLVM integration owns `protectors/llvm/adapter/`; explicit registration connects Shield to core. |
| A2 | **Resolved for milestone 002:** independent schema versions remain intact; the adapter explicitly converts config and validates the local Shield report, published as an artifact. |
| A3 | **Resolved for Shield:** zero transformed sites fail with `NO_TRANSFORMATIONS_APPLIED`. Generic core protection-effectiveness semantics remain backend-specific. |
| A4 | API jobs run in-process as background tasks. A server stop mid-run leaves a job `running`; there is no recovery or queue. |
| A5 | Adapter stdout/stderr are read fully into memory. `max_stdout_bytes` is checked after the process exits, not while it streams. |
| A6 | The repository's public default branch is `dev/integration`. No release branch or required CI was confirmed at this revision; release/branch-protection policy must be agreed and implemented. |
| A7 | The recorded full integration run used Python 3.14 and LLVM 22.1.8. The four-role documentation revision also passed the 105 Core/API/CLI tests on Python 3.12.14; native integration was not rerun there. Packages declare `>=3.11`. |
| A8 | `.env.example` is empty. The runtime environment variables in use are `AEGIS_CONFIG` and `AEGIS_API_TOKEN`. Optionally, the operator names one more in `[provenance] signing_key_password_env` (the signing key password); it is read only by the API/CLI process and never forwarded to adapters. |
| A9 | No isolation runtime: ADR 0004 is proposed, `runsc` is not installed, and the V1–V11 verification has not run. Candidate execution is refused (`SANDBOX_UNAVAILABLE`). |
| A10 | Candidate execution grants, like `AttackLabAuthorization`, are operator-attested files, not cryptographic credentials. Core persists grant usage (the ledger) but not the per-stage records, which are returned to the Lab. The ledger trusts the local filesystem: deleting the store resets it. |
