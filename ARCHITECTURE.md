# AEGIS architecture

This is a living repository architecture note. The original implementation evidence was recorded at `c995857` on `dev/integration`; the revised PDFs retain that evidence and use the current four-role organization. The current workstream organization and status are in [TEAM_WORKSTREAMS.md](docs/TEAM_WORKSTREAMS.md) and [PROJECT_STATUS.md](docs/PROJECT_STATUS.md). Planned work is marked **planned** and is not implemented. If this document and the code
disagree, the code is right and this document has a bug.

## Four active engineering streams (28 October 2026)

- **A — Core Platform, Shield & Integration:** `core/`, `platform/api/`, `platform/cli/`, `protectors/llvm/` including `adapter/`, `demo/image_processor/`, governance and CI. See issue #9.
- **B — Adversarial AI Lab & Mirage:** `attack_lab/` (partial; see attack_lab/README.md) and `protectors/mirage/` (planned), issue #10.
- **C — Frontend & Product Experience:** `platform/dashboard/` (planned), issue #11.
- **D — Signature, Sentinel & Verification:** `provenance/` and `sentinel/` (planned), issue #12. First deliverable is offline signed provenance; policy and watermark research follow separately.

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
                                                     └─ health.py        health check
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
| `protectors/llvm/adapter/` | LLVM Shield adapter | Python ≥3.11, POSIX, stdlib | implemented; textual IR, LLVM 22, explicit registration |
| `demo/image_processor/` | ImageLab controlled application/harness | C++20, CMake, Python stdlib tests | implemented; native/IR baseline/Shield/external variants |
| `attack_lab/` | `aegis-lab` / `aegis_lab` | Python ≥3.11, pydantic; Java Ghidra post-script | partial: v2 trial manifests and pair validation; bounded local Ghidra evidence export; unsigned evidence binding. No attack execution, Core adapter or model calls. |
| `protectors/mirage/` | Mirage decoys | to be decided | planned |
| `provenance/`, `sentinel/` | Signing, watermark/policies | to be decided | planned |
| `platform/dashboard/` | Developer frontend | to be decided | planned |

The Python packages are named `aegis_*` because a top-level package called
`platform` would hide the standard-library `platform` module.

## 2. Package boundaries and dependency rules

These rules reflect the current imports and must stay true:

1. `aegis_core` depends only on `pydantic` (v2) and the standard library. It
   does not import `aegis_api`, `aegis_cli`, FastAPI, or anything under
   `protectors/`.
2. `aegis_api` and `aegis_cli` depend on `aegis_core` and never on each other.
   They hold no business logic of their own: validation, storage and execution
   live in `aegis_core` (`Orchestrator`, `check_health`).
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

The real LLVM Shield adapter is described in §7. The other adapter,
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
   - write `report.json`, then the terminal `job.json`.
3. **API**: `POST /v1/jobs` submits and then runs the job as a FastAPI
   background task in the same process. **CLI**: `aegis protect` submits and
   runs the job in the foreground.

All JSON writes are atomic (temp file, `fsync`, `os.replace`). The store root
defaults to `.aegis/` next to `aegis.toml`. There is no database, queue or
object storage.

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
  again at run time, and expired authorizations are rejected.
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

Lab tools do not implement or bypass Core's two attack-lab authorization gates. Linking Lab authorization references to `AttackLabAuthorization` remains a coordinated future integration task.

## 8. Open architecture issues

| ID | Issue |
| --- | --- |
| A1 | **Resolved in milestone 002:** LLVM integration owns `protectors/llvm/adapter/`; explicit registration connects Shield to core. |
| A2 | **Resolved for milestone 002:** independent schema versions remain intact; the adapter explicitly converts config and validates the local Shield report, published as an artifact. |
| A3 | **Resolved for Shield:** zero transformed sites fail with `NO_TRANSFORMATIONS_APPLIED`. Generic core protection-effectiveness semantics remain backend-specific. |
| A4 | API jobs run in-process as background tasks. A server stop mid-run leaves a job `running`; there is no recovery or queue. |
| A5 | Adapter stdout/stderr are read fully into memory. `max_stdout_bytes` is checked after the process exits, not while it streams. |
| A6 | The repository's public default branch is `dev/integration`. No release branch or required CI was confirmed at this revision; release/branch-protection policy must be agreed and implemented. |
| A7 | The recorded full integration run used Python 3.14 and LLVM 22.1.8. The four-role documentation revision also passed the 105 Core/API/CLI tests on Python 3.12.14; native integration was not rerun there. Packages declare `>=3.11`. |
| A8 | `.env.example` is empty. The runtime environment variables in use are `AEGIS_CONFIG` and `AEGIS_API_TOKEN`. |
