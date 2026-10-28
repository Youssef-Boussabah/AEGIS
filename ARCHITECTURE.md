# AEGIS architecture

This document describes what is implemented on `dev/integration` as of commits
`9a11c89` (LLVM Shield prototype) and `1dd99c4` (core platform). Planned work is
marked **planned** and is not implemented. If this document and the code
disagree, the code is right and this document has a bug.

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
                                                            ┊ planned, not implemented
                                                            ▼
                                                  protectors/llvm  (AegisShield.so,
                                                  run through LLVM `opt`)
```

| Path | Name | Language / build | Status |
| --- | --- | --- | --- |
| `core/` | `aegis-core` / `aegis_core` | Python ≥3.11, hatchling | implemented |
| `platform/api/` | `aegis-api` / `aegis_api` | Python, FastAPI + uvicorn | implemented |
| `platform/cli/` | `aegis-cli` / `aegis_cli` | Python, stdlib `argparse` | implemented |
| `protectors/llvm/` | AEGIS Shield (`AegisShield.so`) | C++20 LLVM pass plugin, CMake, LLVM ≥22 | prototype; **not connected to `aegis_core`** |

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
   uses only the Python standard library.
5. There is no root build. Each component is built and tested on its own (see
   `README.md` and ADR 0001). The root `pyproject.toml` only configures pytest
   to run the three Python suites together.

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

The only adapter in the repository is `aegis_core.testing.fake_adapter`, a
protocol test double that applies **no** protection.

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

## 7. LLVM Shield integration (planned, not implemented)

**Current state:** `protectors/llvm` builds `AegisShield.so`, a module pass
named `aegis-shield` that `opt` runs explicitly. It reads its options from the
pass pipeline string (`seed`, `max-sites`, `enabled`, `config`, `report`).
Optionally it writes a local JSON report (`urn:aegis-shield-llvm:report:1`).
`aegis_core` has **no** adapter for it. With any current configuration,
`aegis protect --backend <anything-shield>` fails with `UNSUPPORTED_BACKEND`.

The integration needs **no change to either side's existing schemas**. It is a
new adapter executable that speaks `aegis.adapter.v1` on one side and drives
`opt` on the other. The constraints below come from reading both
implementations and from manually running `opt` with the job directory layout:

| Concern | How the existing contracts fit |
| --- | --- |
| Registration | an `[adapters.<name>]` entry with `tasks = ["protect"]`. The Shield has no attack capability, so it must not declare `attack_lab`. The backend name is the operator's choice within `^[a-z0-9][a-z0-9_-]{0,63}$`; `aegis-shield-llvm`, the value of the report's `backend` field, would fit. |
| Tool locations | the plugin `.so` and `opt` paths belong in the adapter's `command` argv in `aegis.toml` (operator-trusted), not in request options. Plugin and `opt` must come from the same LLVM build (ABI dependency). |
| Input | the AEGIS input artifact must be LLVM IR, not a linked binary. Textual `.ll` is what the Shield's tests exercise; bitcode is untested. The Shield only transforms functions annotated `aegis.protect`. |
| Options | AEGIS `options` map to pass options: `seed` (decimal uint64; send as a **string**, matching the Shield config schema, because JSON numbers above 2^53 are unsafe), `max-sites` (0–1,000,000), `enabled`. The adapter must validate them and reject anything else. The Shield gives pipeline metacharacters (`; , < > ( )`) no escaping. |
| Paths | the adapter must **not** put absolute store paths into the pass pipeline: the operator-configurable store root may contain pipeline metacharacters, and `opt` then rejects the pipeline (verified). Its working directory is always `<job>/work`, so `../inputs/<name>` and `../outputs/<file>` are fixed relative paths without metacharacters. These relative paths also keep absolute local paths out of the Shield report's `module` field (verified: it records `../inputs/<name>`). |
| Invocation | `opt -load-pass-plugin <so> "-passes=aegis-shield<seed=…;max-sites=…;report=../outputs/shield-report.json>,verify" -S ../inputs/<name> -o ../outputs/<name>.protected.ll`, as an argv array with `shell=False`. A nonzero `opt` exit maps to `status: "failed"` / `ADAPTER_FAILED`. |
| Outputs | `outputs` = the transformed IR and `shield-report.json`. Both are hashed by the orchestrator. |
| Evidence | Shield report facts (LLVM version, `transformed_sites`, per-function `reason`) become adapter `evidence[]` entries. They are recorded with `source: "adapter"`, as claims; the AEGIS contract offers no stronger status for them. |
| Zero transformations | `opt` exits 0 with `transformed_sites: 0` when no function is annotated (verified). The adapter must not report that as a successful protection; see open issue A3. |

Where this adapter lives (for example `protectors/llvm/adapter/`) and who
owns it is undecided (open issue A1).

## 8. Open architecture issues

| ID | Issue |
| --- | --- |
| A1 | **No LLVM Shield adapter exists**, and its home and owner are undecided. Until it exists, AEGIS cannot invoke the Shield. |
| A2 | Two independent schema conventions: `aegis_core` uses `schema_version: "1"` (string) and the protocol id `aegis.adapter.v1`; the Shield uses `schema_version: 1` (integer) and `urn:aegis-shield-llvm:*` ids. Its README calls its schemas *local, provisional* and asks for reconciliation with any shared contract. They don't conflict today, because Shield reports travel as opaque output artifacts. |
| A3 | Success semantics for no-op protection: `aegis_core` rejects a `protect` success with zero **outputs**, but cannot tell that an output is unchanged. An adapter-level rule (for example, fail when `transformed_sites == 0`) or a core-level field is needed. |
| A4 | API jobs run in-process as background tasks. A server stop mid-run leaves a job `running`; there is no recovery or queue. |
| A5 | Adapter stdout/stderr are read fully into memory. `max_stdout_bytes` is checked after the process exits, not while it streams. |
| A6 | No `main` branch exists locally and there is no remote-tracking branch, so the promotion path from `dev/integration` is undefined. There is also no CI; validation is manual (see `AGENTS.md`). |
| A7 | Python 3.14 is the only verified interpreter, although packages declare `>=3.11`. LLVM 22.1.8 is the only verified LLVM. |
| A8 | `.env.example` is empty. The runtime environment variables in use are `AEGIS_CONFIG` and `AEGIS_API_TOKEN`. |
