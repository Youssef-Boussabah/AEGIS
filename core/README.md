# AEGIS core platform

The orchestration layer for AEGIS. It is split into three Python packages:

| Path | Package | Purpose |
| --- | --- | --- |
| `core/` | `aegis_core` | Pydantic v2 contracts, local artifact store, adapter runner, orchestrator, health check |
| `platform/api/` | `aegis_api` | FastAPI service: create a job, get its status, get its report, `/healthz` |
| `platform/cli/` | `aegis_cli` | The `aegis` command: `init`, `inspect`, `protect`, `report` |

(The packages are named `aegis_*` so they don't shadow Python's standard-library
`platform` module.)

There is no database, queue or object store. State lives in a local directory
(`.aegis/` by default) as JSON files next to the artifacts.

## Setup

Requires Python ≥ 3.11 (verified on 3.14.7) and [uv](https://docs.astral.sh/uv/).
From the repository root:

```bash
uv venv .venv
uv pip install --python .venv/bin/python \
  -c core/requirements-dev.lock \
  -e './core[dev]' -e './platform/api[dev]' -e './platform/cli[dev]'
```

`core/requirements-dev.lock` pins every third-party package to the versions the
test suite was verified against. Install the three packages together:
`aegis-api` and `aegis-cli` depend on the local `aegis-core`, which is not
published to an index.

Using plain pip instead: `python -m venv .venv && .venv/bin/pip install -c core/requirements-dev.lock -e './core[dev]' -e './platform/api[dev]' -e './platform/cli[dev]'`.

## Running the tests

Each package has its own test suite and pytest configuration:

```bash
(cd core && ../.venv/bin/pytest)
(cd platform/api && ../../.venv/bin/pytest)
(cd platform/cli && ../../.venv/bin/pytest)
```

The tests use `aegis_core.testing.fake_adapter`, a protocol test double that
applies **no** protection. Never register it as a real backend.

## Quick start

```bash
.venv/bin/aegis init                 # writes ./aegis.toml and ./.aegis/
.venv/bin/aegis inspect              # health check: config, storage, backends
# register a backend under [adapters.<name>] in aegis.toml, then:
.venv/bin/aegis protect ./app.bin --backend <name>
.venv/bin/aegis report <job_id>
.venv/bin/aegis-api                  # HTTP API on 127.0.0.1:8000
```

A fresh `aegis init` registers no backends, so `protect` fails with
`UNSUPPORTED_BACKEND` until you add one. That's intended: AEGIS never reports
success for a backend it can't run.

## Configuration (`aegis.toml`)

Lookup order: `--config PATH`, then `$AEGIS_CONFIG`, then `./aegis.toml`.
Relative paths are resolved against the config file's directory. Unknown keys
are rejected.

```toml
[storage]
root = ".aegis"
max_input_bytes = 67108864

[attack_lab]
enabled = false                  # operator gate for attack-lab tasks

[adapters.example]
command = ["/opt/aegis/bin/example-adapter", "--mode", "strict"]
tasks = ["protect"]              # or ["protect", "attack_lab"]
timeout_seconds = 300
env_passthrough = []             # env vars forwarded to the adapter; nothing else is
max_stdout_bytes = 4194304
```

## Contracts

All models live in `aegis_core.models` and reject unknown fields.

- **ProtectionPolicy**: `backend`, `task` (`protect` | `attack_lab`), typed
  scalar `options`, optional `timeout_seconds`, optional `authorization`.
- **ProtectionJob**: `status` is `pending → running → succeeded | failed`.
  Validators enforce that a `failed` job always has an `error`, a `succeeded`
  job never does, terminal jobs have `finished_at`, and only succeeded jobs list
  output artifacts.
- **Artifact**: name, role (`input` / `output` / `log`), SHA-256, size, and a
  store-relative path. Hashes are always computed by the orchestrator.
- **EvidenceRecord**: `source` is `orchestrator` (observed or verified: hashes,
  exit status, timing) or `adapter` (claimed by the adapter and recorded as-is,
  not verified).
- **AttackEvaluation**: one attack's outcome (`resisted` / `bypassed` /
  `inconclusive` / `error`) against a specific artifact hash. Only accepted for
  authorized attack-lab tasks.
- **ProtectionReport**: produced for every terminal job, including failed ones.
  It has the same status/error invariants plus a `limitations` list that
  states what the report does not prove.

### Error codes

Errors are `{"code", "message", "details"}` (`ErrorInfo`) with a stable `code`:

| Code | Meaning | HTTP | CLI exit |
| --- | --- | --- | --- |
| `INVALID_REQUEST` | malformed request / policy | 422 | 2 |
| `UNAUTHORIZED` | missing or wrong API bearer token | 401 | – |
| `CONFIG_NOT_FOUND`, `CONFIG_INVALID`, `CONFIG_EXISTS` | configuration problems | – | 3 |
| `UNSUPPORTED_BACKEND` | no adapter registered for the backend | 400 | 4 |
| `UNSUPPORTED_TASK` | adapter does not declare the task | 400 | 4 |
| `AUTHORIZATION_REQUIRED` | attack-lab disabled, authorization missing/expired, or a candidate execution refusal; `details.reason` names the cause | 403 | 5 |
| `INPUT_NOT_FOUND` / `INPUT_TOO_LARGE` | input problems | 400 / 413 | 6 / 2 |
| `JOB_NOT_FOUND` | unknown job id | 404 | 6 |
| `JOB_CONFLICT`, `REPORT_NOT_READY` | job is not in the right state | 409 | 7 |
| `ADAPTER_UNAVAILABLE` | executable missing or not executable | job fails | 1 |
| `ADAPTER_TIMEOUT` | adapter killed after its timeout | job fails | 1 |
| `ADAPTER_FAILED` | nonzero exit or `status: "failed"` | job fails | 1 |
| `ADAPTER_INVALID_OUTPUT` | bad JSON, missing/escaping outputs, success with no outputs | job fails | 1 |
| `ARTIFACT_INTEGRITY_ERROR` | input hash changed during the run (job fails); or a stored output no longer matches its recorded SHA-256 when read | job fails / 409 | 1 |
| `ARTIFACT_NOT_FOUND` | no registered output with that SHA-256 in a succeeded job, or no manifest/policy for it (`details.kind`) | 404 | 6 |
| `POLICY_DENIED` | a cooperating Sentinel policy denies the action, or the governing policy is missing/invalid/modified | 403 | 5 |
| `SANDBOX_UNAVAILABLE` | candidate execution: no approved, verified isolation runtime (`details.blockers`); nothing was started | not exposed (500) | not exposed (70) |
| `SANDBOX_FAILED` | candidate execution: runtime start, enforcement, protocol or cleanup failure (`details.failure`); never a candidate outcome | not exposed (500) | not exposed (70) |
| `STORAGE_ERROR`, `INTERNAL_ERROR` | local I/O or unexpected errors | 500 | 3 / 70 |

Requests that can be rejected up front (unsupported backend/task, missing
authorization) are rejected before any job is created. Problems found while
running become a `failed` job with a report.

## Attack-lab authorization

Attack-lab tasks need **both**:

1. `[attack_lab] enabled = true` in the configuration (operator gate), and
2. an `authorization` record on the policy: `authorized_by`, `reference`
   (engagement/ticket id), `scope`, and optionally `expires_at`.

The authorization is checked when the job is submitted and again just before it
runs. It is recorded as evidence in the report and passed to the adapter.
`enabled` must be a TOML boolean; strings such as `"yes"` are rejected.
Refusals carry `details.reason` (`attack_lab_disabled`,
`authorization_missing`, `authorization_expired`).

### Untrusted candidate execution (Phase 4)

Compiling or running a Lab-generated candidate needs both gates above **plus**
`[attack_lab.candidate_execution] enabled = true` (off by default) and a
`CandidateExecutionGrant` that binds the exact candidates, flags, limits,
budgets and validity window. Grant limits may not exceed the operator ceilings
`compile_ceiling` / `execute_ceiling` in the same section. Everything is
re-checked before every stage. Budgets are per grant across all sessions and
processes, kept in `<store>/lab-grants/<grant_id>/ledger.json`. `compile`
requires an explicit `translation_units` list; other submitted files are only
staged for `#include`. Multi-file grants must bind all named source and support
files and the ordered units using `compilation_bundle_sha256`; missing bindings
permit only `candidate.c` compiled alone. Existing single-file grant identities
and persistent ledger usage are preserved. The Firecracker backend (`runtime = "firecracker"`) is
implemented but refused until containment is verified; see
[guest/README.md](guest/README.md) for the guest image and the proposed checks.

**The isolation backend is implemented but unvalidated and unapproved.**
`aegis_core.lab_execution.open_session` with the configured runtime therefore
fails with `SANDBOX_UNAVAILABLE` and nothing is compiled or run. The
design awaiting approval is [ADR 0004](../docs/adr/0004-isolated-candidate-execution.md);
the Lab integration contract is [docs/lab-execution-contract.md](docs/lab-execution-contract.md).
`python -m aegis_core.lab_host` prints the host's static prerequisites; it
never claims that limits are enforced.

Guest supervision drains pipes after the leader exits and polls aggregate
cgroup CPU usage during execution (10 ms polling, with possible overshoot).
Failed VM cleanup retains process/scope tracking and state for retry, and blocks
further runs. Host OOM and deadline observations take precedence over guest
results. Before launch, pinned host assets are copied, hashed and sealed in
anonymous memory files; launches use held descriptors through `/proc/<Core pid>/fd`.
On Linux, Python builds that omit the `fcntl` sealing constants use the stable
kernel UAPI values (`F_ADD_SEALS=1033`, `F_GET_SEALS=1034`; seal/shrink/grow/write
bits `1/2/4/8`). Native Python definitions take precedence. Every snapshot must
read back all four seals with `F_GET_SEALS`; failed operations or incomplete
readback close the descriptor and refuse preflight. No fallback runs on other
platforms. The UAPI definitions are in Linux's `include/uapi/linux/fcntl.h` and
`include/uapi/asm-generic/fcntl.h`.
These copies use up to 2 GiB of additional host memory outside VM scopes and
must be included in operator capacity planning. No real VM has validated this
launch path. See [the review and results](../docs/CORE_EXECUTION_REVIEW.md).

## Security notes

- Adapters run with `shell=False`, as an argument array from the config plus
  `--aegis-request <file>`. User-controlled values (file names, options) go only
  into the request JSON file, never into argv.
- Adapters get a minimal environment (`PATH`, locale, `HOME`/`TMPDIR` set to
  the job's work directory) plus any `env_passthrough` names. Secrets in the
  parent environment are not inherited.
- Each adapter runs in its own process group. On timeout the whole group is
  killed.
- Input file names are sanitized. Job ids are validated before they are used
  in a path. Output paths that escape the output directory, or are symlinks,
  are rejected.
- The API binds to `127.0.0.1` by default. It refuses a non-loopback host
  unless `AEGIS_API_TOKEN` is set, which then requires a bearer token on `/v1/*`.

## Known limitations (initial version)

- API jobs run in-process as FastAPI background tasks. If the server stops
  mid-run, the job stays `running`: there is no recovery or queue yet.
- Adapter stdout and stderr are read into memory. `max_stdout_bytes` is checked
  after the process exits, not while it streams.
- The API accepts inputs as base64 in JSON, capped by `max_input_bytes`. Put a
  reverse proxy body limit in front of it if it is ever exposed.

See [docs/adapter-protocol.md](docs/adapter-protocol.md) for how to write an
adapter.

## Output signing and Sentinel policies (optional)

Core validates the `[provenance]` and `[sentinel]` sections of `aegis.toml`
(both off by default) and exposes `Orchestrator.post_success_hooks`,
`Orchestrator.find_output` and `Orchestrator.read_output` (bytes re-hashed
against the record, `O_NOFOLLOW`, 256 MiB cap). Core itself never loads keys
or imports cryptography: signing and policies are implemented by
`aegis_provenance.jobs`, which the API and CLI register as a hook. See
[ARCHITECTURE.md §8a](../ARCHITECTURE.md) and
[docs/release/FINAL_API_CONTRACT.md](../docs/release/FINAL_API_CONTRACT.md).
