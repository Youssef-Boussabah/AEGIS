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
| `AUTHORIZATION_REQUIRED` | attack-lab disabled, or authorization missing/expired | 403 | 5 |
| `INPUT_NOT_FOUND` / `INPUT_TOO_LARGE` | input problems | 400 / 413 | 6 / 2 |
| `JOB_NOT_FOUND` | unknown job id | 404 | 6 |
| `JOB_CONFLICT`, `REPORT_NOT_READY` | job is not in the right state | 409 | 7 |
| `ADAPTER_UNAVAILABLE` | executable missing or not executable | job fails | 1 |
| `ADAPTER_TIMEOUT` | adapter killed after its timeout | job fails | 1 |
| `ADAPTER_FAILED` | nonzero exit or `status: "failed"` | job fails | 1 |
| `ADAPTER_INVALID_OUTPUT` | bad JSON, missing/escaping outputs, success with no outputs | job fails | 1 |
| `ARTIFACT_INTEGRITY_ERROR` | input hash changed during the run | job fails | 1 |
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
