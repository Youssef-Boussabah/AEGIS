# LLVM Shield adapter

Milestone 002 connects the real LLVM Shield plugin to `aegis_core` through
`aegis.adapter.v1`. The adapter uses Python ≥3.11's standard library and POSIX
resource limits. It imports neither core nor the backend. It requires **LLVM
22.x opt** and a Shield plugin built with that same LLVM installation. Tested
on Linux x86-64 with LLVM 22.1.8 and Python 3.14.7.

The backend has **no established security property**. A successful job means
Shield reported at least one arithmetic expansion, its report passed validation,
and LLVM verified nonempty output IR. It does not establish attack resistance,
native runtime equivalence, or preservation of an IR shape after optimization.

## Register and invoke

Build the plugin using [the backend instructions](../README.md#build-and-test).
After `aegis init`, add this entry to `aegis.toml`, replacing the absolute
repository paths with your own:

```toml
[adapters.llvm-shield]
command = ["/absolute/repo/.venv/bin/python", "/absolute/repo/protectors/llvm/adapter/aegis_llvm_adapter.py", "--opt", "/usr/bin/opt", "--plugin", "/tmp/aegis-shield-build/AegisShield.so"]
tasks = ["protect"]
timeout_seconds = 300
env_passthrough = []
max_stdout_bytes = 65536
```

Keep the adapter directory and `../schemas/report.schema.json` together when
deploying. No backend is registered automatically. The adapter has no attack-lab
capability; do not declare `attack_lab` for it. `aegis inspect` checks the adapter
executable only; plugin/tool/config validation happens when a job runs.

```sh
# Compile only source you trust with your frontend; the adapter accepts IR.
clang -O1 -S -emit-llvm protectors/llvm/tests/fixtures/annotated.c \
  -o /tmp/aegis-adapter-input.ll
.venv/bin/aegis protect /tmp/aegis-adapter-input.ll --backend llvm-shield \
  --option 'seed="18446744073709551615"' --option max-sites=16
.venv/bin/aegis report JOB_ID
```

The **inner double quotes on the seed are required**: the CLI interprets JSON
scalars, so `seed=42` becomes an integer, which this adapter rejects. API/core
callers similarly use `options={"seed": "42"}`. Large seeds never travel through
a floating-point value. Output artifacts are `protected.ll` and
`shield-report.json` under the job's `outputs/`, both hashed by the orchestrator.
Reports can expose function names; keep the store private.

## Options and conversion

Unknown options, incorrect types and out-of-range values fail with
`INVALID_OPTIONS`. No request option can select a tool, plugin, pipeline, config
file, or output path.

| Core option | Default | Accepted | Shield config field |
| --- | --- | --- | --- |
| `seed` | `"0"` | 1–20 ASCII decimal digits, uint64 range; canonicalized as a decimal string | `seed` |
| `max-sites` | `16` | integer 0–1,000,000; booleans rejected | `max_sites_per_function` |
| `enabled` | `true` | boolean | `enabled` |

The adapter writes a **local** config with integer `schema_version: 1`; it does
not change either existing schema. The original local Shield report is an
artifact; bounded adapter evidence contains the transformation total, LLVM
version, effective config and counts by function reason. Full per-function
details stay in that artifact. Core records these as `source: "adapter"` claims.

## Paths, execution and limits

Run through the core orchestrator, which supplies an absolute request path and
sets cwd to `<job>/work`. The adapter validates the current job layout, absolute
input/output paths, safe input name, and empty output directory. Symlinked paths,
hardlinked artifacts and special files are rejected. It copies and hashes the
input into a private temporary directory under `work/` before LLVM reads it.
The input hash must match the request. The original input is never modified.

All LLVM argv elements derived from paths inside the job are **fixed relative
names**. The only pass pipeline is:

```text
aegis-shield<config=shield-config.json;report=shield-report.json>,verify
```

The staged module identifier is `shield-input.ll`; it deliberately does not
preserve the input artifact's filename. Store roots containing spaces or LLVM
pipeline metacharacters work because they never enter the pipeline. Relative
storage roots retain core's documented resolution against `aegis.toml`'s parent.
Core does **not** rebase arbitrary `command` arguments against that parent, so
use absolute Python, script and plugin paths. `--opt` accepts an absolute path
or a bare executable name resolved on the adapter's inherited PATH; tool paths
with slashes must be absolute. Tool/plugin paths are operator-trusted.

LLVM is launched with argv arrays, `shell=False`, null stdin, a minimal
environment, and no additional environment passthrough. Children **inherit the
core's process group**. Core owns the wall timeout (including the version probe,
transformation and final verification) and kills the entire group on expiry.
Do not invoke this protocol executable without a supervising timeout/group.

The operator may append these arguments to the registered command:

| Argument | Default |
| --- | --- |
| `--max-input-bytes` | 67,108,864 (64 MiB) |
| `--max-output-bytes` | 134,217,728 (128 MiB) |
| `--max-report-bytes` | 4,194,304 (4 MiB) |

Each limit must be 1–4,294,967,296 bytes. Request JSON is capped at 512 KiB;
each LLVM diagnostic stream at 64 KiB. File-backed capture avoids unbounded
pipe buffering. POSIX `RLIMIT_FSIZE` imposes a hard per-file cap equal to the
largest output/report/diagnostic limit (including LLVM's temporary reports).
Polling enforces smaller individual limits during execution and final size
checks reject oversized results; a smaller limit may be exceeded briefly,
up to the hard cap, before the process is killed. This is not an aggregate disk,
CPU or memory quota. Core's existing generic stdout/stderr buffering remains
unchanged, but this adapter emits a bounded result and bounded diagnostics.

Only textual LLVM IR is supported; binary magics and NULs are rejected, then
LLVM's parser validates the content. Filenames/extensions alone are not trusted.
The adapter never invokes a compiler, linker, native input or output executable.
LLVM parsing runs on the host: this bridge is **not a sandbox** against LLVM
parser bugs, malicious plugins, or concurrent writers with access to the store.
Use trusted operator tools/plugins and keep the job directories private.

## Failure semantics

The adapter prints exactly one protocol JSON result. A handled failure exits 0
with `status: "failed"`, and no registered outputs. Under the unchanged core
protocol this becomes `ADAPTER_FAILED`; the specific adapter code is at
`error.details.adapter_error.code`. Core's own timeout is `ADAPTER_TIMEOUT`.
Argument-parser failures exit nonzero and are also core `ADAPTER_FAILED`.

| Adapter code | Meaning |
| --- | --- |
| `NO_TRANSFORMATIONS_APPLIED` | Valid report records zero sites, including disabled/zero-budget/unselected inputs |
| `INVALID_REQUEST`, `UNSUPPORTED_TASK`, `INVALID_OPTIONS` | Invalid wire request, unsupported task, or policy options |
| `INVALID_CONFIGURATION`, `TOOL_UNAVAILABLE`, `PLUGIN_UNAVAILABLE`, `UNSUPPORTED_LLVM` | Invalid paths, missing tools/plugin, or unsupported opt version |
| `UNSUPPORTED_FORMAT`, `INPUT_TOO_LARGE`, `ARTIFACT_INTEGRITY_ERROR` | Input rejected or hash mismatch |
| `LLVM_FAILED` | Tool failed, including invalid IR, ABI/plugin failure, or failed output verification |
| `INVALID_SHIELD_REPORT` | Schema mismatch or inconsistent version, configuration, module, totals, status, selection or site indices |
| `INVALID_ARTIFACT`, `EMPTY_ARTIFACT`, `UNSAFE_PATH`, `OUTPUT_TOO_LARGE` | Missing/empty/unsafe/oversized artifacts or diagnostics |
| `ADAPTER_IO_ERROR` | Other file/resource/JSON processing failure |

A zero exit from `opt` alone never means success. A success requires nonzero
reported sites, consistent local schema data, nonempty regular artifacts,
changed output bytes and an independent LLVM verifier run. These checks cannot
independently prove that a trusted plugin's claimed transformations occurred.
Failed jobs may leave partial private work files after a hard timeout or partial
publication after an I/O error; core registers no output artifacts for them.

## Tests

The adapter integration suite needs the existing core/CLI development environment
and real tools. The original Shield CTest suite remains independent of Python
package dependencies.

```sh
.venv/bin/python -m pytest protectors/llvm/adapter/tests \
  --shield-plugin /tmp/aegis-shield-build/AegisShield.so \
  --shield-opt /usr/bin/opt --shield-clang /usr/bin/clang
.venv/bin/pytest
ctest --test-dir /tmp/aegis-shield-build --output-on-failure
```

The suite compiles the checked-in trusted C fixture to IR and submits it through
the real core orchestrator and CLI. Fault-injection wrappers damage real LLVM
results or exercise errors/timeouts; they never manufacture protection success.
See [VALIDATION.md](VALIDATION.md) for the recorded run and limitations.
