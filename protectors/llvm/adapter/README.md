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

## Combined Shield + Mirage backend (`llvm-shield-mirage`)

`aegis_shield_mirage_adapter.py` is a second protocol executable that reuses this
adapter's request validation, Shield stage, runner and limits unchanged, then runs
the [Mirage](../../mirage/README.md) transformer on **exactly** the verified Shield
output. The full consumer contract is
[docs/release/NATIVE_BACKEND_CONTRACT.md](../../../docs/release/NATIVE_BACKEND_CONTRACT.md).

```toml
[adapters.llvm-shield-mirage]
command = ["/absolute/repo/.venv/bin/python", "/absolute/repo/protectors/llvm/adapter/aegis_shield_mirage_adapter.py", "--opt", "/usr/bin/opt", "--plugin", "/tmp/aegis-shield-build/AegisShield.so", "--clang", "/usr/bin/clang", "--llvm-link", "/usr/bin/llvm-link"]
tasks = ["protect"]
timeout_seconds = 300
env_passthrough = []
max_stdout_bytes = 65536
```

`--clang` and `--llvm-link` must be absolute and from the same LLVM 22 installation
as `--opt`. The adapter imports Mirage from `protectors/mirage/src` beside this
directory (never from another installation) and fails with `TOOL_UNAVAILABLE` if it
is missing. Deploy the two directories together.

Chain: hash-checked input → Shield (validated report, plugin-free verification,
changed output) → Mirage on that file → Mirage report must name the Shield
output's SHA-256 as its input and the final module's SHA-256 as its output →
plugin-free verification of the final module → exclusive publication of
`protected.ll`, `shield-stage.ll`, `shield-report.json` and `mirage-report.json`.
Core hashes all four, so the chain can be rechecked from Core's records alone.
Mirage's `clang`/`llvm-link`/`opt` calls go through this adapter's `run_tool`:
they stay **in Core's process group** (Mirage's standalone runner starts its own
session, which a Core timeout could not kill), with the same minimal environment
and file limits. Mirage compiles only its own generated decoy source to IR; no
input, output or native artifact is executed.

Additional options: `mirage-seed` (decimal string ≤ 2^63−1; default the `seed`
value, required when `seed` is larger), `mirage-count` (1–32, default 3) and
`mirage-enabled` (default `true`; `false` is a succeeding control whose
`protected.ll` equals `shield-stage.ll`). Additional failure code: `MIRAGE_FAILED`
(message names Mirage's fixed reason, such as `decoy_symbol_collision` or
`target_triple_mismatch`). Shield no-op inputs still fail with
`NO_TRANSFORMATIONS_APPLIED` before Mirage runs. Mirage requires the module's
target triple to match clang's default target, or to differ from it only in the
vendor field of a four-part triple (for example rustc's `x86_64-unknown-linux-gnu`
against Clang's `x86_64-pc-linux-gnu`); the decoys are then compiled for the
module's exact triple. Any other difference fails with `target_triple_mismatch`.
Mirage reads and writes at most 64 MiB per module regardless of the adapter's
`--max-input-bytes`/`--max-output-bytes`; a larger Shield output fails with
`MIRAGE_FAILED` (`input_too_large`), and no outputs are registered.

Evidence adds one adapter claim with the inserted count, seed, decoy-source digest
and the chain digests. Decoy names stay in the private `mirage-report.json`.
Decoys are uncalled and can be identified as unreachable; this backend has no
established security property. Retention in a final executable depends on the
consumer's build and is checked separately (see `scripts/native_tests`).

## Tests

The adapter integration suite needs the existing core/CLI development environment
and real tools. The original Shield CTest suite remains independent of Python
package dependencies.

```sh
.venv/bin/python -m pytest protectors/llvm/adapter/tests \
  --shield-plugin /tmp/aegis-shield-build/AegisShield.so \
  --shield-opt /usr/bin/opt --shield-clang /usr/bin/clang \
  --shield-llvm-link /usr/bin/llvm-link
.venv/bin/pytest
ctest --test-dir /tmp/aegis-shield-build --output-on-failure
```

The suite compiles the checked-in trusted C fixture to IR and submits it through
the real core orchestrator and CLI. Fault-injection wrappers damage real LLVM
results or exercise errors/timeouts; they never manufacture protection success.
`test_shield_mirage_adapter.py` covers the combined backend: chain digests,
determinism, equality of its Shield stage with standalone `llvm-shield`, disabled
controls, option validation, missing/mismatched tools, decoy collisions, triple
mismatch, corrupted Mirage-stage results, byte limits, minimal environment, and
Core's timeout killing a Mirage-stage descendant. `--shield-llvm-link` defaults to
`llvm-link` on PATH. See [VALIDATION.md](VALIDATION.md) for the recorded Shield-only
run and limitations, and
[NATIVE_INTEGRATION.md](../../../docs/release/NATIVE_INTEGRATION.md) for the
current combined results.
