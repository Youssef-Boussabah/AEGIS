# Native backend contract: `llvm-shield` and `llvm-shield-mirage`

Owner: Agent 4 (native protection integration). Consumers: Agent 1 (Core/API/CLI)
and Agent 3 (dashboard). Status: **implemented and tested** in the working tree on
30 October 2026 (results in [NATIVE_INTEGRATION.md](NATIVE_INTEGRATION.md)).

Nothing here changes `aegis.adapter.v1`, `aegis_core.models`, the API routes or the
storage layout. Both backends are ordinary registered adapters. Neither has an
established security property.

## Registered backends

`scripts/product.py configure` writes the workspace `aegis.toml`. It registers a
backend **only after a real probe job succeeds** through `python -m aegis_cli protect`
on the owned fixture `protectors/llvm/tests/fixtures/annotated.c` (seed `"42"`), in a
throwaway store. `llvm-shield` is required: if its probe fails, configure writes no
config. `llvm-shield-mirage` is registered only if its probe also passes the chain
check below; otherwise configure prints a warning and omits it. An existing
`aegis.toml` is never overwritten.

| Backend | Tasks | Command (all paths absolute) | Timeout |
| --- | --- | --- | --- |
| `llvm-shield` | `["protect"]` | `.venv/bin/python protectors/llvm/adapter/aegis_llvm_adapter.py --opt OPT --plugin AegisShield.so` | 300 s |
| `llvm-shield-mirage` | `["protect"]` | `.venv/bin/python protectors/llvm/adapter/aegis_shield_mirage_adapter.py --opt OPT --plugin AegisShield.so --clang CLANG --llvm-link LLVM_LINK` | 300 s |

`env_passthrough = []`, `max_stdout_bytes = 65536`. Neither backend declares or
accepts `attack_lab`. `/healthz` checks only that `command[0]` exists, as before.

## Input

Textual LLVM 22 IR only (`.ll`), up to 64 MiB. At least one function must carry the
`aegis.protect` annotation and an eligible flag-free integer `add`; otherwise the job
fails with `NO_TRANSFORMATIONS_APPLIED`. The target triple must be the host's
(Mirage compiles its decoys for the default target); a four-part triple that differs
only in its vendor field, such as rustc's `x86_64-unknown-linux-gnu` on a host whose
Clang defaults to `x86_64-pc-linux-gnu`, is accepted and the decoys are compiled for
the module's exact triple. Binary/bitcode/ELF input fails
with `UNSUPPORTED_FORMAT`. No input or output is compiled to native code or executed.

## Options (`policy.options`)

| Option | Backends | Type / range | Default |
| --- | --- | --- | --- |
| `seed` | both | decimal **string**, 1–20 digits, ≤ 18446744073709551615 | `"0"` |
| `max-sites` | both | integer 0–1,000,000 | `16` |
| `enabled` | both | boolean (Shield stage) | `true` |
| `mirage-seed` | `llvm-shield-mirage` | decimal **string**, ≤ 9223372036854775807 | the `seed` value; if `seed` exceeds 2^63−1 this option is required |
| `mirage-count` | `llvm-shield-mirage` | integer 1–32 | `3` |
| `mirage-enabled` | `llvm-shield-mirage` | boolean | `true` |

Any other key, a wrong type or an out-of-range value fails with `INVALID_OPTIONS`.
`llvm-shield` rejects the `mirage-*` options. The dashboard can send the same
`{"seed": "42", "max-sites": 16}` body to either backend.

## Outputs (registered and hashed by Core)

| Backend | `output_artifacts[].name` |
| --- | --- |
| `llvm-shield` | `protected.ll`, `shield-report.json` |
| `llvm-shield-mirage` | `protected.ll` (final Shield+Mirage IR), `shield-stage.ll` (verified Shield output, Mirage's input), `shield-report.json`, `mirage-report.json` (`aegis.mirage.report.v1`) |

**Chain check anyone can do from Core's own hashes:** in `mirage-report.json`,
`input_sha256` equals Core's SHA-256 of `shield-stage.ll`, and `output_sha256`
equals Core's SHA-256 of `protected.ll`. `product.py smoke` and configure's probe
check exactly this. `shield-stage.ll` is byte-identical to the `protected.ll` that
`llvm-shield` produces for the same input and Shield options.

## Evidence (`source: "adapter"`, i.e. claims)

- `llvm-shield`: one record, unchanged (`transformed_sites`, `llvm_version`,
  `function_reasons`, `config`, `report_schema`, `limitations`).
- `llvm-shield-mirage`: the same Shield record, then one Mirage record:
  `{enabled, configured_count, inserted_count, seed, report_schema,
  chain: {shield_stage_sha256, mirage_input_sha256, final_output_sha256},
  decoy_source_sha256, final_artifact_retention: "requires_independent_check",
  limitations}`. Decoy function **names are not in the evidence**; they are only in
  the private `mirage-report.json` artifact.

The dashboard should show `inserted_count` and the chain digests, label them as
adapter claims, and never present either record as protection or resistance.

## Failure codes (`error.code = "ADAPTER_FAILED"`, specific code in `error.details.adapter_error.code`)

All `llvm-shield` codes apply to both backends (see
[adapter README](../../protectors/llvm/adapter/README.md#failure-semantics)).
`llvm-shield-mirage` adds:

| Code | Meaning |
| --- | --- |
| `MIRAGE_FAILED` | Mirage refused or failed; `message` names a fixed reason such as `decoy_symbol_collision`, `target_triple_mismatch`, `matching_llvm22_required`, `decoy_insertion_failed` |
| `TOOL_UNAVAILABLE` / `INVALID_CONFIGURATION` | `--clang` / `--llvm-link` missing or not absolute, or the Mirage source is not beside the adapter |
| `INVALID_ARTIFACT` / `ARTIFACT_INTEGRITY_ERROR` | the Mirage report does not bind the Shield output and the final module, or a file changed between verification and publication |
| `UNSUPPORTED_LLVM` | Mirage's clang/llvm-link/opt are not the same LLVM 22 version as Shield's opt |

Disabled controls: `enabled: false` or `max-sites: 0` fails with
`NO_TRANSFORMATIONS_APPLIED` on both backends (Mirage never runs). `mirage-enabled:
false` **succeeds**: `protected.ll` is byte-identical to `shield-stage.ll`,
`inserted_count` is 0 and the Mirage evidence summary starts with
"Mirage disabled (control)".

## Process and isolation guarantees (unchanged from `llvm-shield`)

argv arrays, `shell=False`, null stdin, minimal environment (`PATH`, `LANG`,
`LC_ALL`, `HOME`, `TMPDIR`), fixed relative file names inside a private job work
directory, bounded files and diagnostics (`RLIMIT_FSIZE` plus polling), and
Core-owned timeout. Mirage's LLVM tools run through the same runner, **inside
Core's process group** (not in a separate session), so Core's timeout kills them
(tested). The adapter never modifies the input; Core re-hashes it after the run.

## What this does not establish

No attack resistance, no reverse-engineering cost, no AI-reconstruction effect. Mirage
decoys are uncalled and can be identified as unreachable. Final-binary retention
depends on the consumer's own build; it is checked by the native tests for the owned
`signal.c` fixture and ImageLab only.
