# Optional Rust component workflow

This standalone developer tool automates the pre-optimization Rust experiment in
[full-system validation](../../docs/release/FULL_SYSTEM_VALIDATION.md#c1-photocraft--partial-component-level).
It captures one library unit-test compilation, selects integer-signature functions,
submits real protection jobs through Core's existing adapters, compiles both IR
variants with Clang, replays rustc's linker command, and compares every test outcome.
Nothing registers globally or changes Cargo, rustup, the release, or another module.
See [RESULTS.md](RESULTS.md) for measured scope and unresolved problems.

Shield and Mirage have **no established security property**. Selection, transformed
IR, retained symbols and passing tests are separate observations, not attack resistance.

## Requirements and supported scope

- Existing repository `.venv` with `aegis-core` and pytest installed; Python >=3.11.
  This module installs nothing and has no runtime dependency on pytest.
- Native Linux x86-64 GNU library unit-test builds (`cargo test --release --lib`).
  Validated compiler: rustc 1.98.1, host `x86_64-unknown-linux-gnu`, LLVM 22.1.8.
- `opt`, `llvm-dis`, Clang, and the existing Shield plugin built against the same
  LLVM installation. Every LLVM stage must report the **exact** rustc LLVM version,
  currently LLVM 22.x. The adapter independently checks its plugin report version.
  Combined mode additionally requires matching `llvm-link` and `llvm-nm`.
- Owned/trusted crates, existing dependencies, native libraries and linker. This
  runs trusted Cargo builds, LLVM parsers and native tests on the host, without a
  sandbox. It is not for model-generated code or hostile build scripts/artifacts.
- A fresh private scratch directory outside source trees. Generated IR, reports,
  objects and binaries stay there. Adapter reports expose private function names.

No nightly flags, custom targets, custom sysroots, multiple codegen units at the
protection stage, custom linkers, PGO, sanitizers, `target-cpu`/`target-feature`
overrides, panic=abort, proc-macro/CDylib targets or arbitrary Cargo build wrappers
are supported. Ordinary dependency proc macros may run as part of trusted Cargo
compilation. Unsupported compiler options fail explicitly rather than being ignored.
Only the selected test component is substituted; other crates and std link normally.
Generic std/dependency functions instantiated in that component may be selected.

## Reproduce on the owned fixture

From the repository root, with the existing matching plugin already built:

```sh
repo="$PWD"
scratch="$(mktemp -d /tmp/aegis-rust.XXXXXX)"
AEGIS_RUST_CRATE=aegis_rust_component \
AEGIS_RUST_CAPTURE="$scratch/invocation.json" \
RUSTC_WRAPPER="$repo/integrations/rust/capture.py" \
CARGO_TARGET_DIR="$scratch/target" \
cargo test --manifest-path integrations/rust/fixtures/component/Cargo.toml \
  --release --lib --no-run --offline --locked

.venv/bin/python integrations/rust/protect.py \
  --invocation "$scratch/invocation.json" --output "$scratch/shield" \
  --plugin /tmp/aegis-shield-build/AegisShield.so --samples 5

.venv/bin/python integrations/rust/protect.py \
  --invocation "$scratch/invocation.json" --output "$scratch/combined" \
  --plugin /tmp/aegis-shield-build/AegisShield.so \
  --backend llvm-shield-mirage --samples 5
```

`capture.py` must retain its executable bit. It is an opt-in `RUSTC_WRAPPER` for
this command only; do not put it in global Cargo configuration. It delegates
ordinary compiler invocations and exclusively records the successful `--test`
invocation whose exact `--crate-name` matches `AEGIS_RUST_CRATE`. Cargo crate names
use underscores where package names use hyphens. The JSON is mode 0600.
Use a fresh target directory: if Cargo says `Fresh`, it may never invoke the
wrapper, so no new capture will be produced. Existing captures are never overwritten.
The wrapper preserves Cargo's inherited jobserver file descriptors.

The capture records the concrete compiler, cwd, argv and a fixed allowlist of
Cargo compile-time metadata (`CARGO_PKG_*`, manifest paths, `OUT_DIR`, etc.). Other
environment dependencies, including custom `cargo:rustc-env` variables, require
manual integration and may cause replay to fail. Captures are trusted build
instructions: inspect them before using captures received from another person.
Keep the original Cargo target directory, dependencies and source checkout intact.
The runner snapshots the original Cargo test binary and never overwrites it.

The fixture's four tests check 24 u32 edge pairs, every 8-bit input pair (65,536),
12 u64 edge pairs, 100,000 deterministic wide pairs against u128 arithmetic, and
captured Cargo metadata. Its release profile explicitly disables overflow checks.
These are owned regression inputs, not third-party application workloads.

## What the runner does

1. Reject unsupported compiler configurations, snapshot the original Cargo binary,
   and check rustc/LLVM versions. Save the capture hash and tool paths/versions.
2. Replay the captured invocation into a new private directory, retaining source,
   dependency, cfg and metadata arguments. Explicitly set `opt-level=3`, `lto=off`,
   `codegen-units=1`, `save-temps`, `emit=llvm-ir,link`, and `print=link-args`.
   This changes the compilation recipe if the capture used ThinLTO or more CGUs;
   the ordinary Cargo binary remains a separate comparison variant.
3. Locate exactly one primary `*-cgu.0.rcgu.o` and its `*.no-opt.bc`. Use `llvm-dis`
   on that **pre-LLVM-optimization** module. The ordinary optimized `.ll` is not
   the integration point: inlining may already have removed eligible functions.
4. Mark every canonical single-line definition with scalar integer return and
   parameter types, excluding variadic and `optnone` functions. This opt-in tool
   selects by signature, never by benchmark/function name. It adds the existing
   `"aegis.protect"` function attribute without changing bodies. LLVM verifies it.
5. Create a private local Core configuration with attack-lab disabled; run the
   existing `llvm-shield` or `llvm-shield-mirage` adapter. Core supervises the adapter
   timeout/process group and hashes all outputs. The consumer rechecks those hashes.
   Transformation counts remain explicitly **adapter claims**. This workflow does
   not configure signing, Sentinel, the API or a global backend registration.
6. Compile unmarked baseline and protected IR with matching `clang -O3 -fPIC -c`.
   Replace precisely the primary CGU object in the printed linker argv. Preserve
   rustc's allocator/shim/symbol objects, dependency archives, runtime libraries,
   rpath/linker search flags and `--gc-sections`. Do not replace all `.rcgu.o` files.
   Linker text is parsed as shell-quoted data and executed with argv, never a shell.
7. For combined mode, independently check all reported Mirage decoy symbols in the
   final executable using matching `llvm-nm`. Absence fails `DECOYS_NOT_RETAINED`.
8. Run original Cargo, matched baseline and protected binaries with libtest pretty
   output, one test thread, no color; alternate forward/reverse order across samples.
   Compare named pass/fail/ignored outcomes, counts and exit codes. Record every
   sample time and binary hash, and check binaries did not change while executing.

Every replayed compiler/linker/test command has a wall timeout (default 300 seconds
per stage), its own process group, minimal environment and file-backed diagnostics
limited to 8 MiB per stream. Timeout/exception/normal completion cleans up its group.
Diagnostic limits are polled and may overshoot between checks; oversized logs fail.
Cargo's initial capture build uses Cargo's ordinary environment and supervision;
it is distinct from the bounded protection workflow. Input/adapter output limits
are per file; there is no aggregate disk, memory or CPU quota. Budget scratch space
for multiple IR copies when processing large crates.

## Reports and failures

Each new output directory gets `run.json` on a handled failure or completion, plus
numbered stdout/stderr files, compiler scratch and Core's private store. Invalid
CLI arguments use argparse's usage error and cannot create a report. An unusable or
pre-existing output directory produces a small JSON error and a nonzero exit.
Reports are local developer
records, not shared/public API schemas. Keyboard interruption is not a completed run.

Exit 0 requires a successful real adapter job and passing matched baseline and
protected test outcomes. An original Cargo failure is also a failure. An equal
set of upstream failures yields `tests.equivalent=true`, `baseline_passed=false`,
`status=failed`, error `BASELINE_TEST_FAILURE`, and a nonzero exit. That result is
evidence of matching observed failures, never a passing suite or a behavioral score.
Every individual test name/outcome remains in the private report.

| Error | Meaning / action |
| --- | --- |
| `UNSUPPORTED_RUST`, `UNSUPPORTED_LINK` | Use the documented native release library-test recipe; application/crate-library injection is not implemented. |
| `UNSUPPORTED_LLVM` | Align rustc, all LLVM stages and the built plugin. No IR version conversion is attempted. |
| `INPUT_TOO_LARGE` | Raise `--max-input-bytes` deliberately for Shield if scratch/resources permit. Both Core and adapter limits are set together. |
| `MIRAGE_INPUT_TOO_LARGE` | Selected module already exceeds Mirage's fixed 64 MiB cap; choose Shield or a smaller component. No automatic backend fallback or IR splitting. Even a smaller input can grow beyond the cap at the Shield/Mirage stage; that remains `MIRAGE_FAILED` from the adapter. |
| `NO_ELIGIBLE_FUNCTIONS` | No definitions were marked; no job was run. |
| `ADAPTER_FAILED` | Inspect `adapter_job.error`, including `details.adapter_error.code`; zero eligible sites remain `NO_TRANSFORMATIONS_APPLIED`. No outputs are registered by failed Core jobs. |
| `LLVM_FAILED`, `LINK_FAILED`, `RUSTC_FAILED` | Private stage log identifies the incompatible stage. Partial artifacts are diagnostic scratch, not successful outputs. |
| `STAGE_TIMEOUT`, `OUTPUT_TOO_LARGE` | A local stage was killed; increase a timeout deliberately or inspect diagnostics. Core timeouts remain `ADAPTER_TIMEOUT` inside job details. |
| `BEHAVIOR_MISMATCH`, `NONDETERMINISTIC_BASELINE`, `INVALID_TEST_OUTPUT` | Observations cannot establish matching behavior. No failure is converted into a pass. |
| `BASELINE_TEST_FAILURE`, `ORIGINAL_TEST_FAILURE` | Real unprotected tests failed; read named outcomes, even if the protection job itself succeeded. |

Default `--max-input-bytes` is 67,108,864; maximum is 4 GiB. Algo required
536,870,912 in this host's experiment. Adapter output cap is twice the configured
input cap (bounded to 4 GiB); its report cap is 32 MiB. Mirage's independent fixed
64 MiB limit is unchanged. The combined adapter supports rustc's vendor-only triple
difference (`x86_64-unknown-linux-gnu` versus Clang's `x86_64-pc-linux-gnu`) in this
checkout; architecture/OS/environment differences still fail.

## PhotoCraft components

Use an independently obtained, licensed checkout outside this repository and an
existing dependency cache. The validated pin and manifest license fields are in
RESULTS.md. Keep all sources, generated IR and binaries outside the release.
For each package, capture as above with its workspace manifest and `-p` selector:

```sh
AEGIS_RUST_CRATE=photocraft_color \
AEGIS_RUST_CAPTURE="$scratch/color-invocation.json" \
RUSTC_WRAPPER="$repo/integrations/rust/capture.py" \
CARGO_TARGET_DIR="$scratch/photocraft-target" \
CARGO_HOME=/tmp/aegis-fsv/cargo-home \
cargo test --manifest-path /tmp/aegis-fsv/targets/photocraft/Cargo.toml \
  -p photocraft-color --release --lib --no-run --offline --locked
```

For algo use `photocraft_algo`, `-p photocraft-algo`, and a new capture filename.
Run `protect.py` on that capture, choosing Shield with
`--max-input-bytes 536870912`. The guide's `/tmp/aegis-fsv` paths refer to the
existing local validation checkout/cache, not distributed dependencies.

Whole-application Cargo builds, doctests, integration-test targets, protected rlib
construction, workspace-wide incremental protection and automatic per-crate build
substitution remain **not implemented**. A captured invocation can be reused only
while its compiler/source/dependency paths remain valid. This tool does not make
Cargo's cache content-addressed or establish source/build provenance.

## Regression tests

```sh
# Parser/failure/process tests, no LLVM or Rust required:
.venv/bin/python -m pytest integrations/rust/tests/test_pipeline.py -q

# Explicit real owned-crate suite; missing prerequisites fail, never silently skip:
.venv/bin/python -m pytest integrations/rust/tests/test_real.py -q \
  --rust-shield-plugin /tmp/aegis-shield-build/AegisShield.so

# Both suites:
.venv/bin/python -m pytest integrations/rust/tests -q \
  --rust-shield-plugin /tmp/aegis-shield-build/AegisShield.so
```

Default pytest within this module selects the parser/process suite; root test and
build configuration is untouched. Real tests copy only the owned fixture into
scratch and execute its reference checks through both actual adapters. Synthetic
unit fixtures are never presented as protection or security evidence.
