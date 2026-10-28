# AEGIS Shield: initial LLVM backend

This directory is a standalone C++20 LLVM new-pass-manager plugin. Version 0.1
implements a deterministic arithmetic expansion on explicitly selected integer
functions. It is a compiler prototype, with **no established security property**.
No root build, other protector, or shared contract is required or modified.

## Build and test

Tested with the installed LLVM/Clang **22.1.8**, CMake 4.4.3, Ninja, and Python
3.14.7 on Linux x86-64. Use LLVM development headers and tools from the same
installation; plugins have an LLVM ABI dependency. LLVM 22 moved the plugin
header to `llvm/Plugins/PassPlugin.h`; older releases are intentionally rejected.
Later versions are not validated. Nothing here installs packages.

From the repository root:

```sh
cmake -S protectors/llvm -B /tmp/aegis-shield-build -G Ninja \
  -DLLVM_DIR="$(llvm-config --cmakedir)" \
  -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/aegis-shield-build -j2
ctest --test-dir /tmp/aegis-shield-build --output-on-failure

# Detailed output for the 14 Python integration cases:
python3 protectors/llvm/tests/test_shield.py \
  --plugin /tmp/aegis-shield-build/AegisShield.so \
  --opt /usr/bin/opt --clang /usr/bin/clang
```

Python uses only its standard library. CMake finds `opt` and `clang` in LLVM's
tool directory for CTest. The remaining command examples assume those matching
tools are on `PATH`. `/tmp` keeps generated files outside the source tree.

## Select functions and run

Opt in from C/C++ with the exact string `aegis.protect`:

```c
__attribute__((annotate("aegis.protect"), noinline))
unsigned sum(unsigned a, unsigned b) { return a + b; }
```

The pass reads Clang's `llvm.global.annotations`. For hand-written IR, attach
the string function attribute `"aegis.protect"`. Attribute presence selects the
function regardless of the attribute's value. Source annotations match exactly;
`aegis.protect.extra` does not select a function. `noinline` is useful to retain
selected function boundaries during frontend optimization; it is not required
by the pass. Annotated functions must return a scalar integer, accept only
scalar integer arguments, and be non-variadic definitions without `optnone`.
They may contain control flow and other instructions; only eligible adds change.

An end-to-end example using the checked-in source fixture:

```sh
clang -O1 -S -emit-llvm protectors/llvm/tests/fixtures/annotated.c \
  -o /tmp/aegis-input.ll
opt -load-pass-plugin /tmp/aegis-shield-build/AegisShield.so \
  '-passes=aegis-shield<seed=42;max-sites=16;report=/tmp/aegis-report.json>,verify' \
  -S /tmp/aegis-input.ll -o /tmp/aegis-transformed.ll
clang -O2 -c /tmp/aegis-transformed.ll -o /tmp/aegis-transformed.o
```

Link the resulting object with the application's other objects as usual. The
plugin registers an explicit **module pass** named `aegis-shield`. It does not
automatically insert itself into Clang's pipeline: `-fpass-plugin` alone will
load it without running the transformation. Place the pass deliberately with
`opt`; for example, `aegis-shield,default<O2>,verify` runs LLVM's O2 pipeline
after expansion. Earlier frontend optimization can remove or combine adds.
Clang's default `-O0` emits `optnone` functions, which this pass skips; use `-O1`
for the frontend as above, or explicitly manage `optnone` in a custom IR flow.
Unsigned source arithmetic gives modular adds; signed C adds commonly carry
overflow flags and are skipped.

## Options and local contracts

No shared schemas or substantive root guidance existed in the initial
repository: root `AGENTS.md`, `README.md`, and architecture files were empty.
The files in [schemas/](schemas/) are **local, provisional contracts**, not
assumed integrations with other AEGIS modules. Their v1 identifiers and field
names must be reconciled with any future shared contract by its owner.

Options are semicolon-separated inside a single quoted pass element:

| Option | Default | Meaning |
| --- | --- | --- |
| `seed` | `0` | Unsigned decimal uint64, including `18446744073709551615` |
| `max-sites` | `16` | Per-function eligible-add budget, 0–1,000,000; zero makes no changes |
| `enabled` | `true` | Exact `true` or `false`; false makes no changes |
| `config` | absent | Local JSON config file |
| `report` | absent | JSON report output path; no report if omitted |

The pass without brackets uses defaults. Unknown/duplicate inline options,
invalid values, unknown JSON fields, unsupported config versions, unreadable
config files, and report output failures terminate `opt` with a diagnostic and
nonzero status. Do not consume its IR output on failure. There is no escaping
for pipeline metacharacters: option values must not contain `;`, `,`, `<`, `>`,
`(`, or `)`. Spaces work when the entire pipeline argument is shell-quoted.
Use a unique report path per module/process. The report is written to an
adjacent temporary file and renamed over the destination only after a successful
write; its parent directory must exist. An existing destination is replaced.
Report and IR output paths must be distinct and must not overwrite input files.

The config format is described by
[config.schema.json](schemas/config.schema.json), with an example in
[config.example.json](config.example.json). `schema_version: 1` is required;
omitted settings retain defaults. `seed` is a decimal **string** to preserve
uint64 values in consumers with floating-point JSON numbers. The backend
additionally checks the uint64 range. Load the file first, then apply explicit
inline settings, regardless of option order:

```sh
opt -load-pass-plugin /tmp/aegis-shield-build/AegisShield.so \
  '-passes=aegis-shield<config=protectors/llvm/config.example.json;seed=7;report=/tmp/aegis-report.json>,verify' \
  -S /tmp/aegis-input.ll -o /tmp/aegis-transformed.ll
```

The [report schema](schemas/report.schema.json) records effective configuration,
LLVM version, input module identifier, and each function in module order,
including unselected functions and declarations. `transformed_sites` at module
level is the sum of all function site-array lengths. Each site records the
original zero-based **add ordinal within its function**, bit width, and variant.
The ordinal counts all original adds, including ineligible adds. Site arrays
follow original instruction order. They identify sites in that input IR, not
stable source locations or identifiers across compiler changes.

Function `status` is `transformed` exactly when its site array is nonempty.
`reason` gives either `expanded` or the first function-level skip reason.
`skipped_adds` counts instruction-level reasons only when the function was
otherwise eligible; it does not enumerate non-add instructions. A zero budget
uses `no-eligible-sites` and counts otherwise eligible adds under `budget`.
The report has no timestamp or machine addresses: identical input module
identifiers, input IR, LLVM build, and config give identical IR and reports.
Changing only an input filename changes the module identifier in the report
and the IR's ModuleID comment. Seed selection itself does not depend on paths.
Reports can reveal function names; manage them as build artifacts.

## Transformation and semantics

The pass expands unflagged scalar `add` instructions of width **2–128** with
one of these identities in arithmetic modulo `2^width`:

```text
a + b = (a XOR b) + ((a AND b) << 1)    # xor-carry
a + b = (a OR b)  +  (a AND b)          # or-carry
```

For each bit, `a + b = (a XOR b) + 2*(a AND b)`. Also
`a OR b = (a XOR b) + (a AND b)` because those terms have disjoint set bits.
These identities prove equality for defined bitvector inputs including wraparound.
No new arithmetic instruction carries `nsw` or `nuw`; width >=2 makes the
constant shift amount valid. The pass changes no control-flow edges, calls,
memory operations, signature, linkage, calling convention, or selection annotations.
It returns `PreservedAnalyses::none()` after changes and `all()` for a no-op.

Inputs are frozen before duplicate uses; equal operands share one freeze.
For defined inputs `freeze` is the identity. For implicit undef or poison,
freezing chooses a consistent value: this is a permitted LLVM **refinement**,
not a claim of identical poison/undef propagation. Direct undef/poison operands
are skipped conservatively. Programs with undefined behavior have no promised
runtime equivalence. Unsigned, defined runtime inputs are the verification domain.

The pass skips flagged adds (to avoid changing their overflow/poison contract),
i1, widths above 128, and vector adds. All other opcodes remain unchanged.
Every generated instruction carries `!aegis.shield.generated` metadata;
immediate repeated passes do not expand them again. Other optimizer passes may
drop the marker, so this is not a permanent cross-pipeline idempotence guarantee.
Generated instructions inherit debug locations, and the replacement result takes
the old result's name; arbitrary instruction metadata is not copied.

Selection is specified without platform RNGs: FNV-1a-64 over the function name
bytes (offset 14695981039346656037, prime 1099511628211), xor the seed, then
the SplitMix64 finalizer with its increment (`mix` in `src/Shield.cpp`). An add's
rank is `mix(function_key XOR add_ordinal)`. Select the lowest ranks up to the
budget, break ties by ordinal, and expand in original order. Even ranks use
`xor-carry`, odd ranks use `or-carry`. All hash arithmetic is wrapping uint64.
Different seeds may produce the same choices in a small function. This is a
reproducible selection mechanism, not a cryptographic generator or secret key.

## Validation and benchmark

The 14-case integration suite checks that real instructions change, annotations
match exactly, reports match their v1 invariants, seeds reproduce and alter
choices, budgets/config overrides work, and immediate repeated runs are no-ops.
Negative cases cover unannotated/unsupported signatures, declarations, `optnone`,
flagged/vector/i1/i129 adds, undef/poison, disabled/zero budgets, empty modules,
invalid settings/configs, and report failures. It verifies generated IR, including
an indirect-undef case with repeated uses and a single shared freeze.

The runtime fixture checks independent unsigned-C reference results for every
pair of 8-bit inputs, explicit wide overflow boundaries, and 100,000 deterministic
random input pairs. It exercises i2/i3/i7/i8/i16/i32/i64/i65/i127/i128, constants, repeated
operands, dependent adds, and loops with PHIs and zero-iteration exits. Baseline
and two transformed seeds run at `-O0`, `-O2`, and `-O3`, comparing their checksums.
A separate test runs `default<O2>` after the pass and then
executes the result. These checks are regression evidence alongside the algebraic
identities; there is no formal whole-pass proof or exhaustive wide-input check.
The i128 executable fixture currently assumes the tested host's native C ABI.

Run the executable benchmark from the repository root:

```sh
python3 protectors/llvm/benchmarks/benchmark.py \
  --plugin /tmp/aegis-shield-build/AegisShield.so \
  --output /tmp/aegis-benchmark.json
```

It compiles one annotated dependency-chain kernel with Clang O1, expands it,
then compiles both versions with O2 and links each to the same timed runner.
Each executable gets one warmup and nine alternating samples of 20 million
calls by default. The runner uses `CLOCK_MONOTONIC` and consumes the result in
a checksum; timing excludes process launch and compilation. All sample checksums
must match. The JSON includes sample times, median/min/max, IR size, executable
size, and exact kernel `.text` size and hash. It requires matching
`llvm-objcopy` as well as Clang and opt. Optional `--iterations`, `--samples`,
`--seed`, and tool-path arguments support reruns. Its benchmark v1 JSON is a local
measurement record, not a shared AEGIS benchmark schema.

See [benchmarks/RESULTS.md](benchmarks/RESULTS.md) for the checked-in run and
limitations. Optimizers can recover simple arithmetic from these identities;
no particular IR shape, machine-code difference, or overhead is guaranteed for
other programs, seeds, compiler versions, or optimization levels. This backend
provides no tamper detection, anti-debugging, encryption, diversification threat
model, or measured resistance to reverse engineering. Obfuscated IR, changed
machine code, and matching outputs alone establish **no security guarantee**.
