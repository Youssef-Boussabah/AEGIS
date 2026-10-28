# AEGIS ImageLab

ImageLab is a small C++20 image-processing library and CLI. It is a
**controlled reference target** for benchmarking software-protection tools:
it gives a protector a few well-specified functions to transform, then checks
that the transformed build still produces bit-identical results and measures
what changed.

- The algorithms are standard and deliberately simple: a rational
  (Reinhard-style) tone curve, BT.601-weighted saturation/contrast/brightness,
  and a range-gated unsharp mask. They are not novel or proprietary.
- ImageLab contains **no obfuscation or protection** of its own. It only marks
  which functions a protector may transform.
- Passing ImageLab's comparison shows that outputs match on the tested inputs.
  It is **not** evidence of protection. The LLVM Shield has no established
  security property (see [protectors/llvm/README.md](../../protectors/llvm/README.md)).

Verified on Linux x86-64 with Clang/LLVM 22.1.8, CMake 4.4.3, Ninja and
Python 3.14.7, in Release and Debug (+ASan/UBSan). A GCC 16.2.1 build
compiles warning-free and passes its 5 tests (native variant only; the IR
variants need Clang). Nothing else is verified.

## Layout

```
include/imagelab/imagelab.hpp  public C++ API (images, params, operations)
include/imagelab/kernels.h     C ABI of the three protected kernels
include/imagelab/pam.hpp       strict PAM/PPM codec used by CLI and tests
src/kernels.cpp                the protected kernels, and nothing else
src/image.cpp                  validation and image drivers
src/pam.cpp                    codec
cli/main.cpp                   imagelab-cli
bench/bench.cpp                imagelab-bench
protect.allowlist              agreed list of protected functions
tests/unit_tests.cpp           C++ unit tests, with a second reference model
tests/imagelab_reference.py    independent Python reference model + codec
tests/test_reference.py        CLI vs Python reference on every fixture
tests/test_cli.py              CLI error paths and exit codes
tests/check_ir.py              annotation/allowlist and Shield-run checks
tests/fixtures/                generated fixtures + expected output hashes
tools/make_fixtures.py         deterministic fixture generator
tools/compare_variants.py      baseline vs transformed comparison
benchmarks/RESULTS.md          one recorded comparison run
```

## Build and test

From the repository root (build trees go to `/tmp`, outside the source tree):

```sh
cmake -S demo/image_processor -B /tmp/aegis-imagelab-build -G Ninja \
  -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/aegis-imagelab-build
ctest --test-dir /tmp/aegis-imagelab-build --output-on-failure
```

That builds the `native` and `ir-baseline` variants and runs 9 tests. To add
the LLVM Shield variant, build the Shield first (see its README), then pass
its plugin; this adds the `shield` variant and runs 12 tests:

```sh
cmake -S protectors/llvm -B /tmp/aegis-shield-build -G Ninja \
  -DLLVM_DIR="$(llvm-config --cmakedir)" \
  -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/aegis-shield-build
cmake -S demo/image_processor -B /tmp/aegis-imagelab-build -G Ninja \
  -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Release \
  -DIMAGELAB_SHIELD_PLUGIN=/tmp/aegis-shield-build/AegisShield.so
cmake --build /tmp/aegis-imagelab-build
ctest --test-dir /tmp/aegis-imagelab-build --output-on-failure
```

Executables are written per variant: `<build>/<variant>/imagelab-cli`,
`imagelab-bench` and `imagelab-unit-tests`. Tests need Python 3 (standard
library only). Nothing is installed.

| CMake option | Default | Meaning |
| --- | --- | --- |
| `IMAGELAB_ENABLE_IR_VARIANTS` | `ON` | Build variants through LLVM IR. Needs Clang and an `opt` of the **same** version next to it (checked at configure time). Turned off with a warning for non-Clang compilers. |
| `IMAGELAB_SHIELD_PLUGIN` | empty | Path to `AegisShield.so`; adds the `shield` variant and the `imagelab.shield` test |
| `IMAGELAB_SHIELD_SEED` | `42` | Shield `seed` (decimal digits only) |
| `IMAGELAB_SHIELD_MAX_SITES` | `64` | Shield `max-sites` (decimal digits only) |
| `IMAGELAB_EXTERNAL_KERNELS_IR` | empty | A `.ll`/`.bc` file of kernels transformed by any other tool; adds the `external` variant |
| `IMAGELAB_IR_BACKEND_FLAGS` | `-O2` | Flags for compiling every IR variant to an object (a CMake list) |
| `IMAGELAB_WERROR` | `OFF` | Warnings are errors |
| `IMAGELAB_SANITIZE` | `OFF` | ASan + UBSan on everything except IR-variant kernel objects |

## Protected functions

Exactly three functions are protector targets. They are listed in
[protect.allowlist](protect.allowlist) and are the only functions in
[src/kernels.cpp](src/kernels.cpp):

```c
uint32_t imagelab_tone_map_pixel(uint32_t rgba, uint32_t exposure_q8, uint32_t knee);
uint32_t imagelab_color_adjust_pixel(uint32_t rgba, uint32_t saturation_q8,
                                     uint32_t contrast_q8, uint32_t brightness_biased);
uint32_t imagelab_enhance_pixel(uint32_t center, uint32_t north, uint32_t south,
                                uint32_t west, uint32_t east,
                                uint32_t amount_q8, uint32_t threshold);
```

There are two equivalent ways to select them:

1. **Annotation.** With Clang, each definition carries
   `__attribute__((annotate("aegis.protect"), noinline))` (macro
   `IMAGELAB_PROTECT`). That is the exact string the LLVM Shield matches in
   `llvm.global.annotations`. With other compilers the macro is just
   `noinline`. Defining `IMAGELAB_NO_PROTECT_ANNOTATIONS` removes the
   annotation, for negative controls.
2. **Allowlist.** `protect.allowlist` names the same C-linkage (unmangled)
   symbols, one per line. It is for tools that select by name.

The `imagelab.annotations` test keeps the two in sync. It requires the
annotated set in the IR to equal the allowlist, and it checks that each
function meets the Shield's selection rules: a definition with a
scalar-integer return value and arguments, not variadic, no `optnone`, and at
least one `add` without `nuw`/`nsw` flags.

Why the kernels look the way they do:

- **Integer-only signatures.** The Shield skips any function with a pointer
  argument, so each kernel processes one pixel packed into a `uint32_t`
  (`R | G<<8 | B<<16 | A<<24`). The drivers in `src/image.cpp` load and store
  bytes, so the packing doesn't depend on host byte order. The cost is one
  out-of-line call per pixel, which dominates run time; ImageLab is not a
  fast image library.
- **Unsigned arithmetic only.** Signed C++ additions get `nsw` flags, which
  the Shield skips. Signed intermediate values are therefore stored with an
  explicit bias (documented in the code), and there is no undefined behaviour.
- **`always_inline` helpers.** The Shield rewrites only the bodies of
  annotated functions, so the helper arithmetic must be inlined into them,
  even at `-O0`.

To add a protected function: keep it in `src/kernels.cpp` with C linkage,
scalar integer types and `IMAGELAB_PROTECT`; add it to `protect.allowlist`;
add reference-model tests. Changing the set changes what every comparison
measures, so record it.

## Protector workflow and variants

All IR variants start from one protector input, `<build>/ir/kernels.input.ll`,
and are compiled with the same `IMAGELAB_IR_BACKEND_FLAGS`:

```
src/kernels.cpp ──clang++ -O0 -Xclang -disable-O0-optnone──▶ kernels.frontend.ll
               ──opt function(sroa),verify──────────────────▶ kernels.input.ll   (protector input)
kernels.input.ll ─────────────────────────── clang++ -O2 -c ─▶ kernels.ir-baseline.o
kernels.input.ll ─opt aegis-shield<…>,verify─▶ kernels.shield.ll ─ clang++ -O2 -c ─▶ kernels.shield.o
IMAGELAB_EXTERNAL_KERNELS_IR ─────────────── clang++ -O2 -c ─▶ kernels.external.o
```

Each object is linked with the same unprotected drivers, CLI, benchmark and
unit tests.

| Variant | Kernels object | Use |
| --- | --- | --- |
| `native` | `src/kernels.cpp` compiled normally (`-O3` in Release) | ordinary build |
| `ir-baseline` | `kernels.input.ll` + backend flags | **the fair baseline** for a protected variant: same pipeline, no protector |
| `shield` | Shield output + backend flags | LLVM Shield transformed |
| `external` | your IR + backend flags | any other protector |

Why `-O0` without `optnone`: with `-O1` or higher, LLVM's InstCombine proves
that the bounded channel arithmetic cannot overflow and adds `nuw`/`nsw` to
every add. The Shield then finds 0 eligible sites (measured with Clang 22.1.8:
0 of 42 adds eligible at `-O1`, against 43 of 43 with this pipeline). SROA only removes the
`-O0` stack slots and adds no flags. Paths are kept relative (`src/kernels.cpp`,
`kernels.input.ll`), so the IR and the Shield report carry no absolute build
paths, and the Shield pipeline string contains no metacharacters from the
build directory.

The pipeline itself costs performance. `ir-baseline` is about 2.2× slower
than `native` on `enhance` in the recorded run, because `native` is compiled
directly at `-O3`. Compare protected variants with `ir-baseline`, not
`native`.

To evaluate another protector: give it `kernels.input.ll`, configure with
`-DIMAGELAB_EXTERNAL_KERNELS_IR=<its output>`, build, and run `ctest` and
`tools/compare_variants.py`. The output must keep the three function
definitions and their C signatures, or linking fails. A transform that
changes results fails `imagelab.unit.external`, `imagelab.reference.external`
and `imagelab.compare` (verified with a deliberately corrupted IR file).

## Image model and API invariants

See [imagelab.hpp](include/imagelab/imagelab.hpp).

- **Format.** RGBA8, straight (not premultiplied) alpha, row-major, bytes in
  R, G, B, A order. Operations change R, G and B and copy A unchanged.
- **Views.** `{data, width, height, stride}`. `stride` is the byte distance
  between row starts, must be at least `width * 4`, and has no alignment
  requirement. The view spans `stride * (height - 1) + width * 4` bytes; the
  last row needs no padding. Row padding is never read into results and never
  written.
- **Limits.** `1 ≤ width, height ≤ 32768` and `width * height ≤ 2^26`.
  The span must fit in `ptrdiff_t` and in the address space after `data`.
  All size arithmetic is checked for overflow.
- **Validation order:** parameters, then source view, then destination view,
  then sizes, then aliasing. The first failure is returned as a `Status`:
  `null_pointer`, `invalid_dimensions`, `invalid_stride`, `size_overflow`,
  `dimension_mismatch`, `aliasing` or `invalid_parameter`. On any error the
  destination is untouched.
- **Aliasing.** `tone_map` and `adjust_color` accept an exact in-place call
  (same `data` and `stride`) or fully disjoint buffers. `enhance` needs
  disjoint buffers. Any other overlap returns `aliasing`.
- **Borders.** `enhance` reads outside pixels from the nearest edge pixel
  (clamp-to-edge). For 1×N and N×1 images the missing neighbours are the
  pixel itself.
- **Determinism.** Integer arithmetic only, single-threaded, no global state.
  The same input and parameters give the same bytes on every platform.
- `fingerprint()` is FNV-1a-64 over the visible row bytes, for quick equality
  checks. It is not a cryptographic hash.

## Numeric semantics

`c` is an input channel value in [0, 255]; `clamp` limits to [0, 255];
`round(x)` is `floor(x + 1/2)` (round half up, also for negative values).
All formulas are exact rational arithmetic; the C++ code computes them
exactly with unsigned integers.

**Tone map** (`exposure_q8` ∈ [1, 4096], 256 = 1.0; `knee` ∈ [1, 2^20]):

```
M = 255 * 256,   E = c * exposure_q8
out = min(255, round(255 * E * (M + knee) / (M * (E + knee))))
```

This is the curve `x(1+k)/(x+k)` on `x = E/M`, `k = knee/M`. It maps 0 to 0
and, at `exposure_q8 = 256`, 255 to 255. It is non-decreasing in `c` and in
`exposure_q8` (tested). A larger `knee` is closer to linear.

**Colour adjust** (`saturation_q8`, `contrast_q8` ∈ [0, 1024], 256 = 1.0;
`brightness` ∈ [-255, 255]), applied to each channel of a pixel:

```
Y  = round((77 R + 150 G + 29 B) / 256)          luma of the input pixel
s1 = clamp(round(Y + (c - Y) * saturation_q8 / 256))
s2 = clamp(round(128 + (s1 - 128) * contrast_q8 / 256))
out = clamp(s2 + brightness)
```

Each stage saturates before the next one starts. With the defaults
(256, 256, 0) the operation is exactly the identity, verified on all 2^24 RGB
values. Saturation 0 gives `Y` and contrast 0 gives 128. The kernel receives
`brightness + 255`.

**Enhance** (`amount_q8` ∈ [0, 1024], 256 = 1.0; `threshold` ∈ [0, 255]),
per channel, with the 4-neighbours `n s w e`:

```
blur  = round((4c + n + s + w + e) / 8)
range = max(c,n,s,w,e) - min(c,n,s,w,e)
gate  = 0 if range <= threshold, else min(16 * (range - threshold), 256)
out   = clamp(round(c + (c - blur) * amount_q8 * gate / 65536))
```

Flat regions (`range ≤ threshold`) are unchanged. Above the threshold the
gain ramps up linearly over 16 levels. `amount_q8 = 0` or `threshold = 255`
gives the identity.

**Kernel totality.** The C kernels accept every `uint32_t` value. Parameters
outside the ranges above are saturated to the nearest bound (tested on random
inputs), so every call has defined output. The C++ API and the CLI reject
out-of-range parameters instead of saturating them.

## CLI

```
imagelab-cli tone    [--exposure-q8 N] [--knee N] INPUT OUTPUT
imagelab-cli color   [--saturation-q8 N] [--contrast-q8 N] [--brightness N] INPUT OUTPUT
imagelab-cli enhance [--amount-q8 N] [--threshold N] INPUT OUTPUT
imagelab-cli info    INPUT          # prints width, height and fingerprint
imagelab-cli --help | --version     # --version names the kernel variant
```

Defaults are the `ToneMapParams`, `ColorParams` and `EnhanceParams` defaults
in `imagelab.hpp`. Numbers are strict decimals; only `--brightness` may be
negative. Each option may be given once.

- **Input:** PAM `P7` with `DEPTH 4`/`RGB_ALPHA` or `DEPTH 3`/`RGB`, or binary
  PPM `P6`; `MAXVAL` 255 only. Three-channel input gets alpha 255. The
  decoder rejects unknown or duplicate header keys, headers over 4096 bytes,
  short payloads and trailing bytes.
- **Output:** PAM `P7 RGB_ALPHA`. It is written to a temporary file in the
  same directory and renamed into place with mode `0666 & ~umask`, so a
  failed run never leaves a partial or stale output. OUTPUT must not be the
  INPUT file.

| Exit | Meaning |
| --- | --- |
| 0 | success |
| 1 | internal error |
| 2 | usage error: unknown command or option, malformed number, wrong arguments, OUTPUT is INPUT |
| 3 | I/O error: cannot open, read, write or rename |
| 4 | invalid image file |
| 5 | parameter out of range |
| 6 | image exceeds the dimension limits |

## Tests

| CTest name | What it checks |
| --- | --- |
| `imagelab.fixtures` | `tests/fixtures/*` equal a fresh run of `tools/make_fixtures.py` |
| `imagelab.cli` | 55 CLI checks: every exit code, bounds accepted and rejected, no output and no temp files on failure, output mode, `info` fingerprint |
| `imagelab.unit.<variant>` | 18 C++ test groups (about 21.7 million checks): kernels against a second, signed-arithmetic reference model (exhaustive over channels for tone, all 2^24 RGB values for colour identity, 2 million random cases each for colour and enhance), known answers, totality, monotonicity, validation, aliasing, strides, padding, borders, 1×1/1×N/N×1, codec acceptance and rejection |
| `imagelab.reference.<variant>` | CLI output for 10 fixtures × 15 parameter sets equals the Python reference model byte for byte, and its SHA-256 equals `tests/fixtures/expected.sha256.json` |
| `imagelab.bench.smoke` | the benchmark runs |
| `imagelab.annotations` | annotation set == allowlist, and the Shield selection rules (IR variants only) |
| `imagelab.compare` | `compare_variants.py --quick`: identical CLI outputs and benchmark fingerprints across all variants (IR variants only) |
| `imagelab.shield` | Shield report: every allowlisted function `transformed` and nothing else annotated; only allowlisted bodies changed (Shield variant only) |

There are two independent reference models. `tests/imagelab_reference.py`
uses exact `fractions.Fraction` arithmetic and its own codec.
`tests/unit_tests.cpp` uses plain signed 64-bit arithmetic. Neither uses the
biased integer forms of `src/kernels.cpp`. The known-answer values were
computed separately with exact fractions.

During development the suite was also checked by planting bugs in a scratch
copy (wrong rounding, a wrong luma weight, wrong gate slope, wrap-around
borders, a weaker stride check, accepting trailing bytes, a widened
parameter range, an allowlist mismatch, a removed annotation). Each one made
at least one test fail. Separately, the unit tests ran clean under
`-fsanitize=integer` on the library sources, with only the intentionally
wrapping FNV fingerprint suppressed.

Regenerate fixtures with `python3 tools/make_fixtures.py --write tests/fixtures`.
After a **deliberate** change to the semantics, regenerate the expected
hashes from the Python model, never from the CLI, and review the diff:
`python3 tests/test_reference.py --fixtures tests/fixtures --update-manifest`.

## Benchmarks

`imagelab-bench` times each operation on one deterministic synthetic image
(SplitMix64 noise over gradients and 32×32 blocks, so `enhance` takes both
gate branches). It prints JSON (`imagelab.bench.v1`) with every sample, the
median, minimum and maximum, and the output fingerprint. Defaults: 1024×768,
1 warmup, 9 samples of 4 calls each, seed 1. Timing uses `steady_clock` and
excludes image generation.

`tools/compare_variants.py` runs all variants of one build tree in rotating
order and writes `imagelab.compare.v1` JSON. The JSON holds settings, the
environment (CPU, governor, compiler, Shield config), output equivalence,
timings, and artifact hashes and sizes, including per-kernel machine-code
bytes read from the ELF symbol table. It exits 1 if any output differs:

```sh
taskset -c 3 python3 demo/image_processor/tools/compare_variants.py \
  --build /tmp/aegis-imagelab-build --rounds 5 --output /tmp/imagelab-compare.json
```

See [benchmarks/RESULTS.md](benchmarks/RESULTS.md) for one recorded run and
its conditions. Its numbers apply only to that machine, toolchain, image and
seed.

## Known limitations

- Only Clang/LLVM 22.1.8 on Linux x86-64 is verified, with GCC 16.2.1 for the
  native variant. The ELF code-size readout and the CLI's atomic-write path
  (`mkstemp`) are POSIX/ELF-specific; other platforms fall back or report
  "unavailable", untested.
- 8-bit RGBA only: no 16-bit, gamma or colour-space handling, and no
  premultiplied alpha. Tone mapping and colour work on raw 8-bit code values.
- Per-pixel out-of-line kernel calls dominate run time by design (Shield
  compatibility). Throughput numbers describe this harness, not image
  processing in general.
- `kernels.input.ll` comes from a `-O0`-based pipeline. A protector that
  expects optimised IR may behave differently. The Shield's own README notes
  that later optimisation can undo its rewrites.
- Equivalence is established on the fixtures, the parameter sets, random
  kernel tests and the benchmark image. It is not a proof for all inputs.
- `check_ir.py` parses the textual IR that Clang/opt 22 print for this
  project; it is not a general LLVM IR parser.
- Reading the umask for output files briefly changes it process-wide; this
  is fine for the single-threaded CLI, but not for multi-threaded callers of
  `pam::write_file`.
- `demo/image_processor/` belongs to role A (Core Platform, Shield & Integration);
  role C maintains the product demonstration flow. See the root `AGENTS.md`.
