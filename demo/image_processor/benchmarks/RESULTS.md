# ImageLab variant comparison: recorded run

One run of `tools/compare_variants.py` on 2026-10-28 (UTC). These numbers
describe this machine, toolchain, image, seed and Shield configuration only.
Do not extrapolate them to other programs, inputs, compilers, flags or
hardware. They measure speed and size, **not** security.

## Command

```sh
cmake -S protectors/llvm -B <shield-build> -G Ninja \
  -DLLVM_DIR="$(llvm-config --cmakedir)" \
  -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Release
cmake --build <shield-build>
cmake -S demo/image_processor -B <build> -G Ninja -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_BUILD_TYPE=Release -DIMAGELAB_WERROR=ON \
  -DIMAGELAB_SHIELD_PLUGIN=<shield-build>/AegisShield.so
cmake --build <build>
taskset -c 3 python3 demo/image_processor/tools/compare_variants.py \
  --build <build> --rounds 5 --output compare.json
```

Shield settings: `seed=42`, `max-sites=64` (CMake defaults). Backend flags for
IR variants: `-O2`. The `native` variant uses the Release default (`-O3`).

## Conditions

| Item | Value |
| --- | --- |
| CPU | Intel Core Ultra 9 185H (hybrid P/E cores), run pinned to logical CPU 3 (a P-core, 5.1 GHz max) |
| Frequency control | none; cpufreq governor `powersave`, turbo not disabled |
| OS | Linux 7.2.3 (CachyOS), glibc 2.44, x86-64 |
| Toolchain | Clang/LLVM 22.1.8 (clang++, opt), CMake 4.4.3, Ninja, Python 3.14.7 |
| Image | 1024×768 synthetic, seed 1 (see `bench/bench.cpp`) |
| Samples | 5 rounds × 9 samples = 45 per operation per variant; each sample is 4 back-to-back calls; 1 warmup per round; variants rotated each round |
| Load | 1-minute load average about 1.2 just before the run; other activity on the machine was not controlled |

## Results

Median wall time per call over 45 samples (each sample's time divided by 4),
with the ratio to `ir-baseline`, the fair baseline (same IR pipeline, no
protector):

| Variant | tone ms | color ms | enhance ms | tone ×base | color ×base | enhance ×base |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| native | 9.94 | 10.77 | 16.11 | 1.00 | 0.98 | 0.46 |
| ir-baseline | 9.95 | 11.01 | 34.88 | 1.00 | 1.00 | 1.00 |
| shield | 10.01 | 12.14 | 37.95 | 1.01 | 1.10 | 1.09 |

The sample spread was wide and bimodal. Per-sample minimum/maximum for 4
calls, in ms:

| Variant | tone | color | enhance |
| --- | --- | --- | --- |
| native | 21.9 / 41.8 | 24.2 / 45.3 | 38.6 / 67.6 |
| ir-baseline | 39.5 / 41.7 | 43.7 / 46.1 | 83.2 / 145.8 |
| shield | 22.6 / 42.3 | 27.6 / 51.2 | 93.4 / 158.3 |

The minimums are roughly half the medians, which is consistent with
frequency changes during the run (powersave governor, turbo). Medians are
the more stable figure here, but differences under about 10% are within the
noise of this setup.

Output fingerprints were identical in every sample of every variant
(tone `fdc2c6b36032f747`, color `d596a5ea0a8971b0`, enhance
`42323edd250f3f9e`). CLI outputs were byte-identical for all 10 fixtures × 15
parameter sets.

Kernel machine code (from the ELF symbol table of each kernels object):

| Variant | executable section bytes | tone | color | enhance |
| --- | ---: | ---: | ---: | ---: |
| native | 1671 | 331 | 565 | 759 |
| ir-baseline | 1335 | 336 | 577 | 407 |
| shield | 1482 | 374 | 649 | 442 |

Shield report: 43 sites transformed (tone 9, color 24, enhance 10), 0
skipped, LLVM 22.1.8.

## Limitations

- One machine, one session, no frequency pinning; hybrid CPU. A repeat run
  without `taskset` gave similar medians (within about 5%), but this is not
  a controlled performance study.
- One synthetic image, one parameter set per operation, one Shield seed. The
  per-pixel out-of-line call dominates run time, which dilutes any change
  inside the kernels.
- `native` vs `ir-baseline` differences come from the build pipeline
  (`-O3` direct compile vs the `-O0`→SROA→`-O2` IR flow), not from any
  protector.
- Equal outputs on these inputs are regression evidence, not proof of
  equivalence. Larger code and slower kernels are not evidence of protection;
  the LLVM Shield has no established security property, and no attack was
  run.
