# Mirage

Mirage v0.1 inserts deterministic, uncalled arithmetic functions into LLVM 22
modules for ELF builds. The functions have plausible entitlement/key/state names,
are pure unsigned arithmetic, and have no callers, initializers, I/O, network,
mutable global state or runtime hooks. They create additional static analysis
targets. **Reverse-engineering resistance is not established.**

Clang's `used` and `retain` attributes preserve the functions through LLVM
optimization and ELF linker section garbage collection. Mirage creates a side
module and combines it with the input using `llvm-link`; it does not edit Shield,
Core, ImageLab or shared contracts. Every generated module is verified with `opt`.
Insertion fails explicitly on malformed IR, symbol collisions, unsupported targets,
toolchain mismatches or missing retention metadata. The decoys are compiled for
Clang's default target; a module whose four-part triple differs from it only in the
vendor field (rustc emits `x86_64-unknown-linux-gnu`, Clang defaults to
`x86_64-pc-linux-gnu`) gets decoys compiled with `--target=<module triple>`, so the
linked module keeps its own triple. Every other mismatch fails with
`target_triple_mismatch`. Rust IR was exercised only on one external crate
(see `docs/release/FULL_SYSTEM_VALIDATION.md`). Final-binary retention still
requires independent inspection after the application's own build.

## Setup and usage

Use existing Python 3.11+, pytest and matching Clang/LLVM **22** tools. No package
installation is needed with `PYTHONPATH`; the transformer is stdlib-only.

```sh
export PYTHONPATH="$PWD/protectors/mirage/src:$PWD/attack_lab/src"
clang --version
opt --version
llvm-link --version
.venv/bin/python -m aegis_mirage INPUT.ll --output-dir /tmp/mirage-enabled --seed 42 --count 3
.venv/bin/python -m aegis_mirage INPUT.ll --output-dir /tmp/mirage-control --seed 42 --disabled
.venv/bin/python -m pytest protectors/mirage/tests -q
```

Output directories must be new. They contain `module.ll` and `report.json`
(`aegis.mirage.report.v1`), with exact input/output hashes, configuration, inserted
names, source-template digest and toolchain hashes. The disabled module is
byte-identical to its input. `aegis_mirage.restore(original, report, output)`
reproduces the no-decoy input after checking its digest; it requires the original
and does not attempt textual surgery on optimized IR. Nothing here executes
input/output programs.

## Core backend (`llvm-shield-mirage`)

Mirage is registered with Core only through the combined Shield + Mirage adapter
in [protectors/llvm/adapter](../llvm/adapter/README.md#combined-shield--mirage-backend-llvm-shield-mirage),
which runs Mirage on the verified Shield output of each job. That adapter passes
`transform(..., runner=..., work_dir=...)`: `runner(argv, cwd)` replaces the
standalone runner so tools stay in Core's process group (the standalone runner
starts its own session, which suits the CLI but would escape a Core timeout), and
`work_dir` keeps scratch files in the job's private work directory. Both default
to the standalone behaviour. There is no standalone Mirage-only Core backend.

## Real demonstration

From the repository root, with an already built Shield and installed Ghidra:

```sh
PYTHONPATH=attack_lab/src:protectors/mirage/src .venv/bin/python attack_lab/scripts/role_b_demo.py \
  --output-dir /tmp/aegis-role-b-demo-reproduction \
  --ghidra-headless "$HOME/Applications/ghidra_12.1.4_PUBLIC/support/analyzeHeadless" \
  --shield-plugin /tmp/aegis-shield-build/AegisShield.so --authorized-owned-fixture
```

This compiles and executes only `tests/fixtures/signal.c`, an AEGIS-owned trusted
fixture. Its million-input output digest matches for baseline, Shield and
Shield+Mirage. Three decoys survive O2 and linker GC and appear in actual Ghidra
exports. The report includes nine process timing samples per variant, warmup,
hardware/date, every build command, final hashes, no-decoy control and limitations.
Private paired reconstructions use FakeOffline and never execute candidates.
For this fixture, Shield's two IR changes optimize back to the baseline binary;
Mirage adds 176 bytes. This is static retention evidence, not attack resistance.

## Existing ImageLab workflow

Mirage output can use ImageLab's existing external-IR input, without source changes:

```sh
PYTHONPATH=protectors/mirage/src .venv/bin/python -m aegis_mirage \
  /tmp/aegis-imagelab-build/ir/kernels.shield.ll --output-dir /tmp/imagelab-mirage --seed 42
cmake -S demo/image_processor -B /tmp/imagelab-mirage-build -G Ninja \
  -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Release \
  -DIMAGELAB_SHIELD_PLUGIN=/tmp/aegis-shield-build/AegisShield.so \
  -DIMAGELAB_EXTERNAL_KERNELS_IR=/tmp/imagelab-mirage/module.ll
cmake --build /tmp/imagelab-mirage-build -j2
ctest --test-dir /tmp/imagelab-mirage-build --output-on-failure
.venv/bin/python demo/image_processor/tools/compare_variants.py \
  --build /tmp/imagelab-mirage-build --baseline shield --rounds 4 --width 256 --height 256 \
  --samples 5 --warmup 1 --repeat 2 --seed 42 --output /tmp/imagelab-mirage-comparison.json
llvm-nm --defined-only /tmp/imagelab-mirage-build/external/imagelab-cli
```

The input build prerequisite is documented in [ImageLab](../../demo/image_processor/README.md).
The measured run passed 14/14 ImageLab CTests; all three decoys were retained.
The existing comparison measured 135 extra bytes of kernel-object code and
matching outputs. Small timing differences are noisy observations under the
recorded conditions, not performance guarantees. See the [Role B handoff](../../attack_lab/docs/role-b-delivery.md).

Limitations: LLVM 22 / ELF / same-target toolchain only; static-library objects
must actually be selected by the linker; custom stripping/rewriting may discard
symbols or code. Decoys are independent and can be identified as unreachable by
an analyst. No live model evaluation, AI target-selection effect or behavioral
reconstruction resistance has been measured. Detailed reports can reveal names
and belong in private build artifacts.
