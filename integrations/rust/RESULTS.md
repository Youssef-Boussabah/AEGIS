# Rust component integration results — 30 October 2026

## Verdict and scope

The optional workflow in [README.md](README.md) now captures a Cargo library-test
compiler invocation and automatically performs pre-opt IR extraction, signature
marking, real Core/adapter protection, matched Clang code generation, rustc linker
replay and per-test comparison. Both real backends work on the owned fixture and
PhotoCraft color. PhotoCraft algo works through Shield at component level, with
an existing upstream failing test; its workflow truthfully exits **failed** despite
matching baseline/protected outcomes. Mirage cannot accept algo's large module.

This is **not whole-application Rust protection**, protected rlib production, a
workspace Cargo build hook or evidence of attack resistance. Only one test crate's
main codegen unit is substituted. Dependencies/std link unchanged; their generic
instantiations in the selected crate can still be transformed. No existing Core,
adapter, protector, native integration or release contract was changed.

Work began 08:11 Toronto. Feature implementation and measured component runs were
complete by 08:42 Toronto, before the 10:15 feature cutoff. Final documentation
and verification followed. No commit, push, publication, package installation,
global Rust/toolchain change or licensing modification was performed.

## Conditions and evidence

- AEGIS HEAD: `691ce2717934c22dd30883b5dd8a586ebf78bf20` plus the existing
  uncommitted working tree and these optional additions; no new commit was made.
- Host: Linux 7.2.3-1-cachyos x86-64, Intel Core Ultra 9 185H, 22 logical CPUs.
- Python 3.14.7, rustc 1.98.1 (`48a229cea`, LLVM 22.1.8), Cargo 1.98.1.
  Compiler: `/home/youss/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/rustc`.
  Its host is `x86_64-unknown-linux-gnu`.
- `opt`, `clang`, `llvm-dis`, `llvm-link`, `llvm-nm`, `llvm-size`: existing `/usr/bin`
  LLVM 22.1.8 tools. Existing plugin: `/tmp/aegis-shield-build/AegisShield.so`.
- All scratch/evidence: `/tmp/aegis-rust-integration` (0700). Six measured runs'
  `run.json` files contain exact subprocess argv, cwd, logs, versions, SHA-256,
  sizes, Core jobs, sample times and named outcomes. `measurements.json` there
  derives artifact sizes, hashes, `.text` sizes and timing statistics from them.
- Source: newly written owned fixture under `fixtures/component/`. PhotoCraft
  checkout: `https://github.com/storytold/photocraft` at
  `28be431b4ad3ddc7080d46f3eacc399f3e44fa5b`, read/built in
  `/tmp/aegis-fsv/targets/photocraft`. Its workspace declares `MIT OR Apache-2.0`;
  local `LICENSE-MIT` and `LICENSE-APACHE` were inspected. No third-party source,
  artifacts, proprietary assets or private Shield reports were added to this module.

The original manual experiment and requirements were inspected in
`docs/release/FULL_SYSTEM_VALIDATION.md`, the LLVM and adapter READMEs, and
`/tmp/aegis-fsv/tools/{mark_eligible.py,relink.py}`, prior rustc/linker commands,
IR and test records. New experiments used **fresh Cargo builds and captures**, not
the old protected outputs. Color's protected IR and final matched native hashes
reproduced the previous manual results; raw IR ModuleID comments contain run paths.

## Exact compiler, IR and linker requirements

The protection point is saved `*.rcgu.no-opt.bc`, disassembled by matching
`llvm-dis`, before LLVM optimizations inline integer helpers. Replayed rustc uses
`-C opt-level=3 -C lto=off -C codegen-units=1 -C save-temps`
`--emit=llvm-ir,link --print=link-args`. The captured original Cargo artifact is
snapshotted separately; PhotoCraft's ordinary release profile uses ThinLTO.

Both unmarked baseline and adapter-protected textual IR compile with
`clang -O3 -fPIC -c`. Final linking reuses the exact printed rustc linker argv,
replacing **only** the primary `*-cgu.0.rcgu.o` and `-o` output. Rust's additional
shim/symbol objects, dependency archives, runtime libraries, native search paths,
LLD driver options and `--gc-sections` remain in that argv. Linker environment is
restricted to printed PATH/LC_ALL/VSLANG plus the runner's minimal environment.
Exact LLVM versions are checked before compilation/protection, and the adapter
independently verifies its output with LLVM. Vendor-only triple differences work
with the existing combined adapter in this checkout.

All component tests run with `--test-threads=1 --format=pretty --color=never`.
Each variant has the same sample count and forward/reverse alternating order.
Matching counts alone do not suffice: named outcomes and exit codes must match.

## Reproduction commands used

From `/home/youss/Projects/aegis`:

```sh
env AEGIS_RUST_CRATE=aegis_rust_component \
  AEGIS_RUST_CAPTURE=/tmp/aegis-rust-integration/owned-final-invocation.json \
  RUSTC_WRAPPER=/home/youss/Projects/aegis/integrations/rust/capture.py \
  CARGO_TARGET_DIR=/tmp/aegis-rust-integration/owned-final-target \
  cargo test --manifest-path integrations/rust/fixtures/component/Cargo.toml \
  --release --lib --no-run --offline --locked

env AEGIS_RUST_CRATE=photocraft_color \
  AEGIS_RUST_CAPTURE=/tmp/aegis-rust-integration/color-invocation.json \
  RUSTC_WRAPPER=/home/youss/Projects/aegis/integrations/rust/capture.py \
  CARGO_HOME=/tmp/aegis-fsv/cargo-home \
  CARGO_TARGET_DIR=/tmp/aegis-rust-integration/photocraft-target \
  cargo test --manifest-path /tmp/aegis-fsv/targets/photocraft/Cargo.toml \
  -p photocraft-color --release --lib --no-run --offline --locked

env AEGIS_RUST_CRATE=photocraft_algo \
  AEGIS_RUST_CAPTURE=/tmp/aegis-rust-integration/algo-invocation.json \
  RUSTC_WRAPPER=/home/youss/Projects/aegis/integrations/rust/capture.py \
  CARGO_HOME=/tmp/aegis-fsv/cargo-home \
  CARGO_TARGET_DIR=/tmp/aegis-rust-integration/photocraft-target \
  cargo test --manifest-path /tmp/aegis-fsv/targets/photocraft/Cargo.toml \
  -p photocraft-algo --release --lib --no-run --offline --locked
```

Each capture then used this exact command shape, with the argument combinations
in the table below (replace the output directory with a new name to rerun):

```sh
.venv/bin/python integrations/rust/protect.py \
  --invocation /tmp/aegis-rust-integration/INVOCATION \
  --output /tmp/aegis-rust-integration/RUN \
  --plugin /tmp/aegis-shield-build/AegisShield.so \
  --backend BACKEND --samples SAMPLES
```

| RUN | INVOCATION | BACKEND | SAMPLES | Additional argument |
| --- | --- | --- | --- | --- |
| `owned-final-shield` | `owned-final-invocation.json` | `llvm-shield` | 5 | none |
| `owned-final-combined` | `owned-final-invocation.json` | `llvm-shield-mirage` | 5 | none |
| `color-shield` | `color-invocation.json` | `llvm-shield` | 5 | none |
| `color-combined` | `color-invocation.json` | `llvm-shield-mirage` | 5 | none |
| `algo-shield` | `algo-invocation.json` | `llvm-shield` | 3 | `--max-input-bytes 536870912` |
| `algo-mirage-limit` | `algo-invocation.json` | `llvm-shield-mirage` | 1 requested; 0 executed | `--max-input-bytes 536870912` |

Default backend was omitted in actual Shield invocations (it is `llvm-shield`).
Each run's `steps` contains the expanded compiler, LLVM, linker and test argv.
PhotoCraft captures used the existing dependency cache entirely offline. Fresh
Cargo builds took 9.30 seconds for color and 2 minutes 29 seconds for algo on this
host with that warm download cache. These are observations, not cold-build claims.

## Component results

| Component / backend | Pre-opt definitions / marked | Reported functions / sites changed | Original Cargo tests | Matched baseline tests | Protected tests | Workflow result |
| --- | --- | --- | --- | --- | --- | --- |
| Owned / Shield | 55 / 6 | 2 / 4 | 4 pass | 4 pass | 4 pass | succeeded |
| Owned / Shield+Mirage | 55 / 6 | 2 / 4; 3 decoys | 4 pass | 4 pass | 4 pass | succeeded; 3/3 decoy symbols retained after O3/final link |
| PhotoCraft color / Shield | 866 / 23 | 1 / 2 | 30 pass | 30 pass | 30 pass | succeeded |
| PhotoCraft color / Shield+Mirage | 866 / 23 | 1 / 2; 3 decoys | 30 pass | 30 pass | 30 pass | succeeded; 3/3 decoy symbols retained after O3/final link |
| PhotoCraft algo / Shield | 72,781 / 313 | 13 / 26 | 725 pass, 2 fail, 27 ignored | 726 pass, 1 fail, 27 ignored | same 726/1/27 | **failed: BASELINE_TEST_FAILURE**; matched outcomes agree in all 3 samples |
| PhotoCraft algo / Shield+Mirage | 72,781 / 313 | no adapter job submitted | original snapshotted | not run | not run | **failed: MIRAGE_INPUT_TOO_LARGE**; fixed 64 MiB cap |

The owned changes are its two authored arithmetic functions. Color changes only
an instantiated std integer iterator helper: **zero PhotoCraft-authored color
functions transform**. Algo's 13 transformed functions include six functions/
closures attributed to PhotoCraft source, totaling 11 sites; seven others are
instantiated core/dependency helpers. Attribution was manually inspected in the
private function report and is separate from the adapter's module totals.

Algo's unchanged failing test is
`pixelate::tests::facet_reuse_matches_scalar_in_every_model`, a NaN bit-pattern
assertion. Its original ThinLTO binary additionally fails
`pixelate::tests::cell_filters_match_scalar_models_edges_and_fractional_cells`.
These were already present in the prior manual validation and recur before
protection. No test was deleted, filtered, skipped or changed to obtain a pass.
The 27 ignored cases are upstream libtest ignores, recorded as such. All three
samples preserve each variant's same named outcomes. This is component regression
evidence, not a whole-program semantic proof.

## Artifacts, hashes and size

All sizes below are bytes. SHA-256 for adapter outputs was computed by Core and
rechecked by this consumer; native/input hashes were computed locally. The two
separate raw IR runs have different absolute ModuleID comments; adapter staging
normalizes that identifier, and the combined Shield stage equals standalone Shield.

| Component | Original Cargo ELF | Matched baseline ELF | Shield ELF | Shield+Mirage ELF |
| --- | ---: | ---: | ---: | ---: |
| Owned | 1,082,736 | 1,082,840 | 1,082,872 | 1083248 |
| PhotoCraft color | 1,674,576 | 1,691,800 | 1,691,832 | 1692232 |
| PhotoCraft algo | 12,623,880 | 14,046,512 | 14,046,984 | not built |

Final .text bytes, measured using llvm-size -A on each final ELF:

| Component | Original Cargo | Matched baseline | Shield | Shield+Mirage |
| --- | ---: | ---: | ---: | ---: |
| Owned | 615,406 | 615,438 | 615,470 | 615614 |
| PhotoCraft color | 868,718 | 846,088 | 846,120 | 846264 |
| PhotoCraft algo | 8,165,614 | 8,597,427 | 8,597,747 | not built |

Full SHA-256 of final native artifacts:

| Component / variant | SHA-256 |
| --- | --- |
| Owned / original Cargo | ac5862fd385470a4b91f02d742bf477722c34774891d8f3c47a3eb04e1a5f2f2 |
| Owned / matched baseline | a3c5adf68e449a8daea1a91a4eafacd83a43283e9c239470edade6943b14bee3 |
| Owned / Shield | b57e9fb34592b6ec8ba4b60488260c44a2a1cd5021e296abbfb4c9917bb064d2 |
| Owned / Shield+Mirage | 1ee42aacdab072b62509a4bdcac4928525ca36386ccc81f2e9e5ee47807071d7 |
| PhotoCraft color / original Cargo | 63acbd92cb5a372cd2e8da5f26e3aabb1e598d4f802bc868522a037871400b27 |
| PhotoCraft color / matched baseline | 0d652724144212174733e5aacd952dd1d3ccbf5fc043a9972d0dcc212b99605a |
| PhotoCraft color / Shield | 71a2274ee80f2ba38f37fef4e3ab90e5a61901f3d1ddf645f6ea74113bdc226d |
| PhotoCraft color / Shield+Mirage | da84cd984e836e512e6d29abd4a40ce715b1a6f3cce34fbf3918c7dbfe6415e5 |
| PhotoCraft algo / original Cargo | 87be31ab63b04bf1b23db064c46f0128684932c98049ce13ab377c469167c515 |
| PhotoCraft algo / matched baseline | cbf6e6a19758c2d7ced13d195e997b8a0224f36c13e36171f6695eb74a53f46f |
| PhotoCraft algo / Shield | 8dcb76dda7a3e13fa0bdcad79164d37e43eaf27b65196a1ad85f5abd8ebcc3bd |

Full SHA-256 of IR inputs and protected outputs (inputs from standalone runs):

| Component / stage | Bytes | SHA-256 |
| --- | ---: | --- |
| Owned / raw pre-opt IR | 118,051 | 8bc5e689c3d5eb71bd49dbc87767fb5cc23eca0a41c56437b77a14bd681eba8b |
| Owned / marked adapter input | 118,153 | ca9f838da13e13b0695291168b3ea00458bf9e1c4343460070ac55e96f4e6cc0 |
| Owned / Shield output | 119,684 | dc47801481cd2392b4af74140050bbbf1e94ca42299cfe371248c9fde08e9ab3 |
| Owned / Shield+Mirage output | 121,925 | 5be2b5ff394eb78f7f4d2ea9a069fb9004bb583529bb4015817b9be53b64e624 |
| PhotoCraft color / raw pre-opt IR | 2,730,717 | 541060ed3e87bb3854ede6066292aa912675d15142d6e790fa6c4617f2b314a7 |
| PhotoCraft color / marked adapter input | 2,731,108 | 32e1b59b38387d576868ff11b4063d20eef26cc80ce501cac25c871c654ca468 |
| PhotoCraft color / Shield output | 2,731,747 | 6c5d85f608aee207689da60cab9862f1e17fa109a3825b550846db8e4479ae7d |
| PhotoCraft color / Shield+Mirage output | 2,713,193 | f7ce5de61246c471bbb32db202edfb77272e092f8828bca535c3a11a18087793 |
| PhotoCraft algo / raw pre-opt IR | 287,569,908 | a08d97f6c66852a1ae7211da795f1cbcdcfb11fd19194793785820fa8c67af1f |
| PhotoCraft algo / marked adapter input | 287,575,229 | 46acb23d13d7c2f5cd8289b44a7534de631c7ed85cee7c56314bd6730f804f3a |
| PhotoCraft algo / Shield output | 287,581,131 | 33979c606d4b25667c6f77ebec378c37661f2d2779d214a92993929a1ce3a631 |

Private Core job IDs and run-record hashes:

| Run directory | Core job ID | run.json SHA-256 |
| --- | --- | --- |
| owned-final-shield | fc4a5a88f1b142208c10596f11338b7c | 6019f19bc9dbefb66a9c204258ff5b6542b819ddbde25e13559348d9201f6556 |
| owned-final-combined | 2714024561734332820686658fb64112 | 621bc458715db8d2eb8f8cc7b35e43d330c24866192d637d8c8a9b06fb2a9c3a |
| color-shield | 447feef8363c427c9cdb504fdb42c553 | 1411cc4ebd5f73c70391c9455534c599c747d054fa6563aac4a5b5bae347d012 |
| color-combined | eed0c2bf1ac6474295d117229e1ca082 | 1d81814cc6e328a8c363bbb3bc1ecbd1e7572b137e8eb9def7ba2f43350a410f |
| algo-shield | 5bb062011f3e48ff966f87200f09eb7d | 1057f2ae1ceb5c1acb0c31acc7b5ac39ab095be78c58199053fa9dcb2a44cd4f |
| algo-mirage-limit | none; preflight refusal | 524fa4776553aad5a58da7aa60f32c8b01e90bbbf4b6eb2c6ea7f4eef31785d9 |

## Observed performance

Whole test-process wall times in milliseconds: median [min, max]. Five samples
per variant for owned/color, three for algo; no explicit warmup. Times include
process launch and the crate test workload, using one libtest thread. Other agents,
compilation and companion validation were active on this same host; CPU affinity,
frequency, cache state and system load were not controlled. Raw samples remain in
each run.json. This is a noisy compatibility observation, **not a controlled
protection-overhead benchmark**, and cannot be extrapolated to other workloads.

| Run | Samples per variant | Original Cargo ms | Matched baseline ms | Protected ms |
| --- | ---: | ---: | ---: | ---: |
| owned-final-shield | 5 | 3.314 [1.238, 3.454] | 3.277 [1.233, 3.378] | 3.283 [3.254, 3.397] |
| owned-final-combined | 5 | 3.368 [3.307, 3.416] | 3.417 [3.357, 3.495] | 3.379 [3.373, 3.434] |
| color-shield | 5 | 602.956 [582.931, 683.467] | 683.395 [651.792, 733.449] | 702.096 [667.287, 709.200] |
| color-combined | 5 | 617.929 [601.506, 632.859] | 683.721 [683.139, 752.075] | 683.374 [682.699, 701.872] |
| algo-shield | 3 | 52977.188 [50928.036, 55589.435] | 51735.907 [50944.107, 57932.252] | 57652.267 [50628.524, 57994.140] |

## Regression and compatibility validation

```sh
.venv/bin/python -m pytest integrations/rust/tests -q \
  --rust-shield-plugin /tmp/aegis-shield-build/AegisShield.so

.venv/bin/python -m pytest core/tests platform/api/tests platform/cli/tests \
  protectors/llvm/adapter/tests -q \
  --shield-plugin /tmp/aegis-shield-build/AegisShield.so \
  --shield-opt /usr/bin/opt --shield-clang /usr/bin/clang \
  --shield-llvm-link /usr/bin/llvm-link

ctest --test-dir /tmp/aegis-shield-build --output-on-failure
ctest --test-dir /tmp/aegis-fsv/ws/imagelab-build --output-on-failure
```

| Suite | Final result |
| --- | --- |
| New Rust module | **63 passed**, no warnings/skips, 3.57 seconds: 59 parser/failure/process tests and 4 real adapter/build/test cases |
| Core/API/CLI/both existing real adapters | **675 passed**, 1 existing Starlette/httpx TestClient deprecation warning, 42.31 seconds, outside restricted sandbox |
| Existing Shield CTest | **1/1 passed**, 1.40 seconds |
| Existing ImageLab CTest | **12/12 passed**, 3.00 seconds |

Initial companion execution under the restricted runtime failed in Core's
containment subprocesses; an isolated reproduction gave **183 passed, 1 failed**
(`sandbox_start_failed`). The broader sandbox run was interrupted and has no final
pass count. The unchanged suites passed on the authorized unrestricted rerun;
no Core tests or controls were modified. Existing native builds were reused.

Development-only failures also remain distinct from final results: the initial
fixture's explicit `wrapping_add` calls changed instantiated core helpers rather
than authored functions. The final fixture uses direct release integer arithmetic
and asserts its own functions transform. A replay initially omitted `opt-level=3`,
which enabled overflow checks and failed edge tests in both variants; the replay
and normalization regression were fixed before PhotoCraft experiments.

The suite covers unsupported compiler modes, strict captures, symlink/hardlink
rejection, signature selection, exact linker parsing, literal argv/environment
handling, test-output inconsistencies, differing failing names with equal counts,
diagnostic overflow, process-group timeout cleanup, final Mirage retention, actual
baseline failure preservation and actual input-size rejection before a job.
The real algo experiment additionally exercises the fixed Mirage cap. Missing
prerequisites fail the explicitly selected real suite rather than silently skipping.

Other platforms/compiler versions, whole application builds, protected rlib use,
doctests, workspace injection, signing/Sentinel in this wrapper, fresh full Lab,
Mirage standalone, native-integration, dashboard, hosted CI and full release gates:
**NOT RUN in this task**. Those modules were not changed; release-wide validation
belongs to the coordinated release owner. No established suite was weakened.

## NVIDIA coordination and security limits

This Rust session made **0 inference requests, 0 spending reservations, $0 estimated
usage**. This does not assert a zero cumulative project bill. The operator resolved
the designated credential runtime as their separate Fish terminal at this repository
and centrally coordinates the shared **$20 total** ceiling and single-use approvals;
there is no agent-accessible shared ledger to assume exists. No key was requested,
read, printed, copied or passed to an LLM prompt.

Claude owns the baseline and Shield live evaluation. The independent evaluation
engineer coordinates the fresh owned `recon_mix` comparison and verified evidence.
No overlapping Rust calls were prepared or executed: an extra selected arithmetic
function comparison after O3 would add little to that coordinated experiment.
Fresh owned Rust run records and binaries were handed off for evidence-import
compatibility. **Fresh NVIDIA evaluation evidence was not available to this task
at this report's completion**; historical offline revalidation is not counted as
a new call or a Rust attack result. The operator/evaluation owner must supply and
verify that separately. No PhotoCraft source was transmitted, no model-generated
candidate was compiled/executed, and no behavioral attack score is claimed.

No reverse-engineering resistance, tamper protection or security property has been
established. Native byte differences, integer expansions, test agreement and
retained unreachable decoys do not establish such properties.

## Remaining manual steps and unresolved problems

- Obtain/trust an eligible crate, its dependencies and native libraries; build the
  matching Shield plugin separately. Toolchain installation is outside this tool.
- Capture one fresh Cargo library-test invocation and deliberately choose that
  entire component for signature-based marking. Fresh Cargo target directories
  avoid a cache hit producing no capture. Keep capture paths valid.
- Source/build provenance is not independently established: arbitrary source and
  dependency graphs are not hashed or snapshotted by this wrapper. Compiler and
  artifact identity, observed commands and outcomes are recorded, not an SBOM.
- Custom compile-time environment and nonstandard linker/codegen configurations
  need manual integration; they are unsupported or fail replay explicitly.
- Post-opt IR can have zero eligible functions; arithmetic flags and signatures
  constrain coverage. The adapter's no-op error remains a failure. Color has no
  authored transformation. No particular protected IR shape is promised after O3.
- Large Rust IR needs substantial scratch and explicit input-limit increases;
  algo's 32,972,711-byte Shield report also approaches this wrapper's 32 MiB report
  cap. Mirage's independent 64 MiB module cap remains unresolved. There is no
  automatic splitting, silent fallback, or changed Mirage limit.
- Algo's upstream NaN assertions still fail. Runtime tests cover only the crate's
  supplied harness and owned reference checks; equivalence beyond them is unproven.
- Whole-app Cargo substitution, library artifact production, incremental/cache
  integration and workspace-wide protection remain **not implemented**.
- Generated artifacts/private reports stay in scratch; neither third-party inputs
  nor this optional workflow's generated output were added to a release archive.

## Changed-file inventory

All additions are under exclusive ownership `integrations/rust/`; existing files
elsewhere were left as found, including other contributors' uncommitted work.

| File | Purpose |
| --- | --- |
| `capture.py` | Opt-in single-crate Cargo compiler capture |
| `protect.py` | Optional bounded component protection/relink/test workflow |
| `README.md` | Reproducible developer guide, supported configurations and failures |
| `RESULTS.md` | This measured report and limitations |
| `pyproject.toml` | Module-local optional pytest defaults; no installable package |
| `.gitignore` | Ignore module test caches and accidental Cargo target output |
| `tests/conftest.py` | Module import path and explicit real-plugin option |
| `tests/test_pipeline.py` | Parser, failure, environment and process regressions |
| `tests/test_real.py` | Both real backends, actual failing baseline and size-limit cases |
| `fixtures/component/Cargo.toml` | Standalone owned crate/release profile; no dependencies |
| `fixtures/component/Cargo.lock` | Only that owned package; no third-party dependencies |
| `fixtures/component/src/lib.rs` | Owned arithmetic functions and four independent reference tests |
