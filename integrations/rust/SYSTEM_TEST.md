# Current-tree PhotoCraft system test — 30 October 2026

**Completed:** both color pipelines pass their component tests. Algo's actual
Shield job, native compile and linking succeed; matched/protected test outcomes
agree in all three samples, with one existing failing test. Its workflow correctly
exits **failed: BASELINE_TEST_FAILURE**. Oversized Mirage input fails explicitly.
The first `/tmp` adapter failure is preserved separately from the SSD retry.

## Scope and provenance

This independent rerun started at 10:09 Toronto against HEAD
`691ce2717934c22dd30883b5dd8a586ebf78bf20` plus the current combined uncommitted tree.
It introduces no features or runtime changes. Its only repository addition is
`integrations/rust/SYSTEM_TEST.md`. Existing source/dependency/toolchain and licensing
settings are unchanged. Verification completed at 10:36 Toronto, before the
requested noon verification cutoff; feature development had already stopped before
the original 10:15 cutoff. No credentials, inference requests, spending, generated
candidate execution, installation, commit, push or publication are involved.

Initial private scratch: `/tmp/aegis-rust-system-20261030-1010` (0700). Bulk retries
use `/home/youss/aegis-system-test-scratch-20261030/rust` on the SSD (0700), explicitly
provided by the release owner and accessed through approved tool escalation. The before-run
fingerprint in `sources-before.json` covers 47 relevant Core, Shield, adapter,
Mirage and Rust module source/configuration files. The completion audit found
**0/47 changed**; `sources-after.json` records the matching final hashes. This is
a scoped runtime audit, not a claim that unrelated concurrent release files were
unchanged. PhotoCraft's authorized existing checkout remains clean at
`28be431b4ad3ddc7080d46f3eacc399f3e44fa5b` under
`/tmp/aegis-fsv/targets/photocraft`; its workspace declares `MIT OR Apache-2.0`.
No third-party source, IR, native artifacts or private function reports enter the
repository/release through this change.

Host/toolchain: Linux 7.2.3-1-cachyos x86-64, Intel Core Ultra 9 185H (22 logical
CPUs), Python 3.14.7, rustc 1.98.1 (LLVM 22.1.8), matching installed LLVM/Clang
22.1.8 tools. Native source and dependency archives are the existing authorized
ones. To avoid duplicating dependency storage with only 2.4 GiB initially free in
`/tmp`, the selected color/algo test binaries were compiled afresh by replaying
their recorded Cargo rustc argv with new output directories. Dependency archives
were reused; dependency graph resolution/recompilation was **not** repeated.
These are fresh native selected-crate compiles and captures, not reused protected
artifacts or a new whole-workspace Cargo build.

The current Shield source was rebuilt in private scratch. Its new plugin SHA-256
is `ed3002eef080e2b178d33d294a0497d5126d0c395b6cb6733ecad6f8a1d2b214`, identical
to the earlier plugin's bytes. The existing LLVM adapters and Core orchestrator
from the current tree execute all protection jobs; no mock backend is used.

## Commands and exact command records

From `/home/youss/Projects/aegis`:

```sh
cmake -S protectors/llvm \
  -B /tmp/aegis-rust-system-20261030-1010/shield-build -G Ninja \
  -DLLVM_DIR=/usr/lib/cmake/llvm -DCMAKE_CXX_COMPILER=/usr/bin/clang++ \
  -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/aegis-rust-system-20261030-1010/shield-build -j2
ctest --test-dir /tmp/aegis-rust-system-20261030-1010/shield-build --output-on-failure

.venv/bin/python -m pytest integrations/rust/tests -q \
  --rust-shield-plugin /tmp/aegis-rust-system-20261030-1010/shield-build/AegisShield.so
```

Fresh captures used the current `capture.py` and concrete rustc executable from
each previous capture. For each `name` in `color`, `algo`, the replay preserved
the original argv except its `--out-dir`, now
`/tmp/aegis-rust-system-20261030-1010/<name>-cargo-replay`. It supplied the capture's
allowlisted Cargo compile-time metadata, `AEGIS_RUST_CRATE=photocraft_<name>` and
`AEGIS_RUST_CAPTURE=/tmp/aegis-rust-system-20261030-1010/<name>-invocation.json`.
`capture-steps.json` stores both exact expanded argv/cwd, log locations and timings;
the fresh invocation JSON files store the resulting exact compiler metadata.
The supervising runner used argv arrays, no shell, a minimal environment, private
logs, process-group cleanup and a 600-second wall timeout for each capture.
Color's fresh compile/capture took 3.392 seconds; algo's took 133.118 seconds.

```sh
.venv/bin/python integrations/rust/protect.py \
  --invocation /tmp/aegis-rust-system-20261030-1010/color-invocation.json \
  --output /tmp/aegis-rust-system-20261030-1010/color-shield \
  --plugin /tmp/aegis-rust-system-20261030-1010/shield-build/AegisShield.so --samples 3

.venv/bin/python integrations/rust/protect.py \
  --invocation /tmp/aegis-rust-system-20261030-1010/color-invocation.json \
  --output /tmp/aegis-rust-system-20261030-1010/color-combined \
  --plugin /tmp/aegis-rust-system-20261030-1010/shield-build/AegisShield.so \
  --backend llvm-shield-mirage --samples 3

.venv/bin/python integrations/rust/protect.py \
  --invocation /tmp/aegis-rust-system-20261030-1010/algo-invocation.json \
  --output /tmp/aegis-rust-system-20261030-1010/algo-shield \
  --plugin /tmp/aegis-rust-system-20261030-1010/shield-build/AegisShield.so \
  --max-input-bytes 536870912 --samples 3
```

The `/tmp` algo attempt failed with outer `ADAPTER_FAILED`, nested
`ADAPTER_IO_ERROR`, job `817d21c4e3c940e89babb279aeac4750`, **zero registered
outputs**. The adapter intentionally exposes no underlying errno. Concurrently,
the shared tmpfs reached 100% according to the release owner; 578 MiB remained
after adapter cleanup. Storage exhaustion is consistent with these observations,
not independently proved from the adapter's generic diagnostic. The complete
failed attempt remains intact; it is not counted as successful protection.

After that attempt exited, the full pipeline was restarted with the same fresh
capture, a new output directory and all subsequent compiler/Core work on SSD:

```sh
.venv/bin/python integrations/rust/protect.py \
  --invocation /tmp/aegis-rust-system-20261030-1010/algo-invocation.json \
  --output /home/youss/aegis-system-test-scratch-20261030/rust/algo-shield \
  --plugin /tmp/aegis-rust-system-20261030-1010/shield-build/AegisShield.so \
  --max-input-bytes 536870912 --samples 3

.venv/bin/python integrations/rust/protect.py \
  --invocation /tmp/aegis-rust-system-20261030-1010/algo-invocation.json \
  --output /home/youss/aegis-system-test-scratch-20261030/rust/algo-mirage-limit \
  --plugin /tmp/aegis-rust-system-20261030-1010/shield-build/AegisShield.so \
  --max-input-bytes 536870912 --backend llvm-shield-mirage --samples 1
```

Historical/shared evidence was neither deleted nor moved. This relocation requires
no workflow source change: the new location is outside all Git/source trees and
satisfies the existing output-containment checks.

Every completed `run.json` records the exact rustc, LLVM, linker and native test
argv/cwd, versions, stage timings/logs, original/IR/output hashes, Core job and
named libtest outcomes. The workflow uses pre-opt IR, explicit signature marking,
real adapter protection, matching `clang -O3 -fPIC`, and rustc's actual linker argv
with only the primary CGU object/output substituted. Original Cargo/ThinLTO,
matched unprotected and protected test binaries are separate variants.

## Results

| Check | Result |
| --- | --- |
| Fresh Shield build | configured and built, no compiler warnings |
| Shield CTest using fresh build | **1/1 passed**, 1.34 seconds |
| Rust module using fresh build/current Core/adapters | **63 passed**, 0 warnings/skips, 3.49 seconds |
| PhotoCraft color / Shield | succeeded: original, matched and protected **30/30 pass** in each of 3 samples |
| PhotoCraft color / Shield+Mirage | succeeded: original, matched and protected **30/30 pass** in each of 3 samples; all 3 decoy symbols retained after O3/final linking |
| PhotoCraft algo / Shield | SSD Core job succeeded: 13 functions / 26 sites; native compile/link succeeded; original 725 passed / 2 failed / 27 ignored, matched and protected each 726 / 1 / 27 in all 3 samples; pipeline **failed: BASELINE_TEST_FAILURE** |
| PhotoCraft algo / Shield+Mirage | **failed: MIRAGE_INPUT_TOO_LARGE** on the SSD rerun, before any Core job; no native protected build or test execution |

Color's adapter reports **1 transformed function / 2 sites** out of 866 definitions
and 23 marked signatures. The transformed function is an instantiated std helper;
**no PhotoCraft-authored color function transforms**. These are adapter claims,
separate from verified artifact hashes and locally observed test outcomes. Each
color pipeline emitted two Clang vendor-only target-triple override warnings
(one each for baseline/protected code generation), preserved in its stage logs.

Algo's fresh marked input is larger than Mirage's fixed 67,108,864-byte module cap.
The actual combined invocation above exits 1 with `MIRAGE_INPUT_TOO_LARGE`, even
though the operator deliberately raised the wrapper/Core/adapter input ceiling to
536,870,912 bytes. The wrapper neither silently falls back to Shield nor changes
Mirage's independent limit. The separate successful Shield Core job is
`3edfe29f1b4244b7b1b3d2f0c07c6515`; its protected IR SHA-256 is
`33979c606d4b25667c6f77ebec378c37661f2d2779d214a92993929a1ce3a631`.

Algo has 72,781 pre-opt definitions and 313 marked integer signatures. Its current
matched baseline and protected binaries both fail
`pixelate::tests::facet_reuse_matches_scalar_in_every_model`, a NaN bit-pattern
assertion. The original ThinLTO binary additionally fails
`pixelate::tests::cell_filters_match_scalar_models_edges_and_fractional_cells`.
Every original/matched/protected test invocation exits 101; all named outcomes,
not merely totals, remain stable across the three samples. The 27 ignores are
the crate's existing ignores, not filters added by AEGIS. No upstream source or
tests were altered, filtered or weakened. Agreement on these observed outcomes
does not turn the failing suite into a pass or prove whole-program equivalence.

The SSD Shield run records `tests.equivalent=true`, `baseline_passed=false`,
`original_passed=false`, `original_matches_baseline=false` and final status
`failed`. Its local error is `BASELINE_TEST_FAILURE`, separately from the real
succeeded Core job. Like color, its native code generation emits two preserved
Clang vendor-only triple warnings. Algo's Shield output and final baseline/Shield
ELF hashes reproduce the previous experiment despite the new private output paths.

## Verified artifact identity and measurements

All recorded input/intermediate/native artifact hashes and Core output hashes were
recomputed from the actual files at completion. Native hashes below are local
observations; protected IR hashes are Core-computed and locally rechecked.

| Component / final variant | ELF bytes | .text bytes | SHA-256 |
| --- | ---: | ---: | --- |
| Color / original Cargo | 1,674,576 | 868,718 | 63acbd92cb5a372cd2e8da5f26e3aabb1e598d4f802bc868522a037871400b27 |
| Color / matched baseline | 1,691,800 | 846,088 | 0d652724144212174733e5aacd952dd1d3ccbf5fc043a9972d0dcc212b99605a |
| Color / Shield | 1,691,832 | 846,120 | 71a2274ee80f2ba38f37fef4e3ab90e5a61901f3d1ddf645f6ea74113bdc226d |
| Color / Shield+Mirage | 1,692,232 | 846,264 | da84cd984e836e512e6d29abd4a40ce715b1a6f3cce34fbf3918c7dbfe6415e5 |
| Algo / original Cargo | 12,623,880 | 8,165,614 | 87be31ab63b04bf1b23db064c46f0128684932c98049ce13ab377c469167c515 |
| Algo / matched baseline | 14,046,512 | 8,597,427 | cbf6e6a19758c2d7ced13d195e997b8a0224f36c13e36171f6695eb74a53f46f |
| Algo / Shield | 14,046,984 | 8,597,747 | 8dcb76dda7a3e13fa0bdcad79164d37e43eaf27b65196a1ad85f5abd8ebcc3bd |

.text was measured with llvm-size -A on each actual final executable.

| Run / Core job | Marked input bytes / SHA-256 | Protected IR bytes / SHA-256 |
| --- | --- | --- |
| color-shield / d674d5096ea045589c5d0ca146dc1486 | 2,731,117 / b6edd2e598fdf24d606ade48168707ac8108e130d24f6d3fd08bc53b52fa07ec | 2,731,747 / 6c5d85f608aee207689da60cab9862f1e17fa109a3825b550846db8e4479ae7d |
| color-combined / 607d298e45ea42fbb8d3c009e9dc52c3 | 2,731,119 / e59b212c0dbea2c3c08eb549cc75cd337288c3c458903e3b7d6e7ec25a8e1f31 | 2,713,193 / f7ce5de61246c471bbb32db202edfb77272e092f8828bca535c3a11a18087793 |
| algo-shield / 3edfe29f1b4244b7b1b3d2f0c07c6515 | 287,575,253 / f69e2d71e4221a4c05b85ff970d2c541f6be577f6056d836d3fedf37ac7b47ab | 287,581,131 / 33979c606d4b25667c6f77ebec378c37661f2d2779d214a92993929a1ce3a631 |

| Run record | Status / error | run.json SHA-256 |
| --- | --- | --- |
| color-shield | succeeded / none | 09ebd44a9bcfd05c8ab5cc2eee9be8dfc0ed38c840e6ff0cd444cf13e0228cf6 |
| color-combined | succeeded / none | 1875b920b35fbace2d9bd9004f4877c650e404a07061ff91d9014bfab2e23267 |
| algo-tmp-failed | failed / ADAPTER_FAILED | 9d845adf8f241e6479716c286e676415ef29665264a2bdfcfbceb15560d5ca67 |
| algo-shield | failed / BASELINE_TEST_FAILURE | 217cf3c08c5a295ecb60855d4723f8e2a33dbf6f728b9938a078bcf4e4e79ae3 |
| algo-mirage-limit | failed / MIRAGE_INPUT_TOO_LARGE | 433b2b7db7b2c7eeb8d5b431cac4b207bcbc23d8831c42f9d2d7f316bbb1b01d |

Whole test-process wall times, seconds: median [minimum, maximum], three samples
per variant, alternating forward/reverse order, one libtest thread, no explicit
warmup. Source/build/gate work was concurrent on the host; CPU frequency, cache
and affinity were uncontrolled. These are observed test timings, not controlled
overhead estimates or measurements transferable to other workloads.

| Pipeline | Original seconds | Matched seconds | Protected seconds |
| --- | ---: | ---: | ---: |
| color-shield | 0.703 [0.609, 0.709] | 0.685 [0.652, 0.769] | 0.703 [0.634, 0.706] |
| color-combined | 0.552 [0.552, 0.559] | 0.634 [0.618, 0.652] | 0.633 [0.617, 0.659] |
| algo-shield | 50.090 [49.546, 53.935] | 52.134 [50.955, 54.624] | 51.770 [51.190, 52.280] |

## Release assessment

No new Rust module code blocker was found and no runtime/source fix was made.
The supported optional component workflow is operational on this current tree.
The original `/tmp` job demonstrates that large modules need sufficient private
scratch: its adapter failed explicitly with no outputs; the unchanged pipeline
then completed real protection/compilation/linking on adequately sized SSD scratch.
That environmental failure remains part of this report, not a passing run.

Outstanding limits remain: algo's upstream failing test prevents an all-passing
PhotoCraft claim; Mirage cannot process its large module; color transforms only
an instantiated std helper; whole-application/rlib protection is not implemented.
These constrain release claims and were not hidden by a fallback or test change.
Root release gates and the independent inference-only wrapper fix are owned by
the release engineer and are outside this task's source audit/test scope.

Changed repository file in this rerun: **`integrations/rust/SYSTEM_TEST.md` only**.
All generated inputs, binaries, IR, detailed function reports and audit/summary
records remain in the two private scratch locations above. `system-test-summary.json`
under the `/tmp` location records the reverified hashes, named outcomes, warnings,
timings and all five run-record paths/hashes, including the failed first attempt.

## Limits and checks not run

Whole-application PhotoCraft protection, protected rlib production, GUI/assets,
doctests and other target/platform/toolchain combinations are **not run** and remain
outside the supported component workflow. Root full integration/API/dashboard/
browser/signature/Sentinel gates are being run by the release owner, not duplicated
here. This report must not be presented as those gates passing.

No NVIDIA inference or new Ghidra/REA experiment is performed here. The operator
and Claude own the coordinated live runs; no request is duplicated and no
third-party source is disclosed. Changed IR/native bytes, decoy retention and
matching tests establish **no reverse-engineering resistance or security property**.
