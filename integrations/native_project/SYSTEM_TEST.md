# Current-tree reVC system test — 30 October 2026

Fresh execution started at 10:09 Toronto, after the native-module handoff. This
report supersedes the earlier **two-component** reVC test only for the new scope
below; it does not combine results from historical runs. Evidence root:
`/tmp/aegis-native-system-20261030-1009/` (0700).

**Verdict: actual game baseline build fails; selected component protection,
native linking and finite runtime comparisons work. The game was not linked or
run, and whole-game protection/equivalence is not claimed.**

## Fresh build and protection results

| Operation | Observed result |
| --- | --- |
| Build Shield from current repository source | Passed; new build directory, LLVM 22.1.8 |
| Fresh Shield CTest | **1/1 passed**, 1.37 s |
| Configure fresh reVC baseline | Passed; one upstream CMake deprecation warning |
| Compile whole declared game/librw build | **Failed**: **293/308** compile-database TUs produced objects; **15** failed |
| Selected real TUs through production Shield | **20/20 succeeded**, 29 per-TU function records / 50 sites |
| Same TUs through production Shield+Mirage | **20/20 succeeded**, same 29 function records / 50 sites |
| Standalone Shield vs combined Shield-stage IR | **20/20 identical SHA-256** pairs |
| Full-TU O2 native observations, each backend | **13** function records differ, **3** identical, **13** unavailable |
| Mirage in combined full-TU objects | **60/60** decoy symbols retained (3 per TU) |
| Extracted, self-contained function execution | **13 function instances / 10 unique linkage names**, O2 and O3, **5,740,206 comparisons, 0 mismatches** |
| Full Darkel TU linked to owned driver | **6 executables**, baseline/Shield/combined at O2/O3, **229,791 cases each**, matching output |
| Mirage in those final combined executables | **3/3** decoys retained in each; baseline/Shield have none |

The 20 selected TUs contain 1,392 observed IR definitions, including header/inline
instances. The 29 transformed records represent 26 unique linkage names, not 29
distinct source-level functions. This is targeted component coverage, not a scan
of every eligible function in all 293 compilable TUs.

| Selected source group | TUs | Observed definitions | Reported transformed function instances | Sites |
| --- | --- | --- | --- | --- |
| reVC game | 8 | 746 | 10 | 12 |
| vendored librw | 12 | 646 | 19 | 38 |

These candidates were selected using earlier compatibility findings, but every
source compilation, IR selection, adapter invocation, verification, native object
and runtime result in this report was produced anew. No historical job, IR or
protected object was used as a successful result. The fresh 308-entry compile
database was generated in this run. The other 273 successfully compiled TUs
received only baseline compilation in this run; the remaining 15 failed baseline
compilation. Two additional real-source negative tests are reported separately.

## Current inputs and baseline failure

Repository HEAD remains `691ce2717934c22dd30883b5dd8a586ebf78bf20`, plus the current
combined working tree. Host/toolchain: Linux 7.2.3-1-cachyos, glibc 2.44, x86-64,
Intel Core Ultra 9 185H / 22 logical CPUs; Python 3.14.7, clang/clang++/opt/
llvm-link/llvm-extract 22.1.8, CMake 4.4.3, Ninja 1.13.2.

Used the already present authorized local checkout
`/tmp/aegis-fsv/targets/revc`, commit
`1b9a5897fdb319c318581a5f9535d2d9661ad578`. No source or assets were downloaded,
licensed, redistributed or sent to a model provider. The existing checkout and
dependencies were reused; build/cache/object directories were new.

Fresh baseline configure selected GL3 + SDL2 + OpenAL, with the source tree's
vendored librw. **The actual diagnostics are GLFW API incompatibilities in that
configuration**, including unknown `GLFWwindow`, missing GLFW gamepad constants
and unavailable GLFW declarations. The fresh errors are not merely an assumed
header-not-found failure. Fifteen TUs fail, starting in `audio/oal/stream.cpp`,
`audio/sampman_oal.cpp`, `core/ControllerConfig.cpp`, and other platform-dependent
units listed exactly in `baseline-summary.json`. The build log contains **37 error
diagnostics and 14,046 warning diagnostics** (repeated headers across TUs included).
The CMake configure warning concerns future removal of compatibility with CMake
versions below 3.10. No warning was suppressed or error turned into success.

Each 20-TU native protection build captured **1,474 upstream compiler warning
diagnostics**, zero compiler errors; its ordinary source and pre-optimization IR
compiles both emit diagnostics. The incompatible-unit negative captured 65
warnings / 16 errors, and the no-op negative captured 84 warnings / 0 compiler
errors. These are separate diagnostic counts, not unique issues or pytest warnings.

Game link was blocked by compilation; no `reVC` executable was produced. Game
execution, game-level correctness and retention in a final game executable were
**not run**. Proprietary game assets were not obtained. No project-source patch,
dependency installation or third-party licensing change was attempted to conceal
these blockers. Compiling a selected TU or testing one method is not testing the
game.

## Real runtime correctness checks

`differential_check.py` in the private evidence root loads the **fresh** Shield
and combined reports. For each transformed function it uses matching LLVM 22
`llvm-extract` on the fresh selected baseline, Shield output and combined output.
It refuses functions with external non-intrinsic declarations, globals,
`inttoptr`, unsupported signatures or inline assembly. Thirteen instances passed
those conditions; **16 were not executed**. The 13 include four instances of the
same inline vertex-count method, hence ten unique linkage names.

The owned C harness generates deterministic edge cases and 200,000 pseudorandom
cases per instance/optimization, with initial SplitMix64 state
`0x9e3779b97f4a7c15`. Arguments are generated once and passed unchanged to all
three variants, including the fourth argument where present. Both O2 and O3
were freshly compiled, linked and executed. The total is **5,740,206 case
comparisons across three returned values**, not 5.7 million distinct game tests.
Output checksums also matched between optimization levels. No compiler/runtime
warning or trap was observed in these harness runs.

Input-domain restrictions are explicit in `differential-summary.json`:

- Reverse-bit count is 0–32, avoiding undefined wide shifts.
- Swizzle coordinates are 0–255; log-width is 1–10, keeping shifts valid.
- Vertex-count input attributes are 1–255; output attributes/buffers are 0–255,
  so its divisor is nonzero. All four arguments are independently generated.
- Other tested arithmetic uses stated integer edge/random values. No complete
  source undefined-behavior audit or formal equivalence proof is claimed.

Extraction changes linkage/names to let all three versions coexist; it does not
change the function bodies. It removes unrelated functions/decoys, so this first
check does **not** establish interaction with the complete game or retained
Mirage inventory.

A second, stronger component check, `darkel_link_check.py`, compiles the **full
fresh Darkel translation-unit IR** for all three variants. It performs no
extraction, name change or function-body edit. Function/data sections and
`--gc-sections` discard unreferenced game methods so the real self-contained
method can link to an owned driver. Mirage's retained sections remain in the
actual combined executable. There are six final executables, with each running
31 cubed boundary-value cases plus 200,000 deterministic random cases:
**229,791 executions of the selected method per executable**. All stdout, stderr
and exit codes match across the three variants at each optimization level, and
the result checksums match across levels.

The selected method is **81 machine bytes** in baseline, **95** in Shield and
combined, for both O2 and O3. The two protected method byte sequences match each
other. Each combined executable also contains all three Mirage decoy functions;
the two controls contain none. Other game sections were deliberately discarded:
these are real **component test executables**, not game executables. Static byte
differences and retained decoys establish no attack resistance.

## Final artifacts and hashes

Both backend build reports rehashed successfully: **652** inventoried files for
Shield, **692** for combined. The report hashes and all accepted protected-object
hashes are recorded privately. Important exact digests:

| Artifact | SHA-256 |
| --- | --- |
| Freshly built plugin | `ed3002eef080e2b178d33d294a0497d5126d0c395b6cb6733ecad6f8a1d2b214` |
| `shield-20/report.json` | `0e4e914ca5778abad89dcbb31f8051b9fc6217acbccdc44a681736f1d6bb8ea6` |
| `combined-20/report.json` | `4fb88a50727d711682bf0f967a5348bd846f00f6259ac6be3c5fd397cca7f8d0` |
| `differential-summary.json` | `a08af4e77475ffde639cfd033c8e24dfd523ff804b938fe56adb09c91fd27ff1` |
| `darkel-linked-summary.json` | `519fef865fac1296e7dc9a948df71986795cd34a5fbad89b968ef5f9077a29ff` |
| Darkel component baseline ELF, O2 and O3 | `86cca01bff98f8da8daf077b588d9d358e1e82929cbf9b4caf6ae41f1c930733` |
| Darkel component Shield ELF, O2 and O3 | `dab0cb506709c1622242ca27001e25e27c21b32b59a39456a171c272440a15cc` |
| Darkel component combined ELF, O2 and O3 | `028df2c818638d42a99e9b7eeea539114dca9e0cbefa08e6d8c8c14bc660877e` |

The component ELF paths are
`darkel-linked/{baseline,shield,combined}-O{2,3}/component.elf`; baseline/Shield
are 16,128 bytes and combined 16,296 bytes. The extracted-function checks retain
26 additional native harness executables beneath `differential/`. These files
contain third-party-derived code and remain private build artifacts; they are
not release payloads.

`system-artifacts.sha256.json` inventories the persistent fresh evidence and
`final-source-hashes.json` pins the final module and relevant backend source.
The initial snapshot is `initial-source-snapshot.json`. The relevant production
source hashes remained unchanged throughout; only the owned test helper changed
as described below. Records are unsigned consistency evidence, not provenance
attestations. The freshly rebuilt plugin happens to match the earlier plugin's
digest; it was nevertheless compiled from current sources in the new directory.

## Fresh negative cases and suites

| Check | Exact result |
| --- | --- |
| Real `ControllerConfig.cpp` through native workflow | CLI exit **1**, `TOOL_FAILED` at `compile-native`, 0 transformed units, no protected object registered |
| Real `RpAnimBlend.cpp` through combined workflow | CLI exit **1**, `ADAPTER_FAILED` / `NO_TRANSFORMATIONS_APPLIED`, 0 transformed units, no protected output registered |
| Production adapter suite with fresh plugin | **140 passed**, 0 skipped/warnings, 19.84 s |
| Initial module suite with fresh plugin | **66 passed / 1 failed**, 15.57 s; test-helper race below |
| Corrected module suite | **69 passed**, 0 skipped/warnings, 14.65 s |

Both intentional failed native builds still produced truthful failed reports,
and their file inventories verified with `build_status: failed`. Verification did
not turn them into successful protection.

The initially failing test saw `ProcessLookupError` (ESRCH) while reading
`/proc/<pid>/stat` after the supervised child had disappeared. The helper already
handled ENOENT. `tests/test_runner.py` now also recognizes ESRCH as process
disappearance, with explicit regression cases for both errors. A live descendant
still fails the same existing cleanup assertion; no test was skipped or weakened.
**No production/runtime/feature code changed.** This is a test-observation fix
after the feature freeze, not a new feature.

Only repository files changed in this follow-up:

- `integrations/native_project/tests/test_runner.py`
- `integrations/native_project/SYSTEM_TEST.md` (new)

The historical [RESULTS.md](RESULTS.md) remains unchanged and retains its earlier
67-test/two-component snapshot. Final module inventory is now 18 files; its
frozen hashes are in `final-source-hashes.json`.

## Exact commands and reproducibility

All commands ran from `/home/youss/Projects/aegis`, using only existing installed
tools. The source root and shared production code were not edited.

```sh
cmake -S protectors/llvm \
  -B /tmp/aegis-native-system-20261030-1009/shield-build -G Ninja \
  -DLLVM_DIR=/usr/lib/cmake/llvm -DCMAKE_CXX_COMPILER=/usr/bin/clang++ \
  -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/aegis-native-system-20261030-1009/shield-build -j2
ctest --test-dir /tmp/aegis-native-system-20261030-1009/shield-build --output-on-failure

cmake -S /tmp/aegis-fsv/targets/revc \
  -B /tmp/aegis-native-system-20261030-1009/revc-build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=/usr/bin/clang \
  -DCMAKE_CXX_COMPILER=/usr/bin/clang++ -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DLIBRW_PLATFORM=GL3 -DLIBRW_GL3_GFXLIB=SDL2 -DREVC_AUDIO=OAL \
  -DREVC_VENDORED_LIBRW=ON -DLIBRW_INSTALL=OFF -DLIBRW_TOOLS=OFF \
  -DREVC_WITH_SANITIZERS=OFF -DREVC_WITH_ASAN=OFF
cmake --build /tmp/aegis-native-system-20261030-1009/revc-build -j4 -- -k 0

.venv/bin/python integrations/native_project/native_project.py build \
  /tmp/aegis-native-system-20261030-1009/shield-20.json \
  --output /tmp/aegis-native-system-20261030-1009/shield-20 \
  --plugin /tmp/aegis-native-system-20261030-1009/shield-build/AegisShield.so
.venv/bin/python integrations/native_project/native_project.py build \
  /tmp/aegis-native-system-20261030-1009/combined-20.json \
  --output /tmp/aegis-native-system-20261030-1009/combined-20 \
  --plugin /tmp/aegis-native-system-20261030-1009/shield-build/AegisShield.so
.venv/bin/python integrations/native_project/native_project.py verify \
  /tmp/aegis-native-system-20261030-1009/shield-20/report.json
.venv/bin/python integrations/native_project/native_project.py verify \
  /tmp/aegis-native-system-20261030-1009/combined-20/report.json
.venv/bin/python integrations/native_project/native_project.py build \
  /tmp/aegis-native-system-20261030-1009/incompatible.json \
  --output /tmp/aegis-native-system-20261030-1009/incompatible \
  --plugin /tmp/aegis-native-system-20261030-1009/shield-build/AegisShield.so
.venv/bin/python integrations/native_project/native_project.py build \
  /tmp/aegis-native-system-20261030-1009/noop.json \
  --output /tmp/aegis-native-system-20261030-1009/noop \
  --plugin /tmp/aegis-native-system-20261030-1009/shield-build/AegisShield.so

.venv/bin/python /tmp/aegis-native-system-20261030-1009/differential_check.py
.venv/bin/python /tmp/aegis-native-system-20261030-1009/darkel_link_check.py

.venv/bin/python -m pytest protectors/llvm/adapter/tests -q -p no:cacheprovider \
  --shield-plugin /tmp/aegis-native-system-20261030-1009/shield-build/AegisShield.so \
  --shield-opt /usr/bin/opt --shield-clang /usr/bin/clang \
  --shield-llvm-link /usr/bin/llvm-link \
  --basetemp /tmp/aegis-native-system-20261030-1009/adapter-pytest
.venv/bin/python -m pytest integrations/native_project/tests -q -p no:cacheprovider \
  --native-plugin /tmp/aegis-native-system-20261030-1009/shield-build/AegisShield.so \
  --basetemp /tmp/aegis-native-system-20261030-1009/native-pytest-corrected
```

The two manifests list all 20 selected source paths exactly; they refer only to
the new database. Command argv/cwd, diagnostic bytes, effective options and
artifact digests are in their reports. The two owned private test scripts contain
the deterministic harness recipes and record every child command in their
summaries. Their SHA-256 values are respectively
`feac6449cf5b430a918cdee846414f2a890f7f22cc94a33fb0f516c7fa6aeaf5` and
`de0c9897da0295936b2022800948cae71ec87f9346dc0f1df6da74c84110fe27`.
Use new output directories to repeat; the scripts reject reuse.

Logs are `shield-{configure,build,ctest}.log`, `revc-{configure,build}.log`,
`{shield,combined}-20.log`, `differential.log`, `darkel-linked.log`,
`native-pytest.log`, `native-pytest-corrected.log`, `adapter-pytest.log`,
`incompatible.log`, and `noop.log`. Passing disposable pytest fixture directories
were removed to relieve shared `/tmp` pressure; all logs, the failing fixture,
baseline/protected objects and final component/harness executables remain. Scratch
use is about 101 MiB. No historical or other-agent evidence was deleted.

## Blockers and tests not run

- Whole-game build: blocked by 15 existing platform-dependent compilation failures
  in the SDL2 configuration. No game executable; game runtime/equivalence not run.
- Proprietary game assets: not obtained; no attempt to run the actual game.
- Sixteen transformed function instances: not executed because extracted units
  retain external dependencies or fail the conservative harness eligibility check.
- Thirteen full-TU transformed records have no comparable optimized native symbol;
  three have identical bytes. They are not counted as retained native changes.
- No Ghidra, adversarial/NVIDIA inference, generated-candidate execution, signing,
  API/UI integration, package installation, licensing change or publication in this
  follow-up. The release owner handles other integration layers. No security or
  attack-resistance conclusion follows from these checks.
