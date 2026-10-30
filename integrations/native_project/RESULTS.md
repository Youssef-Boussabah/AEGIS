# Native project integration results — 30 October 2026

## Achieved scope

Implemented and tested an optional native C/C++ build workflow entirely inside
`integrations/native_project/`. It accepts explicit manifests or real clang
compile databases, emits and selects pre-optimization IR, supervises the existing
production Shield/Shield+Mirage adapters, verifies IR, builds ELF objects, optionally
links binaries, compares native execution and records hashes and coverage.

**The whole owned example application builds and runs; only two of its four
translation units request protection. reVC testing is two components as objects,
not the game. No whole-application protection or security property is claimed.**

Work began approximately 08:11 Toronto (12:11 UTC); feature implementation and
focused tests finished before 08:35 Toronto, ahead of the 10:15 feature cutoff.
Checkout: `dev/integration`, HEAD `691ce2717934c22dd30883b5dd8a586ebf78bf20`,
with pre-existing concurrent uncommitted work. No existing production/release file
was edited by this task. No commit, push, licensing change, publication, package
installation, model-generated code execution or paid inference was performed.

## Conditions and evidence

Linux `7.2.3-1-cachyos`, glibc 2.44, x86-64; Intel Core Ultra 9 185H, 22 logical
CPUs. Python 3.14.7, pytest 9.2.0, matching clang/clang++/opt/llvm-link 22.1.8,
CMake 4.4.3, Ninja 1.13.2. Existing plugin:

```text
/tmp/aegis-shield-build/AegisShield.so
SHA-256 ed3002eef080e2b178d33d294a0497d5126d0c395b6cb6733ecad6f8a1d2b214
```

No performance or attack-resistance experiment is inferred from the execution
tests. Each build uses a single source compilation per pipeline variant and one
execution per declared case/variant. These measurements apply only to these
sources, flags, tools and host. General equivalence is not proved.

Private persistent evidence is under `/tmp/aegis-native-evidence/`, with the
documented compile-database run under `/tmp/aegis-native-cdb-build/`. Native build
directories are 0700. `report.json` includes every command, working directory,
bounded stdout/stderr file, effective options, per-function adapter reports,
source/plugin hashes, object/binary hashes, execution observations and failures.
`report.sha256` binds that report. These are unsigned consistency records,
**not Core jobs, signed provenance or security attestations**.

## Owned C/C++ application

Source: the seven files in `examples/owned/`. Four TUs: C++ `main.cpp`,
`kernels.cpp`, `policy.cpp`, and C `checksum.c`. Arithmetic and checksum calls
cross object/language boundaries; all are linked into the actual example program.
`kernels.cpp` uses explicit linkage-symbol selection, `checksum.c` uses the
existing source annotation. `main.cpp` and `policy.cpp` remain unprotected.

| Build | Requested / total TUs | Reported changed functions / sites | Different native function bytes | Mirage decoys in linked binary | Execution |
| --- | --- | --- | --- | --- | --- |
| Shield, O2 | 2 / 4 | 3 / 5 | 2 / 3 | none requested | 11/11 cases equal |
| Shield+Mirage, O2 | 2 / 4 | 3 / 5 | 2 / 3 | 6/6 | 11/11 cases equal |
| Shield+Mirage, O3 | 2 / 4 | 3 / 5 | 2 / 3 | 6/6 | 11/11 cases equal |
| Real CMake database, Shield+Mirage, O2 | 2 / 4 database entries | 3 / 5 | 2 / 3 | 6/6 | 11/11 cases equal |

Each row compares **three actually executed binaries**: ordinary source build,
matched unprotected IR build, protected IR build. Every comparison includes exact
stdout bytes, stderr bytes and exit status. Cases cover seed 0, UINT32_MAX,
2^31, empty iteration sets, 1 through 1,000,000 iterations, branch boundary counts,
invalid text, a negative seed, and an excessive count. Three invalid cases return
the expected status 2, with matching stderr; failure is not relabeled success.
No application output files or general side effects are compared.

Six IR definitions were observed across the owned application. Shield reports
`mix_pair` and `fold_word` changed in `kernels.cpp` (four sites), and `step_byte`
changed in `checksum.c` (one site). Native observations and independent inspection
with `llvm-objdump` show:

- `mix_pair` and `fold_word`: different exact ELF function bytes in objects and
  linked O2/O3 executables. The inspected optimized instructions include the
  added xor/and/carry arithmetic. This is limited static retention evidence for
  these functions/flags, not protection against an attack.
- `step_byte`: **identical** optimized function bytes. The reported IR expansion
  does not retain a distinguishable native transformation in these builds.
- All six derived-seed Mirage functions survive O2/O3 and `--gc-sections`, with
  symbols present only in the protected executable. They remain uncalled decoys;
  their presence establishes no reverse-engineering resistance.

At O2, the native source and matched IR baseline files were byte-identical,
16,432 bytes each. Shield remained 16,432 bytes; combined was 16,760 bytes.
File size alone is neither coverage nor evidence of protection.

Selected exact SHA-256 values:

| Artifact | SHA-256 |
| --- | --- |
| O2 normal/matched baseline executable | `eddc9016172516adbc24d374f53125663446230663448d36e8c057f47139aefd` |
| O2 Shield executable | `3cf4d3beb4987dc69952acfb5539beb079a0bac7d6b4146b1070a93092c0ea58` |
| O2 combined executable | `bafbc8e40c16c071313683f2d497f94a6f35c6fb465c1cfa2d8cd86a048e354c` |
| O3 matched baseline executable | `c209604beae5abcd348285fbd450e7cda123b84e24ee66c2dbfa262e2817d6cc` |
| O3 combined executable | `0c7c6bdf72deb6515ae2b7ee2cb72d893fa7fa4cb68d66ff0606e813a8dc4503` |
| O2 Shield report | `1020e7488006d68ab1a9e4757de0d503f20cf88a3148a1cac84967cb988dd2e9` |
| O2 combined report | `5b0492cc124e1a7d75ab21b6b7b51de5fc6a5c73e897374efcb19975a93b76ee` |
| O3 combined report | `5d1ddf6a8a452caf9e1283b26b7215d256a08a8068a2f765308e7b5474b43f5d` |
| Documented compile-database report | `dc66cd865ebc4a8e90828aceb3494ce97534feb415394be70d936d08196f8f9c` |

Hash verification passed for all five persistent reports and all of their
inventoried artifacts (227, 231, 231, 80, and 231 files respectively for Shield O2,
combined O2, combined O3, reVC components, and the documented database build).
Reports include non-reproducible timestamps/job IDs/private paths; artifact hashes
are records of this run, not promises that every fresh directory yields identical
report bytes.

Exact direct-build commands, from repository root:

```sh
.venv/bin/python integrations/native_project/native_project.py build \
  integrations/native_project/examples/owned/project.json \
  --output /tmp/aegis-native-evidence/owned-shield-o2 \
  --plugin /tmp/aegis-shield-build/AegisShield.so --backend llvm-shield --execute

.venv/bin/python integrations/native_project/native_project.py build \
  integrations/native_project/examples/owned/project.json \
  --output /tmp/aegis-native-evidence/owned-combined-o2 \
  --plugin /tmp/aegis-shield-build/AegisShield.so --execute

.venv/bin/python - <<'PY'
import json, os
from pathlib import Path
os.umask(0o077)
source = Path('integrations/native_project/examples/owned/project.json').resolve()
manifest = json.loads(source.read_bytes())
manifest['project_root'] = str(source.parent)
manifest['optimization'] = '3'
with Path('/tmp/aegis-native-evidence/owned-o3.json').open('x') as stream:
    json.dump(manifest, stream, indent=2)
PY

.venv/bin/python integrations/native_project/native_project.py build \
  /tmp/aegis-native-evidence/owned-o3.json \
  --output /tmp/aegis-native-evidence/owned-combined-o3 \
  --plugin /tmp/aegis-shield-build/AegisShield.so --execute
```

The database recipe in [README.md](README.md#existing-compile-databases) was run
exactly at its documented `/tmp/aegis-native-cmake`, `/tmp/aegis-native-cdb.json`
and `/tmp/aegis-native-cdb-build` paths. Use new directories to repeat.

Disassembly was inspected with:

```sh
llvm-objdump -d --no-show-raw-insn \
  --disassemble-symbols=mix_pair,fold_word,step_byte \
  /tmp/aegis-native-evidence/owned-combined-o2/baseline.elf
llvm-objdump -d --no-show-raw-insn \
  --disassemble-symbols=mix_pair,fold_word,step_byte \
  /tmp/aegis-native-evidence/owned-combined-o2/protected.elf
llvm-objdump -d --no-show-raw-insn \
  --disassemble-symbols=mix_pair,fold_word,step_byte \
  /tmp/aegis-native-evidence/owned-combined-o3/protected.elf
```

Private text captures are `baseline-o2.disassembly.txt`,
`combined-o2.disassembly.txt`, `combined-o3.disassembly.txt` in the evidence root.

## reVC/librw — local objects only

Used the already present authorized local educational-evaluation checkout
`/tmp/aegis-fsv/targets/revc`, reVC commit
`1b9a5897fdb319c318581a5f9535d2d9661ad578`, with its existing 308-entry database
`/tmp/aegis-fsv/revc-build/compile_commands.json`. No source/assets were downloaded,
copied into this module, redistributed, or sent to a model provider.

This run selected **2 of those 308 entries**, compiled directly from real C++
source using the database flags/cwd, added conservative integer-signature
selection, called the production combined adapter, and compiled final native
objects at O2:

| Component | Observed definitions | Reported functions / sites transformed | Native comparison |
| --- | --- | --- | --- |
| `src/control/Darkel.cpp` | 23 | 1 / 1 | Changed function bytes observed |
| `vendor/librw/src/base.cpp` | 103 | 1 / 1 | Transformed function symbol unavailable; no retention claim |

Both native objects retain all three Mirage decoys each. The other functions
remain untransformed; the other 306 database entries were not processed. These
are **not** the 293-TU experiment from the earlier full-system validation report,
and that earlier experiment's runtime results are not counted as this task's work.

**Linking, game execution, game-level equivalence and final-game retention: not
run.** The existing environment lacks the platform prerequisites identified in
the full-system report, proprietary game assets were not obtained, and the
selected game object has unresolved game dependencies. No upstream game license
is supplied by this task. Only the generic integration and owned fixtures are
part of this deliverable; reVC-derived artifacts remain private under `/tmp`.

| Artifact | SHA-256 |
| --- | --- |
| Darkel O2 baseline object | `a987790056c48b26b1eabaa87af0d2a1270433f7321cf74806f4636728a26730` |
| Darkel O2 combined object | `ed89fe066f636ed3d6181d48b82fbfe15e205b7d5a4b32231dfc1dc0dca9ee8f` |
| librw base O2 baseline object | `41a1785e1c01b8543d875c6db2eb1f53115661bf9d6ca57c5c4a12de5a7ca2db` |
| librw base O2 combined object | `536767f38c8a1e6af3ecdac0c83d113fdabf6e96bc410e35fcec9256335155e7` |
| Component build report | `77df43133528a188e7f450b877caf7d2fdb2d1803d2b9332c0ae39c28234f5e8` |

Reproduction using the existing authorized local checkout/database:

```sh
.venv/bin/python - <<'PY'
import json, os
from pathlib import Path
os.umask(0o077)
manifest = {
  'schema_version': 1,
  'project_root': '/tmp/aegis-fsv/targets/revc',
  'compile_database': '/tmp/aegis-fsv/revc-build/compile_commands.json',
  'backend': 'llvm-shield-mirage', 'options': {'seed': '42', 'max-sites': 16},
  'optimization': '2',
  'units': [
    {'source': 'src/control/Darkel.cpp', 'selection': {'mode': 'integer-signatures'}},
    {'source': 'vendor/librw/src/base.cpp', 'selection': {'mode': 'integer-signatures'}}
  ]
}
with Path('/tmp/aegis-native-evidence/revc-components.json').open('x') as stream:
    json.dump(manifest, stream, indent=2)
PY
.venv/bin/python integrations/native_project/native_project.py build \
  /tmp/aegis-native-evidence/revc-components.json \
  --output /tmp/aegis-native-evidence/revc-components-o2 \
  --plugin /tmp/aegis-shield-build/AegisShield.so
```

## Tests and failures

| Final suite | Result | Log |
| --- | --- | --- |
| Module focused suite, including real native matrix/CLI/database | **67 passed**, 0 skipped, 0 warnings; 15.40 s | `/tmp/aegis-native-evidence/native-tests.log` |
| Complete Core/API/CLI/real-adapter regression | **675 passed**, 1 existing Starlette/httpx TestClient deprecation warning; 39.65 s | `/tmp/aegis-native-evidence/regression.log` |
| Existing Shield CTest build | **1/1 passed**; 1.30 s | terminal output from `/tmp/aegis-shield-build` |
| Existing ImageLab CTest build | **14/14 passed**; 3.91 s | `/tmp/aegis-native-evidence/imagelab-ctest.log` |

The two CTest runs use existing installed builds; neither was rebuilt for this
module. The native matrix itself freshly compiled its fixtures and used the
real production adapters. No existing test was deleted, skipped or weakened.

Exact final suite commands:

```sh
.venv/bin/python -m pytest integrations/native_project/tests -q \
  -p no:cacheprovider --native-plugin /tmp/aegis-shield-build/AegisShield.so \
  --basetemp /tmp/aegis-native-focused-final

.venv/bin/python -m pytest core/tests platform/api/tests platform/cli/tests \
  protectors/llvm/adapter/tests -q -p no:cacheprovider \
  --basetemp /tmp/aegis-native-regression \
  --shield-plugin /tmp/aegis-shield-build/AegisShield.so \
  --shield-opt /usr/bin/opt --shield-clang /usr/bin/clang \
  --shield-llvm-link /usr/bin/llvm-link

ctest --test-dir /tmp/aegis-shield-build --output-on-failure
ctest --test-dir /tmp/aegis-role-b-imagelab --output-on-failure
```

The regression command required an approved run outside the coding sandbox:
local socket/process-inspection containment fixtures fail under its isolation.
The initial sandboxed complete run showed failures and was interrupted (exit
130; no final pass/fail total). An isolated reproduction of
`test_full_validation_passes_and_its_report_enables_the_runtime` failed once in
55.26 s with `sandbox_start_failed` and an unexpected `vsock.sock` observation.
Those failures are not counted as passes; the approved unrestricted rerun above
passed all 675. No Core containment code/control was changed.

During development an initial unit-only run gave **47 passed / 2 failed**. The
fixture's `/proc` read raced with process exit; the file-cap fixture assumed a
large write must raise instead of possibly returning a partial write. The
fixtures now check process disappearance safely and attempt another write after
reaching the hard cap. Subsequent complete focused runs passed 65 and finally
67 tests. A first manual CLI invocation exposed argparse's `llvm-link` destination
normalization; it was fixed and the real CLI build/plan/verify path is tested.

Focused negative cases prove explicit failure for no transformed sites,
unsupported flags/selection, compiler syntax errors, missing sources/tools/plugin,
oversized source/output, modified object/binary hashes, unexpected execution
output and unsafe generated symlinks. Process-group tests check both hard timeout
and descendants surviving their leader. Artifact-inventory failure writes a
failed report and cannot pass `verify`. A partial failed build does not link or
register failed-unit protected objects.

**Not run:** expensive Ghidra/adversarial suites (Claude's scope), new live
NVIDIA calls from this task, model-generated candidate execution/scoring, reVC
game linking/running, unsupported platform/LTO/archive toolchains. The module
does not establish any attack resistance.

## NVIDIA coordination

Fresh owned O2 baseline, Shield and combined artifact/report paths were sent to
the independent evaluation and release owners. They include actual new adapter
output and native execution evidence, not historical revalidation. The evaluation
owner requested that duplicate fresh Ghidra/NVIDIA runs be held while its batch
is coordinated with Claude's baseline/Shield experiment.

Operator clarification: the designated credential runtime is the separate Fish
terminal at `/home/youss/Projects/aegis`; the key remains there. The operator
executes approved production Lab CLI requests and centrally tracks the **$20
total** budget and single-use approvals. No separate shared agent ledger is
assumed or created. This task's actual inference calls, token usage, reservations
and incremental estimated cost are **0 / 0 / 0 / $0**. Shared cumulative spend is
operator-managed and is not asserted here. No provider-bound reVC evidence was
prepared. Fresh model evidence remains a coordinated project evaluation; it is
not claimed as a completed native-module result.

## Remaining limits and release isolation

- Linux x86-64 ELF64 and a conservative clang flag subset only. No automatic
  arbitrary project linking, wrapper/compiler interception, shared/archive
  libraries, response files, PCH/modules, LTO, CUDA, assembly or cross-compilation.
- Selection sees canonical clang IR and integer signatures. It may miss eligible
  complex signatures; explicit unsupported choices fail. Existing source
  annotations are preserved and may select more than the newly added attributes.
- Successful build status means verified build/adapter operations, with separately
  recorded native retention and optional case-limited execution. It does not mean
  every reported IR expansion survives optimization.
- Per-command timeout/file/stream bounds are implemented; no whole-build deadline
  or aggregate disk/CPU/memory quota. This is a trusted local build tool, not a
  sandbox, candidate executor or protection against malicious compilers/plugins.
- Headers/dependencies/tool binaries are not completely inventoried or sealed.
  Source/plugin before/after checks do not defend against hostile concurrent
  writers or temporary replacement. Records are unsigned.
- No existing package, CI, public API, adapter protocol, Core storage layout,
  security gate or release file was changed. The module can be excluded wholesale
  without changing existing AEGIS entry points. No new dependency or license file.

## Complete changed-file inventory

All files below are new and belong exclusively to `integrations/native_project/`:

- `README.md`
- `RESULTS.md`
- `native_project.py`
- `workflow.py`
- `runner.py`
- `ir.py`
- `examples/owned/CMakeLists.txt`
- `examples/owned/project.json`
- `examples/owned/compute.h`
- `examples/owned/main.cpp`
- `examples/owned/kernels.cpp`
- `examples/owned/checksum.c`
- `examples/owned/policy.cpp`
- `tests/conftest.py`
- `tests/test_manifest_ir.py`
- `tests/test_runner.py`
- `tests/test_native.py`
