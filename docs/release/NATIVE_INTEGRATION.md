# Native protection integration and release gate — 30 October 2026 (UTC)

Historical native validation record. The current packaging, parser/dashboard
integration and release decision are in [FINAL_RELEASE_REPORT.md](FINAL_RELEASE_REPORT.md).

Owner: Agent 4. Scope: the `dev/integration` checkout at
`691ce2717934c22dd30883b5dd8a586ebf78bf20` plus **uncommitted** working-tree changes
from several agents. Nothing was committed, pushed or published.

Host: Intel Core Ultra 9 185H (22 logical CPUs), Linux 7.2.3-1-cachyos x86-64,
glibc 2.44, `.venv` CPython 3.14.7, Node 26.8.1, npm 12.0.2, LLVM/Clang/opt/llvm-link
22.1.8 (`/usr/bin`), CMake 4.4.3, Ninja 1.13.2. Playwright Chromium from the existing
`/tmp/aegis-product-browsers` download.

## 1. What was integrated

- `llvm-shield` (unchanged behaviour) and the new `llvm-shield-mirage` backend, both
  through `aegis.adapter.v1` with no contract, model or storage change. Contract:
  [NATIVE_BACKEND_CONTRACT.md](NATIVE_BACKEND_CONTRACT.md).
- The Shield adapter was refactored into reusable pieces (`run_shield`,
  `shield_evidence`, `plugin_path`, `argument_parser`, `respond`); its 94 existing
  tests pass unchanged.
- Mirage's `transform` gained `runner=` and `work_dir=` (defaults unchanged) so its
  LLVM tools run inside Core's process group under the combined adapter. A malformed
  target-triple line now raises `MirageError` instead of `AttributeError`.
- `scripts/product.py configure` registers a backend only after a real probe job;
  `smoke` exercises every registered backend and checks the Mirage chain against
  Core's hashes; `verify` passes the plugin and `llvm-link` to the native suites.

## 2. Fresh demo workspace

`/tmp/aegis-demo-20261030` (mode 0700; store 0700; config 0600), built from this
checkout with `product.py build` (0 compiler warnings) and `configure` (both probes
passed). No earlier CMake cache or workspace was reused. Served on 8400/5573
beside the operator's server on 8000/5173, which was not touched.

`product.py smoke --api-port 8400 --dashboard-port 5573`: both jobs succeeded.

| Backend | Output | SHA-256 |
| --- | --- | --- |
| `llvm-shield` | `protected.ll` | `4a7da8c1e1eae14ac9a4820c2f684a872123b38b332e816b9582143949d68a9a` |
| `llvm-shield` | `shield-report.json` | `135c529d9daea13b9927b7dc0f3b356657c586e9e869649fe5b5b02740b4764a` |
| `llvm-shield-mirage` | `protected.ll` | `0fc986a807ccd88cd7e1c6a6e504354b3bd5633f9d5515c20fac561460116b42` |
| `llvm-shield-mirage` | `shield-stage.ll` | `4a7da8c1…949d68a9a` (identical to `llvm-shield`) |
| `llvm-shield-mirage` | `shield-report.json` | `135c529d…b4764a` (identical) |
| `llvm-shield-mirage` | `mirage-report.json` | `8ea58753a0550c73336335c79ce4739988ec8e24d78f15a77af95866234fe8aa` |

The Shield digests equal those recorded in VALIDATION.md and INTEGRATION_AUDIT.md
(seed 42 is deterministic). The same digests were produced by a separate direct
Core run earlier the same day.

API checks through the proxy (backend `llvm-shield-mirage`): `mirage-count: 0` →
failed `INVALID_OPTIONS`; `enabled: false` → failed `NO_TRANSFORMATIONS_APPLIED`, no
outputs; `mirage-enabled: false` → succeeded, `protected.ll` = `shield-stage.ll`.

## 3. ImageLab with Shield + Mirage

```sh
W=/tmp/aegis-demo-20261030
AEGIS_CONFIG=$W/aegis.toml .venv/bin/python -m aegis_cli protect --json \
  --backend llvm-shield-mirage --option 'seed="42"' --option max-sites=64 \
  $W/imagelab-build/ir/kernels.input.ll
cp $W/store/jobs/<job>/outputs/protected.ll $W/kernels.shield-mirage.ll
cmake -S demo/image_processor -B $W/imagelab-mirage-build -G Ninja \
  -DCMAKE_CXX_COMPILER=/usr/bin/clang++ -DCMAKE_BUILD_TYPE=Release \
  -DIMAGELAB_SHIELD_PLUGIN=$W/shield-build/AegisShield.so \
  -DIMAGELAB_EXTERNAL_KERNELS_IR=$W/kernels.shield-mirage.ll
cmake --build $W/imagelab-mirage-build -j2
ctest --test-dir $W/imagelab-mirage-build --output-on-failure
llvm-nm --defined-only $W/imagelab-mirage-build/external/imagelab-cli
taskset -c 3 .venv/bin/python demo/image_processor/tools/compare_variants.py \
  --build $W/imagelab-mirage-build --rounds 4 --width 256 --height 256 \
  --samples 5 --warmup 1 --repeat 2 --seed 42 \
  --output $W/imagelab-shield-mirage-compare.json
```

- Core job `8c8afa9abf704db2a0fb93c5fbc922e1`: Shield 43 transformed sites; Mirage 3
  decoys; `protected.ll`
  `2f339866d3225fc1ff6e765ebd1eb78deb681f2fadfb6728917c9fc189e4079a`, `shield-stage.ll`
  `dd5d3c61b343bde072bdbc1810921e31fa61906d52520610e1e11c7a7d026b40`.
- CTest **14/14 passed** (the `external` variant is Shield + Mirage).
- All three decoy functions are defined in the final linked `external/imagelab-cli`
  (after `-O2`); none in the `shield` build.
- `compare_variants.py`: 150 cases per variant, **0 differ** from `ir-baseline`.

Performance observation (one run, 2026-10-30 04:08 UTC; 4 rounds × 5 samples = 20
per operation per variant; 256×256 synthetic image, seed 42; pinned to logical CPU
3 with `taskset`; governor `powersave`, turbo on; 1-minute load average 3.68, other
activity not controlled). Median ms per call:

| Variant | tone | color | enhance | kernel code bytes |
| --- | --- | --- | --- | --- |
| ir-baseline | 0.924 | 1.092 | 3.770 | 1335 |
| shield | 0.976 | 1.203 | 4.070 | 1482 |
| shield + mirage (`external`) | 0.983 | 1.210 | 4.143 | 1617 |

Kernel functions are the same size in `shield` and `external`; the 135 extra bytes
are the three decoys. The 1–2% timing differences between `shield` and `external`
are within what this setup cannot resolve; they are not a performance result.
Nothing here measures security. (The tool's own limitation text says "no CPU
pinning"; this run was pinned externally.)

## 4. Owned `signal.c` fixture (native tests)

`scripts/native_tests/test_shield_mirage_native.py` runs the real adapter through
Core, then builds baseline, Shield, Shield + Mirage and the Mirage-disabled control
with `clang -O2 -ffunction-sections -fdata-sections … -Wl,--gc-sections`, runs the
owned fixture (million-input digest) and inspects symbols: all four outputs are
identical; the three decoys are defined only in the Shield + Mirage executable,
which is larger than the Shield-only one. The same file repeats the ImageLab flow
above in a temporary build (CTest 100%, `enhance` output identical for native,
shield and external, decoys retained).

## 5. Release gate

### 5.1 Preliminary run (other agents still editing)

`PLAYWRIGHT_BROWSERS_PATH=/tmp/aegis-product-browsers .venv/bin/python scripts/product.py verify --workspace /tmp/aegis-demo-20261030 --api-port 8500 --dashboard-port 5673`
— **exit 0**, 04:11:24–04:13:55 UTC.

| Suite | Result |
| --- | --- |
| Python: Core, API, CLI, Provenance, Sentinel, both real adapters, product scripts | **752 passed**, 0 skipped, 1 warning (Starlette/httpx deprecation) |
| Shield CTest | **1/1** |
| ImageLab CTest (workspace build: native, ir-baseline, shield) | **12/12** |
| Mirage | **12 passed** |
| Native final-link tests | **3 passed** |
| Lab offline profile | **2010 passed, 22 skipped = NOT RUN** (real-Ghidra cases; `AEGIS_GHIDRA_HEADLESS` unset) |
| Frontend unit/contract tests | **12/12** |
| Dashboard production build | passed |
| Browser end-to-end (Chromium) | **18 passed** |

The browser runner printed Python `RuntimeWarning: Unexpected value in sys.prefix`
from the web server's relative `.venv` path; tests passed.

### 5.2 Final run (all agents finished; tree unchanged for 10 minutes beforehand)

Agent 1 reported its Core/API/CLI/Provenance/Sentinel edits finished; the dashboard
and Lab paths had no file changes for 10 minutes before the start. Working-tree
fingerprint, identical at start and after the last check: HEAD `691ce271…`,
`sha256(git diff HEAD)` = `7ec55bfb3a11cac10d3dfc9e5cc266b0752d860857c7d9fc739e9689d8198b97`.

Same `verify` command as 5.1 — **exit 0**, 04:33:12–04:35:38 UTC.

| Suite | Result |
| --- | --- |
| Python: Core, API, CLI, Provenance, Sentinel, both real adapters, product scripts | **752 passed**, 0 failed, 0 skipped, 1 warning (Starlette/httpx deprecation) |
| Shield CTest | **1/1 passed** |
| ImageLab CTest (workspace build: native, ir-baseline, shield) | **12/12 passed** |
| Mirage | **12 passed** |
| Native final-link tests (signal.c + ImageLab, Shield + Mirage) | **3 passed** |
| Lab offline profile | **2012 passed, 0 failed, 22 skipped = NOT RUN** in this profile (real-Ghidra cases) |
| Frontend unit/contract tests | **12/12 passed**, 0 skipped |
| Dashboard production build | passed |
| Browser end-to-end (Chromium) | **21 passed** |

Additional checks on the same tree:

| Check | Result |
| --- | --- |
| Strict Lab integration profile with real Ghidra 12.1.4 (`AEGIS_GHIDRA_HEADLESS=…/analyzeHeadless .venv/bin/python -m pytest attack_lab/tests --lab-profile integration -q`), 04:35:52–04:38:28 UTC | **2034 passed, 0 skipped** — the 22 offline NOT RUN cases ran here |
| Default suite `.venv/bin/pytest -q` | **596 passed**, 1 warning |
| `git diff --check` | clean |
| ImageLab Shield + Mirage build (§3) | CTest **14/14**, decoys retained, 150/150 cases identical |

After the gate, `product.py package` was found to drop untracked files outside
`scripts/`, `docs/release/` and `platform/dashboard/` — including the new adapter,
`aegis_provenance/jobs.py` and `aegis_lab/public_summary.py` — so an extracted
package could not run. Fixed: it now ships every untracked, non-ignored file, still
excludes `.env*`, `.venv`, `node_modules`, caches and similar, and **refuses**
key-like files (`*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa*`, `id_ed25519*`). New
regression test added. Re-run after the fix: adapter + product suites **157 passed**
(139 + 18); `git diff --check` clean. The rest of the gate was not re-run for this
packaging-only change.

Package (built after the fix, before this record's final edits): 312 inventoried
files, 0 hash mismatches after extraction; a secret-pattern scan found only test
strings (a fake key in the refusal test, assertion text in Provenance tests, a
presence-only placeholder in a Lab test). No `.env`, keys, store, `aegis.toml`,
virtualenv, `node_modules` or native plugin.

## 6. Supported targets

Supported and tested: Linux x86-64; textual LLVM 22 IR for the host target from C
(owned fixtures) and C++ (ImageLab); ELF executables. Untested: other Linux
distributions, other LLVM front ends. Not supported: macOS, Windows, bitcode or
native binaries as input, other LLVM majors, websites, mobile, consoles; the external
targets PhotoCraft, reVC and Mattermost are not started.

## 7. Limitations

- No established security property for Shield, Mirage or the combination. Decoys are
  uncalled and identifiable as unreachable; no attack, model or analyst was run
  against these outputs here.
- Retention was checked for two owned programs and one compiler/linker
  configuration only.
- At the time of this historical run, combined jobs were exercised over HTTP.
  The current browser suite additionally submits the real combined profile and
  tests signing, policies and tamper handling; see the final report for its latest run.
- Hosted CI was not run; the one-line CI change (plugin path for native tests) is
  syntax-checked only.
- The combined backend inherits `llvm-shield`'s limits: LLVM parsing runs on the
  host and is not a sandbox against LLVM bugs or malicious operator plugins.
- Mirage reads at most 64 MiB; a larger Shield output fails with `MIRAGE_FAILED`.
