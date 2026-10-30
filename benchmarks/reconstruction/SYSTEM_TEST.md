# Independent system validation — 30 October 2026

Validation ran at **10:11–10:16 AM Toronto**, using the current workspace. This
follow-up adds only this report; it changes no implementation or feature after
the 10:15 AM feature cutoff. No release blockers were found in these scoped
checks. Mattermost protection remains explicitly unsupported. Fresh real Ghidra
analysis completed, but no behavioral reconstruction or attack score is claimed.

Private scratch archive:

```text
/tmp/aegis-reconstruction-system-20261030-_3b8w66u
```

The original 16-file benchmark inventory remains unchanged. Tested implementation
and plugin hashes are recorded in `tested-source-hashes.json` in that archive.
The source snapshot was taken after the checks; it is an unsigned local snapshot,
not a sealed attestation against concurrent writers.

## Current-tree regression results

Commands from `/home/youss/Projects/aegis`:

```sh
env AEGIS_RECONSTRUCTION_PLUGIN=/tmp/aegis-shield-build/AegisShield.so \
  .venv/bin/python -B -m unittest discover -s benchmarks/reconstruction/tests -v \
  > /tmp/aegis-reconstruction-system-benchmark.log 2>&1

.venv/bin/python -B -m pytest integrations/native_project/tests -q \
  -p no:cacheprovider --native-plugin /tmp/aegis-shield-build/AegisShield.so \
  --basetemp /tmp/aegis-reconstruction-system-native-pytest \
  > /tmp/aegis-reconstruction-system-native.log 2>&1
```

| Suite | Passed | Failed/errors | Skipped | Warnings | Duration |
| --- | ---: | ---: | ---: | ---: | ---: |
| Reconstruction benchmark unittest | 78 | 0 | 0 | 0 | 1.763 s |
| Native project integration pytest | 67 | 0 | 0 | 0 | 14.77 s |

The native tests use the actual installed LLVM 22.1.8 tools and Shield plugin,
production adapters and trusted owned fixtures. The optional native tests were
enabled; these are not skipped-toolchain results. Existing synthetic parser/unit
fixtures remain unit tests only. The following Ghidra and Mattermost observations
were collected separately from real tools and real artifacts during this run.

## Fresh real Ghidra analysis

Exact driver command:

```sh
.venv/bin/python -B /tmp/aegis-reconstruction-real-ghidra-system.py
```

The retained driver copies only hash-bound files from the original owned benchmark
archive, creates a new comparison declaration and runs the actual
`aegis_lab.ghidra.analyze` worker serially on all three binaries. Each run uses a
new private Ghidra project/cache, lower process priority and a separate output
directory; Claude's ImageLab/color analysis and paid inference jobs are untouched.

Actual settings: Ghidra **12.1.4**, installed launcher
`/home/youss/Applications/ghidra_12.1.4_PUBLIC/support/analyzeHeadless`, actual
`AegisExportFunctions.java`, selector `*`, maximum 64 functions, maximum 20000 C
characters/function, 30 s decompiler timeout, 120 s analysis timeout, 300 s wall
timeout. Launcher, exporter, installation/configuration and binary hashes are
retained in the real reports and tool declaration. Neither binary code nor
decompiled C is executed by this analysis.

| Variant | Functions exported / decompiled | Failures | Selected targets | Worker duration |
| --- | --- | ---: | --- | ---: |
| Baseline | 28 / 28 | 0 | Both completed, neither truncated | 7.364 s |
| Shield | 28 / 28 | 0 | Both completed, neither truncated | 6.960 s |
| Shield+Mirage | 31 / 31 | 0 | Both completed, neither truncated | 6.710 s |

The selected targets are exactly `recon_gate` and `recon_mix` in every variant.
Both selected functions decompiled successfully in all three final binaries.
These observations show that this Ghidra configuration was not blocked on these
targets. They do **not** show a successful behavioral reconstruction.

Selected decompilation text lengths were respectively **212/183 UTF-8 bytes** for
baseline gate/mix, and **306/210 bytes** for both protected variants. Shield and
Shield+Mirage selected-function C hashes were identical to each other, while
differing from baseline. Text size/hash differences are structural observations;
they are not a decompiler-complexity resistance score. The additional combined
functions correspond to the retained decoy inventory; their presence alone does
not show that an analyst was misled.

All three actual reports were imported through `evidence.verify_record` and
rechecked by `benchmark.report_archive`, including on-disk artifact bytes, exact
target sets, declared tool/configuration and comparison identity. Classification
is **`structural_observation`** for every report. No synthetic report was used in
this analysis. An independent `llvm-nm --defined-only` check matched all six
selected-function entry points after Ghidra's recorded 0x100000 PIE image-base
offset; results are in `entry-point-crosscheck.json`.

Exact final artifact SHA-256:

| Variant | SHA-256 |
| --- | --- |
| Baseline | `39904cead0d859e79cb2f1207d566647b5f3842ad424143c5fcae50b6f51f00b` |
| Shield | `1607e36c12900af4e34ecc01a4a4ac4fd183a8aabbd12b102424789c8730b1c7` |
| Shield+Mirage | `b0e25b4d3793f87b00bde40d831450e93914c28f494686f593d7635417c22176` |

Fresh Ghidra comparison identity:
`3855fa501d402bb814693c2529a6420b28853c40ec5823bcd0ab25e13d25d8a1`.
Actual reports are `ghidra/{baseline,shield,shield_mirage}/ghidra-analysis.json`
under the scratch archive. Sidecars, import results, `combined-results.json` and
`SYSTEM_RESULTS.md` are retained there. Native oracle/timing measurements in this
combined archive remain the original measured benchmark data; the report states
that provenance explicitly. Only the Ghidra analysis is newly collected here.

## Mattermost baseline and unsupported protection paths

Authorized existing checkout:
`/tmp/aegis-fsv/targets/mattermost`, revision
`e8d166d8fcc6fdce43e7009dd1b1281bc288475e`. The working tree was clean before
and after the checks. Existing ignored `server/go.work` selects `.` and `./public`.
No third-party source, assembly or artifacts were sent to a provider.

Exact driver command:

```sh
.venv/bin/python -B /tmp/aegis-reconstruction-mattermost-system.py
```

Its actual Go commands, run from the checkout's `server/` directory, were:

```sh
/usr/bin/go version
/usr/bin/go build \
  -o /tmp/aegis-reconstruction-system-20261030-_3b8w66u/mattermost/mattermost-baseline \
  ./cmd/mattermost
/usr/bin/go test -count=1 -json ./public/shared/markdown/...
/usr/bin/go build -buildmode=archive -gcflags=-S \
  -o /tmp/aegis-reconstruction-system-20261030-_3b8w66u/mattermost/markdown.a \
  ./public/shared/markdown
```

The child environment was restricted to PATH, C locale, private HOME/TMPDIR and
these explicit Go settings:

```text
GOPATH=/tmp/aegis-fsv/gopath
GOMODCACHE=/tmp/aegis-fsv/gopath/mod
GOCACHE=/tmp/aegis-fsv/gocache
GOPROXY=off
GOSUMDB=off
GOTOOLCHAIN=local
GOFLAGS=-mod=readonly
```

This reused existing dependency/build caches as requested to avoid duplicating
large caches in the constrained `/tmp` filesystem. No dependency downloads or
package installation were permitted. The focused Go test used `-count=1`, so it
executed rather than returning a cached test result. The installed tool reported
`go version go1.27.1-X:nodwarf5 linux/amd64`.

| Check | Actual result | Scope |
| --- | --- | --- |
| Server baseline build | Exit 0, 4.469 s, 141095018-byte binary | Unprotected Go build; server not started |
| Markdown tests | Exit 0, 1.215 s; 556 named test/subtest pass events, 1 package pass, 0 failed/skipped | Upstream focused tests, not the entire server suite |
| Go package archive + assembly generation | Exit 0 | Current checkout, actual Go toolchain, existing caches |
| Native-project Go TU plan | `INCOMPATIBLE_UNIT` | Actual `markdown.go`, no compiler launched |
| Native-project TypeScript TU plan | `INCOMPATIBLE_UNIT` | Actual `webapp/platform/client/src/client4.ts` |

Server build and Go test stderr were empty; no warnings were emitted by those
commands. The archive command's stderr is the requested assembly listing, not an
empty diagnostic stream. Every command, exit, duration, log path and digest is
recorded in `mattermost/summary.json`.

The actual Go archive, actual Go assembly listing and actual TypeScript file were
then submitted as six **fresh Core protection jobs**, one of each input to each
production backend. Names ended `.ll` deliberately: rejection must depend on
content rather than trusting the filename. Both use the real installed plugin;
no fake adapter or preexisting job outcome was substituted.

| Actual input | `llvm-shield` | `llvm-shield-mirage` | Registered outputs |
| --- | --- | --- | ---: |
| Go package archive | `ADAPTER_FAILED` / `UNSUPPORTED_FORMAT` | Same | 0 for each job |
| Go assembly listing | `ADAPTER_FAILED` / `LLVM_FAILED` | Same | 0 for each job |
| TypeScript source | `ADAPTER_FAILED` / `LLVM_FAILED` | Same | 0 for each job |

All six jobs finished **failed**, as expected for unsupported inputs. The failed
jobs are not reported as successful protection or failed reconstruction attacks.
Their IDs, precise nested errors and input hashes are retained in the private
summary and `mattermost/store/jobs/` records. The two native-project planner
refusals are also retained, alongside the exact input manifests.

Actual input/artifact identities:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Unprotected Mattermost server | 141095018 | `354a973f5cdb57efc6dd33cdc9061f065ab72f7572b09a08ca50200a13a02999` |
| Go archive | 1437284 | `b22b1518e1053c4375fbb3ca885c95ae0c720f498908ba3817e7c7402cfcbaf1` |
| Go assembly listing | 4490050 | `e7ccebee7e26a7992a8309522192cfc73812ad32f9d02d2a6cd590dd13610cdb` |
| TypeScript source | 189749 | `498c633bc5f8810d010e3af8f5f94ebca02945fc0bc3ac75fba40ac500b23350` |

The tracked checkout contains 2619 `.go`, 2518 `.ts`, 2960 `.tsx`, and 567 `.js`
files, with zero `.c`, `.cc`, `.cpp`, `.cxx`, `.C`, `.s` or `.S` files. No C/C++
protection path is demonstrated for Mattermost. Its current Go/TypeScript build
needs a separate backend or independently implemented frontend integration;
changing an extension does not create LLVM IR support.

## Retained evidence and limits

| File under scratch archive | Exact SHA-256 |
| --- | --- |
| `ghidra-system-summary.json` | `ea4ebf3f55417a791a0d81f61dfc5bffae3cd6e6a9f3a7b18b6a456182e97374` |
| `mattermost/summary.json` | `f90f49daf40d8feb745d3463528c57a4f68e7407853f6810e28a8b76eff7b046` |
| `combined-results.json` | `aa412f00f95cc035fcce2c882ce52e20f5a003012b687b4d8f336417b153546b` |
| `entry-point-crosscheck.json` | `21d515b966ff735e9a4afa28bf6cba8222001416c8c6128f36709d175136c121` |
| `tested-source-hashes.json` | `ea5b7ac00df51f9c9a188c1e2fcddc77f67a7881bb9bd396fc59ba2fd9ba4d51` |

The retained drivers use new private scratch paths; do not rerun them against an
existing output directory or reuse another analyst's jobs. Hashes establish local
consistency, not authenticated origin or security. No license/credential state
was altered, and no commit, push or publication was performed by this task.

Not run: full Mattermost integration/UI/database suites or server startup (no
database/services introduced); REA or model reconstruction; candidate compilation
or execution; isolated behavioral scoring. No validated candidate isolation was
established by this task, so behavior scoring stays **unavailable**. Genuine live
NVIDIA requests remain Claude/operator-owned and are separate, hash-bound
experiments on different targets. This validation made **0 provider requests,
$0 inference spending, and $0 reservations**. No global shared-budget total is
inferred from this task's zero usage.
