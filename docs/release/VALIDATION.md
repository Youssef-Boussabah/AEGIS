# Product release validation — 29 October 2026

> Historical baseline. Current release results, inventory and blockers are in
> [FINAL_RELEASE_REPORT.md](FINAL_RELEASE_REPORT.md).

Branch: `feat/product-release`. Base HEAD:
`470f96a9a71a0c8de0d995b4b64a63257bfa97ee`.
Product changes remain **uncommitted**. The review archive’s file inventory binds
the actual working-tree source; HEAD alone does not reproduce those changes.
No Core/backend implementation, architecture file or project-status file was edited.

Host: Intel Core Ultra 9 185H, Linux 7.2.3-1-cachyos x86-64, Python 3.13.15,
Node 26.8.1, npm 12.0.2, LLVM/Clang 22.1.8, CMake 4.4.3, Ninja 1.13.2.
Dashboard: locked React 18, TypeScript 5, Vite 6.4.5 and Playwright 1.64.1.
Chromium was downloaded into `/tmp/aegis-product-browsers` after operator approval.
The source declares Node ≥22.18; the local run used Node 26.8.1. Hosted Node 22
checks are configured, not claimed as executed.

## Commands and outcomes

| Check | Command / evidence | Actual result |
| --- | --- | --- |
| Complete affected Python + adapter + product scripts | `.venv/bin/python -m pytest core/tests platform/api/tests platform/cli/tests protectors/llvm/adapter/tests provenance/tests sentinel/tests scripts/tests -q --shield-plugin /tmp/aegis-product/shield-build/AegisShield.so --shield-opt /usr/bin/opt --shield-clang /usr/bin/clang` | **242 passed**, 1 existing Starlette/httpx deprecation warning, 12.31 s; `/tmp/aegis-product-final-python.log` |
| Shield CTest | `ctest --test-dir /tmp/aegis-product/shield-build --output-on-failure` | **1/1 passed**, no warnings |
| ImageLab CTest, including Shield variant | `ctest --test-dir /tmp/aegis-product/imagelab-build --output-on-failure` | **12/12 passed**, no warnings |
| Original Mirage suite | `.venv/bin/python -m pytest protectors/mirage/tests -q` | **11 passed**, no warnings |
| Explicit-tool Mirage retention/control smoke | `.venv/bin/python -m pytest scripts/native_tests -q` | **1 passed**, no warnings |
| Lab explicit offline profile | `.venv/bin/python -m pytest attack_lab/tests --lab-profile offline -q` | **1670 passed, 24 skipped / NOT RUN**, 51.94 s; two modules need unmerged Core execution contracts, 22 Ghidra cases had no configured `AEGIS_GHIDRA_HEADLESS` in this suite run |
| Frontend contract/privacy checks | `npm --prefix platform/dashboard test` | **5 passed**, zero skips; malformed private JSON errors do not echo input |
| Production build | `npm --prefix platform/dashboard run build` | TypeScript and Vite passed; JS 171.82 kB / gzip 55.91 kB; no bundle-size warning |
| Real API + browser workflow | `PLAYWRIGHT_BROWSERS_PATH=/tmp/aegis-product-browsers npm --prefix platform/dashboard run test:e2e` | **7 passed**, 8.1 s; real upload/report/download/reload/digests, invalid IR failure, unknown job/outage, private import rejection, mobile navigation, HTTP smoke and actual ImageLab local import |
| Combined documented verification | `PLAYWRIGHT_BROWSERS_PATH=/tmp/aegis-product-browsers .venv/bin/python scripts/product.py verify` | Exit 0; `/tmp/aegis-product-verify.log`. That earlier combined run had 241 Python tests before the additional package-inventory test. Final focused Python run above includes the added test; final browser run includes the quick-restart fix |
| Actual local evidence imports | Temporary `/tmp/aegis-product-local-import.mjs`, Chromium | **3 actual summaries loaded**: first retained Role B evidence, then fresh reconstruction/Mirage reproduction plus actual ImageLab comparison; **zero POST requests**; scripted generation remained behaviorally unscored |
| ImageLab example CLI | `shield/imagelab-cli enhance demo/image_processor/tests/fixtures/gradient_17x9.pam /tmp/aegis-product/enhanced.pam`, followed by `info` | Exit 0, 17×9 output, fingerprint `9b72915f4e84b500`; not a protection measurement |
| Workflow syntax | Ruby standard-library YAML parser on `.github/workflows/ci.yml` | Parsed five jobs; no hosted Actions run claimed |
| Diff hygiene | `git diff --check` | Passed |

The browser runner emitted the harmless inherited `NO_COLOR`/`FORCE_COLOR`
warning. Chromium installation reported this host OS as unsupported and used its
Ubuntu 24.04 fallback build; browser execution passed. npm initially warned about
the removed legacy Recharts dependency; it is absent from the final lockfile.
The current lock installation reported zero audit vulnerabilities and an npm 12
notice that esbuild’s postinstall was blocked by install-scripts policy; the
available platform binary built successfully. No global package was installed.

Initial sandbox attempts could not bind loopback; one Core/API test run stalled
at that environment boundary and was terminated. An initial Lab offline run had
one extra Unix-socket skip (1669 passed / 25 NOT RUN). The final authorized runs
above exercised the socket case. An initial browser run passed its assertions but
needed orphan cleanup because default runner SIGKILL bypassed service teardown;
the final configuration uses graceful SIGTERM, and clean shutdown plus immediate
restart was verified. Recently closed sockets initially caused a false occupied-
port preflight failure; SO_REUSEADDR fixed that without accepting active listeners.
No such attempt is substituted for the final successful checks.

## Real Shield evidence

The checked-in authorized `protectors/llvm/tests/fixtures/annotated.c` was compiled
with `clang -O1 -S -emit-llvm`. `product.py configure` registered the actual existing
adapter with absolute Python/script/opt/plugin argv; attack-lab stayed disabled.

A representative successful HTTP/proxy job was
`06ffc4c8b29f48d88eec265ffcf2b59d`, with a Core terminal report and one adapter-claimed
transformed site. Browser tests independently reloaded both output files and
matched Core’s SHA-256 values:

- `protected.ll`: `4a7da8c1e1eae14ac9a4820c2f684a872123b38b332e816b9582143949d68a9a`
- `shield-report.json`: `135c529d9daea13b9927b7dc0f3b356657c586e9e869649fe5b5b02740b4764a`

This proves the local job path and output binding were exercised. It is not
attack-resistance or native-equivalence evidence. Invalid IR was submitted to the
same real adapter and correctly remained failed with no registered output.
Screenshots stay local at `/tmp/aegis-product-browser-report.png` and
`/tmp/aegis-product-browser-evidence.png`.

## Explicitly not run / not established

- Strict Core+Lab integration: **not run**, matching Core execution modules are
  absent from the merged checkout. No owner worktree or snapshot was imported.
- The offline Lab suite’s 22 real-Ghidra cases: **not run in that suite invocation**;
  Ghidra was not configured there. The separate owned demonstration reproduction
  below uses actual installed Ghidra. Neither substitutes for strict integration.
- Actual generated-candidate execution, VM containment, live provider calls,
  NVIDIA GPU inference and third-party REA execution: **not run**. No live-
  inference or attack-resistance result is claimed.
- Public GitHub Actions, deployment, publication, Devpost submission and recording
  a video: **not performed**. The video deliverable is a script/shot sequence.
- License adoption: **pending owner review**. The proposal is not an operative license.
- ARCHITECTURE.md and docs/PROJECT_STATUS.md reconciliation: left to Agent 1 under
  the explicit concurrent-work scope restriction.

## Fresh merged Lab / Mirage demonstration

The runbook's optional owned demonstration was also reproduced from **this merged
checkout**, without importing the unmerged Core snapshot:

```sh
PYTHONPATH=attack_lab/src:protectors/mirage/src .venv/bin/python attack_lab/scripts/role_b_demo.py \
  --output-dir /tmp/aegis-product/lab-demo \
  --ghidra-headless /home/youss/Applications/ghidra_12.1.4_PUBLIC/support/analyzeHeadless \
  --shield-plugin /tmp/aegis-product/shield-build/AegisShield.so \
  --authorized-owned-fixture
```

Exit **0**; log `/tmp/aegis-product-lab-demo.log`. The checked-in owned `signal.c`
fixture was processed through real LLVM and Ghidra 12.1.4. All **4/4 controlled
experiment archives** independently passed `verify_experiment`. Their provider
is `FakeOffline`, all candidates remain behaviorally unscored and no generated
candidate was compiled or executed. Their public summaries were hash-checked and
loaded in Chromium alongside ImageLab with zero POSTs. Private raw evidence stays
under `/tmp/aegis-product/lab-demo`; none is included in the release package.
No new numerical benchmark results are committed by this product task.

## Review package

`product.py package` creates `/tmp/aegis-product/aegis-local-review.tar.gz` with
source, the built dashboard and `RELEASE-MANIFEST.json`. Native outputs, runtime
stores, virtualenv/node_modules and private research evidence are excluded.
The archive’s checksum and independent inventory check are recorded separately
under `/tmp/aegis-product/release-verification.json`, avoiding a checksum that
recursively includes itself. This is a local testable review artifact, not a
published or license-finalized release.

## Changed file inventory

Every changed file in this product task:

- `.github/workflows/ci.yml`
- `README.md`
- `docs/release/AGENT1-CONTRACT.md`
- `docs/release/CI-INTEGRATION.md`
- `docs/release/DEMO-SCRIPT.md`
- `docs/release/LICENSE-MIT-DRAFT.md`
- `docs/release/RUNBOOK.md`
- `docs/release/SUBMISSION.md`
- `docs/release/VALIDATION.md`
- `platform/dashboard/.gitignore`
- `platform/dashboard/FRONTEND_HANDOFF.md`
- `platform/dashboard/README.md`
- `platform/dashboard/index.html`
- `platform/dashboard/package.json`
- `platform/dashboard/package-lock.json`
- `platform/dashboard/playwright.config.ts`
- `platform/dashboard/src/App.tsx`
- `platform/dashboard/src/contracts.ts`
- `platform/dashboard/src/style.css`
- `platform/dashboard/vite.config.ts`
- `platform/dashboard/tests/browser/product.spec.ts`
- `platform/dashboard/tests/contracts.test.ts`
- `scripts/export-product-evidence.py`
- `scripts/native_tests/test_mirage_product.py`
- `scripts/product.py`
- `scripts/tests/test_product.py`
