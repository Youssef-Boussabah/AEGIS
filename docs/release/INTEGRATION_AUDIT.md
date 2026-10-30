# AEGIS integration and QA audit — 30 October 2026 (UTC)

> Historical audit of an earlier snapshot. Its missing-output-download and signing
> gaps are resolved by [FINAL_API_CONTRACT.md](FINAL_API_CONTRACT.md). Current
> package inventory, tests and blockers are in [FINAL_RELEASE_REPORT.md](FINAL_RELEASE_REPORT.md).

Scope: the merged `dev/integration` checkout at
`691ce2717934c22dd30883b5dd8a586ebf78bf20`, plus the **uncommitted** local fixes
listed in §I. Nothing was committed, pushed, merged, deployed or published.

Host (observed): Intel Core Ultra 9 185H, Linux 7.2.3-1-cachyos x86-64,
`.venv` CPython **3.14.7** (VALIDATION.md's 3.13.15 describes an earlier
environment), Node 26.8.1, npm 12.0.2, LLVM/Clang/opt/llvm-link **22.1.8** from
`/usr/bin`, CMake 4.4.3, Ninja 1.13.2, OpenJDK 21.0.12, Ghidra 12.1.4 at
`/home/youss/Applications/ghidra_12.1.4_PUBLIC/support/analyzeHeadless`,
Playwright Chromium in `/tmp/aegis-product-browsers` (existing download).

All audit artifacts (fresh builds, job store, logs, screenshots, package) are in
a private scratch workspace, referred to below as `$W`:
`/tmp/claude-1000/-home-youss-Projects-aegis/ee6c5ffa-a6ae-48ea-8a79-a9489726c9bc/scratchpad/ws`
(logs in the sibling `logs/`, screenshots in `shots/`). The operator's running
demo (`product.py serve --workspace /tmp/aegis-product` on 8000/5173) was never
stopped or reconfigured; all audit servers used ports 8100/5273, 8200/5373 and
8300/5473.

## A. Executive verdict: **demo-ready for the supported scope; partially ready overall**

The supported product path works end to end with the real backend and was
verified in a browser: React dashboard → Vite proxy → FastAPI → Core → real LLVM
Shield adapter (`opt` + `AegisShield.so`) → orchestrator-hashed artifacts →
terminal report, download and reload by ID. Every automated suite passes
(§E), including the strict Lab integration profile with real Ghidra (0 skips).
Eight issues were found and fixed (§D); none was a contract or security-boundary
change.

It is **not** a complete product beyond that scope, and the demo narrative must
say so:

- **Shield shows no established protection.** On the owned `signal.c` fixture the
  final optimized Shield binary is **byte-identical** to the baseline (reproduced
  today). On ImageLab, the Shield binary does differ (43 transformed sites, 752
  changed disassembly lines) and matched the baseline on 150/150 sampled cases.
  Neither result is attack-resistance evidence.
- **Live NVIDIA/Nebius inference has never run.** The transport is offline-tested
  and approval-gated. No credentials were available or used.
- **Behavioral reconstruction scoring is blocked by design:** Core's candidate
  execution runtime refuses every request (no isolation runtime).
- Mirage, Provenance and Sentinel are working **standalone CLIs**, not wired
  into Core jobs or the dashboard (beyond exported summary imports for Mirage).

## B. Per-component status

| Component | Status | Evidence (this audit) |
| --- | --- | --- |
| Core / API / CLI | **Working** | Python suites pass; API edge cases (§E.3) return the documented error codes; CLI `inspect`/`protect`/`report` produced the same SHA-256 outputs as the API path |
| LLVM Shield plugin + adapter | **Working** (prototype, no security property) | Shield CTest 1/1; real adapter suite; jobs succeed with 1 transformed site; invalid/unannotated IR fail explicitly (`LLVM_FAILED`, `NO_TRANSFORMATIONS_APPLIED`) |
| React dashboard | **Fixed → working** | Degraded-health bug fixed (§D1); 8/8 Playwright tests; real token flow; desktop + mobile screenshots |
| Product launcher (`scripts/product.py`) | **Fixed → working** | §D2–D7; 14 product-script tests |
| ImageLab (owned) | **Working** | CTest 12/12; native, IR-baseline and Shield CLIs produce byte-identical `enhance` output; quick comparison 150/150 cases match per variant |
| Mirage | **Working (standalone)** | 11/11 tests; native retention smoke 1/1; CLI inserted 3 decoys; Role B run retained 3 decoys after final link |
| Adversarial Lab + Ghidra | **Working (offline scripted)** | Offline profile 1964 passed / 22 NOT RUN; integration profile with real Ghidra **1986 passed / 0 skipped**; Role B owned-fixture reproduction exit 0; 4/4 archives re-verified by the exporter |
| Lab behavioral scoring via Core | **Blocked by design** | `UnavailableRuntime` refuses every request; not exercised |
| Nebius / NVIDIA live inference | **Untested (not authorized)** | Offline tests only; no network request, credentials or approval used |
| Provenance (Ed25519) | **Working (standalone)** | Sign/verify of a real Shield output: valid → 0; untrusted key, tampered artifact, missing artifact → 1 |
| Sentinel | **Working (standalone)** | create/validate/evaluate on a real Shield output; tampered artifact denied |
| Review package | **Working** | 278 files; no `.env`, keys, store, venv, node_modules, plugin or Lab evidence; secret-pattern scan clean |
| Operator demo workspace `/tmp/aegis-product` | **Stale (operator action)** | Built from deleted `aegis-product-release`; its CTest fails 0/1 and 5/12 because test scripts no longer exist; directory is mode 755 |
| PhotoCraft, reVC, Mattermost | **Unsupported / not started** | Planned external targets only (issue #7) |

## C. Actual integration map

```
 Browser (React dashboard, dist/)                       [C]
   │  same-origin /healthz, /v1/jobs   (Vite preview proxy → AEGIS_API_PORT)
   ▼
 aegis_api (FastAPI) ──┐    aegis_cli (`aegis`) ──┐         [A]
                       └──────────► aegis_core ◄──┘
                                    │ orchestrator, store (SHA-256), reports
                                    │ aegis.adapter.v1 subprocess (argv, no shell,
                                    ▼ timeout, minimal env)
                       protectors/llvm/adapter → opt + AegisShield.so   [A]

 demo/image_processor (CMake) ── uses AegisShield.so at build time        [A]
     └─ compare_variants.py ─► export-product-evidence.py ─► JSON ─┐
 protectors/mirage CLI ─► report.json ─► export-product-evidence.py ┼─► browser import
 attack_lab (Ghidra, scripted provider) ─► experiment.json ─► exporter ┘ (SHA-256 typed
     │                                       (verify_experiment)          by operator;
     └─ imports aegis_core.lab_execution / lab_ledger / lab_authorization  never uploaded)
        (candidate execution: runtime refuses; no Core job, no API endpoint)
 provenance CLI, sentinel CLI: standalone; no imports of Core; not called by jobs  [D]
```

Connected through Core/UI: Core/API/CLI, Shield adapter, dashboard.
Connected only by offline file export + manual hash import: ImageLab, Mirage, Lab.
Not connected: Provenance, Sentinel, Nebius live path, Lab scoring execution.
Gaps (by design, not bugs): no job-list or artifact-download API, no automatic job
signing, Mirage is not a registered backend, no Lab endpoint in the API.

## D. Bugs found and repairs

| # | Problem (observed) | Root cause | Repair | Files | Regression tests |
| --- | --- | --- | --- | --- | --- |
| D1 | With a degraded backend the dashboard said **“API unavailable”**, showed only “HTTP 503” and hid Core's problem list (reproduced in Chromium against the pre-fix bundle) | API returns HTTP 503 **with a valid health report** when degraded; the UI's generic `api()` threw on any non-2xx | New `fetchHealth`/`parseHealth` accept 200/ok and 503/degraded with a strictly validated, self-consistent body; UI shows **API degraded** and lists problems; status dot is green only for ok | `platform/dashboard/src/contracts.ts`, `src/App.tsx` | contract test (consistency/invalid bodies); Playwright degraded test; live check with store made read-only, then recovery |
| D2 | Browser suite and `verify` could not run while a demo server held 8000/5173; occupied port gave `error: [Errno 98] Address already in use` without naming the port | Ports hardcoded in `product.py`, `vite.config.ts`, `playwright.config.ts`, `smoke` | `--api-port/--dashboard-port` (or `AEGIS_API_PORT`/`AEGIS_DASHBOARD_PORT`), defaults unchanged, ports validated 1024–65535 and distinct; Vite proxy and Playwright follow; clear occupied-port message | `scripts/product.py`, `platform/dashboard/vite.config.ts`, `playwright.config.ts` | port validation; occupied-port test; full e2e run on 8100/5273 beside the live demo |
| D3 | `serve` with a degraded API waited 15 s then said only “did not become healthy”; `smoke` printed “HTTP Error 503” | Health 503 treated as a connection failure | `read_health` reads 503 degraded bodies; `serve`/`smoke` fail immediately with Core's problem list | `scripts/product.py` | real API subprocess with a missing adapter fails fast (< 14 s) with the problem text; `read_health` unit test |
| D4 | `serve` printed the dashboard URL before Vite listened (observed connection refused on first browser access) | No readiness wait for the preview | Waits until the preview **proxies** API health, else fails within 15 s | `scripts/product.py` | observed log ordering; e2e |
| D5 | A workspace built/configured from a deleted checkout gave confusing failures (`can't open file …/aegis-product-release/…` in CTest) and its config could pass health while referencing a missing adapter script | Health checks only `command[0]`; nothing compared build caches with the checkout | `build`/`verify` refuse CMake caches from another checkout; `serve`/`verify` refuse configs with missing absolute paths — all with a “use a new --workspace” message | `scripts/product.py` | stale cache/config tests; `verify --workspace /tmp/aegis-product` now stops with that message |
| D6 | Private job inputs/reports were world-readable: `/tmp/aegis-product`, `store/`, `store/jobs/` all mode 755 although the runbook says keep it private | `configure`'s 0700 `mkdir` was a no-op because `build` (CMake) created the directory first; Core uses the umask | New workspaces and the store root are created 0700; existing open workspaces get a warning, never an automatic chmod. Core storage modes unchanged (shared-contract change needs owner approval) | `scripts/product.py` | workspace mode/warning test; configure store 0700 / config 0600 / lab disabled test |
| D7 | `verify` could run the browser suite against a stale `dist/` | No rebuild before e2e | `verify` runs `npm run build` before `test:e2e` | `scripts/product.py` | full gate run |
| D8 | ARCHITECTURE.md listed Mirage and dashboard as “planned” and said Lab makes no model calls | Documentation drift | Rows corrected to observed state, with limits | `ARCHITECTURE.md` | n/a (docs) |

Environment issue (not a code bug): `.venv` lacked `aegis-mirage`, so Mirage tests
and the native smoke failed to import. Resolved by running the README's documented
install into the repository-local `.venv` only (`uv pip install --offline … -e
'./attack_lab[dev]' -e ./protectors/mirage`); no network, system or user packages.

Observed, not changed (owner decision or by design):

- Provenance README lists exit 2 for “missing file”, but a missing **artifact** is a
  verification failure (exit 1, `ARTIFACT_NOT_FOUND`); missing manifest/key exit 2.
  Fails closed either way; README wording belongs to workstream D.
- Sentinel `create` allows `execute` unless `--deny-execute` is passed (explicit
  flag exists; cooperating policy only).
- Core health checks only the adapter executable, not plugin usability (documented).
- Report text “1 transformed sites” (grammar; asserted by an existing test).

## E. Test commands and results (all run on 30 October 2026, this host)

### E.1 Automated suites

| Suite | Command | Result |
| --- | --- | --- |
| Complete Python + real adapter + product scripts (before fixes) | `.venv/bin/python -m pytest core/tests platform/api/tests platform/cli/tests provenance/tests sentinel/tests protectors/llvm/adapter/tests scripts/tests -q --shield-plugin $W/shield-build/AegisShield.so --shield-opt /usr/bin/opt --shield-clang /usr/bin/clang` (first run used `/tmp/aegis-product/shield-build/AegisShield.so`) | **636 passed**, 0 skipped, 1 Starlette/httpx deprecation warning |
| Default suite | `.venv/bin/pytest -q` | **535 passed**, 1 warning |
| Product scripts (after fixes) | `.venv/bin/python -m pytest scripts/tests -q` | **14 passed** (7 existing + 7 new) |
| Shield CTest (fresh build) | `ctest --test-dir $W/shield-build --output-on-failure` | **1/1 passed** |
| ImageLab CTest (fresh build) | `ctest --test-dir $W/imagelab-build --output-on-failure` | **12/12 passed** |
| Stale operator builds | same commands on `/tmp/aegis-product/{shield,imagelab}-build` | 0/1 and 5/12: scripts in deleted checkout missing (environment; see D5) |
| Mirage | `.venv/bin/python -m pytest protectors/mirage/tests -q` | **11 passed** (after the documented install) |
| Native Mirage retention smoke | `.venv/bin/python -m pytest scripts/native_tests -q` | **1 passed** |
| Lab offline | `.venv/bin/python -m pytest attack_lab/tests --lab-profile offline -q` | **1964 passed, 22 skipped = NOT RUN** (real-Ghidra cases without `AEGIS_GHIDRA_HEADLESS`) |
| Lab strict integration, real Ghidra | `AEGIS_GHIDRA_HEADLESS=…/analyzeHeadless .venv/bin/python -m pytest attack_lab/tests --lab-profile integration -q` | **1986 passed, 0 skipped**, 215 s |
| Frontend contracts | `npm --prefix platform/dashboard test` | **6/6 passed** (5 existing + 1 new) |
| Typecheck + production build | `npm --prefix platform/dashboard run build` | passed; JS 172.69 kB (gzip 56.08 kB) |
| Browser end-to-end | `PLAYWRIGHT_BROWSERS_PATH=/tmp/aegis-product-browsers AEGIS_PRODUCT_WORKSPACE=$W AEGIS_API_PORT=8100 AEGIS_DASHBOARD_PORT=5273 npm --prefix platform/dashboard run test:e2e` | **8/8 passed** (7 existing + 1 new), 11.2 s |
| Full release gate | `PLAYWRIGHT_BROWSERS_PATH=/tmp/aegis-product-browsers .venv/bin/python scripts/product.py verify --workspace $W --api-port 8100 --dashboard-port 5273` | **exit 0** (03:30–03:32 UTC): Python **643 passed** (636 + 7 new), 1 warning; Shield 1/1; ImageLab 12/12; Mirage 11; native smoke 1; Lab offline 1964 passed / 22 NOT RUN; frontend 6/6; build OK; browser **8/8** |
| Diff hygiene | `git diff --check` | passed |

### E.2 Product and workstream commands

- `product.py build` / `configure --workspace $W`: exit 0; zero compiler warnings.
- `product.py package --workspace $W`: exit 0, archive SHA-256
  `be00682232ddd8c4604c3c721de436c21777d1187fbd07b472d2f4bb2b7b3b20` (278 files; built
  before the final doc edits, so it does not contain this report).
- ImageLab: `$W/imagelab-build/{native,shield}/imagelab-cli enhance demo/image_processor/tests/fixtures/gradient_17x9.pam …`
  → identical bytes, 17×9, fingerprint `9b72915f4e84b500`.
  `compare_variants.py --quick`: `ok=true`, 150 cases per variant, 0 differences.
  Quick medians (2 samples, 64×48, one round, unpinned; smoke only, not a
  performance result): tone 49.7/53.1/69.7 µs, color 52.8/55.2/104.3 µs, enhance
  80.9/173.7/216.9 µs for native/IR-baseline/Shield.
- Mirage: `clang -O1 -S -emit-llvm protectors/mirage/tests/fixtures/signal.c`,
  `python -m aegis_mirage … --seed 42` → `inserted=3`, output
  `e6ef8a14…40176`; export hash-checked.
- Role B: `attack_lab/scripts/role_b_demo.py --output-dir $W/lab-demo --ghidra-headless … --shield-plugin $W/shield-build/AegisShield.so --authorized-owned-fixture`
  → exit 0, `retained_decoys: 3`, size overhead 176 bytes,
  `behavioral_scoring: pending_authorized_core_runtime`. Baseline and Shield
  ELF SHA-256 both `c592942a07310794…`; Mirage ELF differs. Candidates are
  FakeOffline scripted text, never compiled or run.
- Reconstruction exports of all 4 experiments: exit 0 (each re-runs
  `verify_experiment`); summaries show `execution_performed=false`,
  `attack_effectiveness=not_established`.
- Provenance/Sentinel on a real `protected.ll` (`4a7da8c1…68a9a`): results in §B.

### E.3 API and browser evidence (real backend)

Through the dashboard proxy (audit instance 8200/5373):
unknown backend → 400 `UNSUPPORTED_BACKEND`; `attack_lab` task → 400
`UNSUPPORTED_TASK`; bad base64 → 422; malformed JSON / extra field / bad job ID
→ 422 `INVALID_REQUEST`; unknown job → 404 `JOB_NOT_FOUND`; empty input →
failed `EMPTY_ARTIFACT`; integer seed / unknown option → failed `INVALID_OPTIONS`;
unannotated IR or `max-sites 0` → failed `NO_TRANSFORMATIONS_APPLIED`; invalid
IR → failed `LLVM_FAILED`; `../../etc/passwd.ll` stored as `inputs/passwd.ll`;
valid fixture → succeeded, outputs `protected.ll`
`4a7da8c1e1eae14ac9a4820c2f684a872123b38b332e816b9582143949d68a9a` and
`shield-report.json` `135c529d9daea13b9927b7dc0f3b356657c586e9e869649fe5b5b02740b4764a`
(identical to VALIDATION.md's recorded digests: deterministic for seed 42).

Chromium walkthrough (1440×900): overview → upload → `running` → `succeeded`,
“1 transformed sites · LLVM 22.1.8”, only one POST (`/v1/jobs`); store made
unwritable → header **API degraded** + “artifact store is not writable”;
restored → **API ok**. Bearer-token instance: no token → `UNAUTHORIZED`; token in
Capabilities → job succeeded; token absent from local/session storage, cookies,
URL, DOM and JS bundle; lost on reload (memory only, as documented); absent from
server logs and job store.

## F. Verified launch and walkthrough

From the repository root (fresh workspace recommended; see H1):

```sh
uv pip install --python .venv/bin/python -c core/requirements-dev.lock \
  -e './attack_lab[dev]' -e ./protectors/mirage      # if not yet installed
.venv/bin/python scripts/product.py build     --workspace /tmp/aegis-demo
.venv/bin/python scripts/product.py configure --workspace /tmp/aegis-demo
.venv/bin/python scripts/product.py serve     --workspace /tmp/aegis-demo
```

Open `http://127.0.0.1:5173` → **Protect LLVM IR** → choose
`/tmp/aegis-demo/annotated.ll` → **Submit** → watch running → succeeded → report
(input/output SHA-256, “1 transformed sites”, evidence-source badges,
limitations) → **Download report** → copy job ID → reload → **Protection jobs** →
paste → **Load job**. For the failure demo, upload a file `invalid.ll` with
invalid text → failed, `ADAPTER_FAILED`, “No output artifacts registered.”
In a second terminal: `product.py smoke --workspace /tmp/aegis-demo`.
Research evidence: run the exporter commands in RUNBOOK.md, then paste the printed
SHA-256 in **Research evidence**. The build → configure → serve sequence above
was run with `$W` and ports 8200/5373 (the default ports were in use by the
operator's server).

## G. Security and credential review

- No `NEBIUS_API_KEY` or other credential was read, printed or used; the variable
  was absent. Only test placeholders exist in source (`git grep` scan clean for
  key/token patterns). Live inference requires an approval JSON plus
  `--approve-live-inference`; preflight makes no network request.
- Attack-lab gates unchanged: product config keeps `[attack_lab] enabled = false`;
  the API rejects `attack_lab` for the Shield backend.
- Adapter request files contain options and paths only (no tokens, no
  authorization); adapters get a minimal environment (Core, unchanged).
- Browser bundle: no secrets, local paths, Nebius strings or tokens. Research
  imports never POST (asserted in e2e and in the walkthrough).
- Review package: no `.env`, keys, runtime store, Lab evidence, virtualenv,
  node_modules or native plugin; the git-ignored root `aegis.toml` (local paths) is
  excluded. Tracked validation docs do contain local absolute paths (records).
- Data at rest: fixed for new workspaces (D6). **Existing `/tmp/aegis-product` is
  still 755**; it contains private job inputs/reports and Lab evidence.
- No candidate was compiled or executed; no Firecracker VM was booted; no
  third-party target was touched; no paid request was made.

## H. Remaining blockers and next steps (ranked for the hackathon)

1. **Refresh the operator demo workspace** (5 min, operator): `/tmp/aegis-product`
   was built from the deleted checkout. After stopping the current `serve`, either
   `chmod 700 /tmp/aegis-product` and keep using it for `serve` only, or (better)
   run build/configure/serve with a new `--workspace` so CTest/`verify` work.
   The running server keeps serving the rebuilt (fixed) `dist/`.
2. **Demo narrative accuracy** (team): lead with the traceable pipeline and honest
   evidence, not protection. Show ImageLab's changed binary *and* the `signal.c`
   identical-binary result; do not claim resistance.
3. **Live Nebius/NVIDIA inference** (operator decision, ≤ $0.10 per target per
   attack_lab/docs/live-inference.md): needs a reviewed approval and a credential in
   the operator's own shell. Until run, describe it as “offline-tested transport”.
4. **Commit these fixes** via a reviewed PR from a task branch (not done here).
5. Hosted CI has not been observed running the e2e job; Node 22 path untested here
   (Node 26 locally).
6. Optional integrations not present (do not imply them): automatic signing of job
   outputs with Provenance, Sentinel policy per job, Mirage as a Core backend, a
   Lab API endpoint, behavioral scoring (needs a validated isolation runtime).
7. External targets (PhotoCraft, reVC, Mattermost): not started; ImageLab is the
   only validated application target.

## I. Modified files (uncommitted, `git diff --numstat`)

| File | + / − | Change |
| --- | --- | --- |
| `scripts/product.py` | 118 / 15 | ports, degraded-health handling, readiness wait, stale build/config checks, private workspace, rebuild before e2e |
| `scripts/tests/test_product.py` | 124 / 0 | 7 regression tests |
| `platform/dashboard/src/contracts.ts` | 21 / 0 | `parseHealth`, `fetchHealth` |
| `platform/dashboard/src/App.tsx` | 4 / 6 | degraded health display |
| `platform/dashboard/tests/contracts.test.ts` | 9 / 1 | health contract test |
| `platform/dashboard/tests/browser/product.spec.ts` | 12 / 0 | degraded-health browser test |
| `platform/dashboard/vite.config.ts` | 7 / 2 | proxy port from `AEGIS_API_PORT` |
| `platform/dashboard/playwright.config.ts` | 8 / 3 | ports from env |
| `platform/dashboard/README.md` | 4 / 2 | ports, degraded health |
| `docs/release/RUNBOOK.md` | 14 / 1 | ports, new launcher checks, failure guide |
| `README.md` | 3 / 2 | `verify` beside a running server |
| `ARCHITECTURE.md` | 5 / 5 | stale component rows |
| `docs/release/INTEGRATION_AUDIT.md` | new | this report |

Also changed outside Git: `.venv` gained `aegis-mirage` (editable) and re-linked
`aegis-lab`; `platform/dashboard/dist/` was rebuilt (git-ignored; the operator's
running preview now serves the fixed bundle). Nothing in `/tmp/aegis-product` was
modified.

## J. Facts, assumptions and historical claims

- **Observed today:** every result in §B, §D and §E, the screenshots, and the
  digests above.
- **Assumed:** the operator's plugin in `/tmp/aegis-product` was built from the
  same source as HEAD (the release branch is merged as HEAD); it was not rebuilt
  or compared byte-for-byte.
- **Historical, not re-verified:** hosted CI runs, Node 22 behavior, Role B
  hardware/sample figures in `attack_lab/docs/role-b-delivery.md`, VALIDATION.md's
  earlier counts (e.g. 242 Python / 1670 Lab tests, Python 3.13.15).
- **Not established by anything here:** attack resistance, live model behavior,
  candidate behavioral equivalence, or performance beyond the quick smoke.

## Addendum — 30 October 2026, 04:08 UTC: concurrent changes after this audit

After §A–§J were recorded, other agent sessions changed this same working tree
(no separate worktrees). Among them: Agent 4 added a registered
`llvm-shield-mirage` backend (`docs/release/NATIVE_BACKEND_CONTRACT.md`); others
changed Core config, orchestrator and storage, the API, CLI, Lab, Provenance,
Sentinel, the adapter and the dashboard. `git status` now lists 38 modified and
21 untracked paths. §I lists only this audit's own edits; it no longer describes
the whole diff.

Observed at 04:08 UTC (snapshot, not re-audited):

- This audit's fixes are still present in `scripts/product.py`, `contracts.ts`,
  `App.tsx`, `vite.config.ts` and `playwright.config.ts`.
- Complete Python + real adapter + product scripts: **714 passed**, 1 warning.
  Frontend contracts: **12/12**.
- **Not re-run** on the new tree: CTest, Mirage/native, Lab, production build,
  browser e2e, `verify`, the `llvm-shield-mirage` backend, and the new
  provenance/research/attestation code. Their results in §E describe the earlier
  tree only.
- The dashboard still shows "Shield + Mirage · integration contract pending" as
  a disabled option (dashboard workstream).

Re-run `product.py verify` (on free ports) after the concurrent work settles,
before relying on §A for the combined tree.
