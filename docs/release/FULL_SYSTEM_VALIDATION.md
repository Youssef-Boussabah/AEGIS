# AEGIS full-system validation, repair and external-target testing — 30 October 2026

Independent engineering report for the operator. Checkout `dev/integration` at HEAD
`691ce2717934c22dd30883b5dd8a586ebf78bf20` **plus the uncommitted working tree**
(103 modified/untracked files from earlier workstreams, plus the files listed in §K).
Work ran 06:52–07:55 Toronto (10:52–11:55 UTC). Host: Linux 7.2.3-1-cachyos x86-64,
Intel Core Ultra 9 185H (22 logical CPUs), Python 3.14.7, LLVM/Clang/opt/llvm-link
22.1.8, CMake 4.4.3, Ninja 1.13.2, Node 26.8.1, npm 12.0.2, Ghidra 12.1.4 + OpenJDK
21.0.12, rustc 1.98.1 (LLVM 22.1.8), Go 1.27.1. No commit, push, reset, stash,
publication, package installation, live inference or credit spending was performed.
All scratch output lives under `/tmp/aegis-fsv` (mode 0700).

## A. Executive verdict

**For its documented supported scope — textual LLVM 22 IR on Linux x86-64 — AEGIS is
operational end to end.** Import → Shield → Mirage → Ed25519 signing → verification →
Sentinel → research-evidence import → results was exercised through the real Core,
CLI, HTTP API and dashboard in real Chromium, with real adapters and no mocked
success. The strict release gate passed before and after my changes (§F).

New in this pass: AEGIS processed **code from two of the three selected external
projects**, at **component level only**:

| Target | Verdict |
| --- | --- |
| PhotoCraft (Rust) | **Partial (component).** Two real crates (`photocraft-color`, `photocraft-algo`) protected through real Core jobs via a manual pre-optimization IR pipeline; the crates' own unit tests give identical results after relinking. Shield+Mirage works for `color` after a Mirage fix; `algo` (287 MB IR) exceeds Mirage's 64 MiB limit. Not the application. |
| reVC (C++) | **Partial (component).** 293 of 308 translation units compile to LLVM 22 IR; all 293 went through real Shield jobs (20 transformed). 13 self-contained transformed functions proved equivalent by differential testing. Game not linked (needs GLFW, not installed) and not run (needs proprietary assets, not obtained). No upstream license. |
| Mattermost (Go/TS) | **Unsupported.** No LLVM IR stage exists in its Go or TypeScript toolchains; zero C/C++/assembly. Server baseline built; AEGIS rejects its artifacts with explicit errors. |

What remains incomplete: no whole-application protection for any external target;
Rust requires an operator marking step; no crash recovery for in-flight jobs;
the three-way NVIDIA comparison is not run (needs operator approval); **no
reverse-engineering resistance has been established for anything** — the static
observations in §C show decoys are trivially identifiable as unreachable and
symbols remain readable. License adoption and publication remain operator actions.

## B. Component-by-component results

| Component | Result | Evidence (this pass) |
| --- | --- | --- |
| Core | Works. Jobs, state transitions (`pending → running → succeeded/failed`), orchestrator-side SHA-256, persistence across restart, timeouts with process-group kill, explicit error codes. **Gap:** a job in flight when the API process dies stays `running` forever (§J-1). | API walkthrough 66/66; timeout job `23a85d6f…` `ADAPTER_TIMEOUT` after 2 s, no surviving `opt`; restart check; crash job `1c7a4f2f…` |
| Shield | Works on C, C++ and Rust IR. Deterministic (identical `shield-stage.ll` across jobs). Only explicitly marked integer-signature functions with flag-free adds change; coverage on real code is small (§C). | 293 reVC/librw jobs; PhotoCraft color/algo jobs; 15.4 s on a 287 MB module |
| Mirage | Works through `llvm-shield-mirage`; chain binding verified from Core records; decoys retained after O2/O3 and `--gc-sections`. **Fixed:** rustc triples were refused (§E-1); oversized input mislabeled (§E-3). Fixed 64 MiB limit remains. | color, reVC Darkel and fixture combined jobs; `mirage-enabled=false` control output equals `shield-stage.ll` |
| Signature / Provenance | Works. Every output of every successful signed job verified; offline `aegis-provenance verify` passes with the trusted key and fails with `ARTIFACT_TAMPERED`, `SIGNATURE_INVALID` (manifest edit), `UNTRUSTED_KEY`; missing `--trusted-key` is a usage error. Manifest binds job ID and output SHA-256. | API walkthrough checks `offline_verify_*`, `manifest_binds_job_id_and_sha` |
| Sentinel | Works as **cooperating** metadata. `execute/modify/attack_evaluate` denied, `analyze/redistribute` permitted; unknown action/field → 422; tampered policy → `permitted:false` and download 403; caller restriction enforced (`aegis-cli` permitted, other/none denied); expiry bound in the policy (`expires_at`, unit-tested). Caller IDs are asserted, not authenticated (`caller_id_verified:false`). Outside tools are not bound. | §G, `/tmp/aegis-fsv/ws-caller` |
| API | Works. 401 without/with wrong token; `/healthz` open; downloads re-hash before streaming (409 on store tampering); input names reduced to one safe path component (`../../escape.ll` → `jobs/<id>/inputs/escape.ll`). | 66/66 |
| CLI | Works for protect/verify/evaluate/report/inspect; explicit exit codes (`INPUT_TOO_LARGE` exit 2, failed job exit 1). | all external-target jobs were CLI or Core-API driven |
| `product.py serve` | **Fixed:** SIGHUP (closing the terminal) orphaned the token-gated API and dashboard (§E-2). | regression test, live repro |
| Frontend | Works in real Chromium: upload, both profiles, polling, verification, Sentinel, downloads (hash-checked), invalid input shown as failed with code, NVIDIA summary import (digest-checked, wrong digest refused, zero POSTs), desktop 1440×1000 and mobile 390×844, token never in storage or page text, no console errors. | own walkthrough 19/19; repository Playwright suite 22/22 |
| Lab | Strict real-Ghidra suite passes with zero skips. Attack-lab gates untouched and disabled in all my configs. | §F |
| NVIDIA / Nebius | Archive intact; public summary reproduced byte-for-byte offline; parser policy verified; continuation drafts re-prepared offline, unapproved. | §D |

## C. Real-world software tests

Selected targets come from GitHub issue #7 (exact URLs below). Sources were cloned
to `/tmp/aegis-fsv/targets` (outside the repository); only trusted project test code
and owned harnesses were executed. No target code was disclosed to any AI provider.
The operator-side tools I wrote are in `/tmp/aegis-fsv/tools` and are **not part of
AEGIS**: `mark_eligible.py` adds the `"aegis.protect"` IR function attribute to every
definition whose return and parameter types are all scalar integers (selection by
signature only, never by name — the equivalent of a C author's `annotate`),
`emit_ir.py`, `relink.py`, `batch_shield.py`, `diff_harness.py`.

### C1. PhotoCraft — **partial, component level**

| Item | Value |
| --- | --- |
| Repository | https://github.com/storytold/photocraft, `main` @ `28be431b4ad3ddc7080d46f3eacc399f3e44fa5b` (2026-10-30) |
| License | MIT OR Apache-2.0 (workspace `Cargo.toml`, `LICENSE-MIT`, `LICENSE-APACHE`) |
| Language / build | Rust 2024 edition, Cargo workspace, 2,049 `.rs` files (~753k lines), release profile ThinLTO + 1 codegen unit. Built with isolated `CARGO_HOME=/tmp/aegis-fsv/cargo-home` |
| Baseline (original cargo release build) | `photocraft-color` unit tests **30/30 pass**; `photocraft-algo` **725 pass, 2 fail, 27 ignored** — both failures are upstream NaN bit-pattern assertions in `pixelate::tests`, before any AEGIS step |
| Scope protected | Whole **crate** code units of `photocraft-color` (1.6k lines) and `photocraft-algo` (66k lines), including their `#[cfg(test)]` code; dependencies and std were not protected. Not the application. |

**Compatibility findings.**
1. rustc 1.98.1 emits LLVM 22.1.8 IR that upstream `opt` 22.1.8 parses and verifies.
2. **Post-optimization IR has zero eligible functions**: at `opt-level=3` every
   integer-only helper is inlined (color: 92 definitions, 0 eligible). The working
   integration point is rustc's **pre-optimization** module (`-C save-temps`
   `*.no-opt.bc` → `llvm-dis`), protected before LLVM's O3 pipeline runs (`clang -O3`).
3. Rust has no source annotation; selection needs the operator marking step above.
4. Matched pipeline (issue #7): (a) original cargo build; (b) matched unprotected:
   same rustc invocation with `-C lto=off -C save-temps --print link-args`, IR →
   `clang -O3 -fPIC` → relink with rustc's own linker command; (c) protected: (b) plus
   an AEGIS job between IR and `clang`.
5. Mirage refused Rust IR (`target_triple_mismatch`: `x86_64-unknown-linux-gnu` vs Clang
   `x86_64-pc-linux-gnu`). Fixed (§E-1).
6. `algo` pre-opt IR is 287 MB: Core and adapter defaults (64 MiB) reject it with
   `INPUT_TOO_LARGE` (verified); an operator config raising both limits worked for
   Shield; Mirage has a fixed 64 MiB limit and fails (`input_too_large` after §E-3).

| Crate | Pre-opt definitions | Marked (integer signature) | Shield result | PhotoCraft-authored functions changed |
| --- | --- | --- | --- | --- |
| color | 866 | 23 | job `4d248f0c…`: **1 function, 2 sites** | **none** — the only changed function is `<u8 as core::iter::Step>::forward` (std generic instantiated in the crate) |
| algo | 72,781 | 313 | job `473174f7…`: **13 functions, 26 sites**, 15.4 s | 6 functions / 11 sites: `artistic_fx::kuwahara_reach`, `redeye::halo_radius`, `pyramid::auto_levels`, `pyramid::stack_levels`, `camera_raw::local_tone::depth`, one `sharpen` closure (rest: core `int_sqrt`, `Step::forward`, rustfft, strength_reduce) |

| Runtime equivalence (crate's own test binary, relinked) | color | algo |
| --- | --- | --- |
| Matched unprotected | 30 pass | 726 pass / 1 fail / 27 ignored |
| Shield | 30 pass | **726 / 1 / 27, identical failing test** |
| Shield + Mirage | 30 pass | not possible (Mirage 64 MiB limit) |

The one remaining `algo` failure is the same upstream NaN-bit test in both; the
original ThinLTO build fails one more of those NaN tests, i.e. they are
codegen-sensitive upstream tests, not an AEGIS effect.

| Artifact | SHA-256 |
| --- | --- |
| color pre-opt IR / marked input | `316ee2d8…0abb2dbf` / `702e9f843fd1aecce17691534e99c7d5629700dbbbc22df823d1c22014704939` |
| color Shield `protected.ll` (= combined `shield-stage.ll`) | `6c5d85f608aee207689da60cab9862f1e17fa109a3825b550846db8e4479ae7d` |
| color Shield+Mirage `protected.ll` (job `efbc1541…`) | `f7ce5de61246c471bbb32db202edfb77272e092f8828bca535c3a11a18087793` |
| algo marked input / Shield `protected.ll` | `b74dd1124ce50be38e272bf2788b4256efee0776110eeec144db0a94b939ef56` / `33979c606d4b25667c6f77ebec378c37661f2d2779d214a92993929a1ce3a631` |
| color test binaries unprot / Shield / S+M | `0d652724…` / `71a2274e…` / `da84cd98…` |
| algo test binaries unprot / Shield | `cbf6e6a1…` / `8dcb76dd…` |

Size/performance (this host, tests' own wall time, 5 resp. 3 runs, noisy): color
`.text` 846,088 → 846,120 (Shield, +32 B) → 846,264 B (S+M, +176 B), run 539–603 vs
532–571 vs 534–640 ms; algo `.text` 8,597,427 → 8,597,747 B (+320 B), run 13.9–14.4 s vs
13.9–14.8 s. No overhead distinguishable from noise; not extrapolable.
Retention: all three Mirage decoys are present in the final linked color test binary
after O3 and `--gc-sections`. Signatures: the color jobs were signed and verified,
including through the API walkthrough (§G).

Static analysis observations (permitted, own builds only): 8,094 of 15,895 defined
symbols in the algo binary still carry readable `photocraft_algo` paths (rustc v0
mangling); Shield changed sizes of a few dozen symbols; each decoy has **zero code
references** (`llvm-objdump`), so call-graph analysis identifies them as unreachable.
None of this is evidence of reverse-engineering resistance.

Remaining blockers: whole-application builds need a cargo/rustc wrapper that runs the
marking + AEGIS job per crate inside the build (not implemented); Mirage 64 MiB cap;
no PhotoCraft-authored function in `color` is eligible.

### C2. reVC — **partial, component level; licensing caution**

| Item | Value |
| --- | --- |
| Repository | https://github.com/Jai-JAP/re-GTA, branch `reVC` @ `1b9a5897fdb319c318581a5f9535d2d9661ad578` (2021-12-29), archived; vendored `librw` @ `5501c4fdc7425ff926be59369a13593bb6c81b54` (MIT) |
| License | **None.** README: "We don't feel like we're in a position to give this code a license … only be used for educational, documentation and modding purposes." It mirrors the DMCA-affected re3 project. I limited use to local, non-distributed educational evaluation; no derived artifact belongs in the repository, package or any publication. |
| Language / build | C++ (245 game `.cpp`, ~278k lines incl. headers) + librw; CMake/Ninja, Clang 22.1.8, `-DLIBRW_PLATFORM=GL3 -DLIBRW_GL3_GFXLIB=SDL2` |
| Baseline build | **Partial: 295/310 build steps compile; 15 TUs fail** because reVC's Linux platform layer (`skel/`, `Pad.cpp`, `Frontend.cpp`, …) hard-requires GLFW (not installed; installing needs operator approval). `LIBRW_PLATFORM=NULL` is rejected by the game's `fakerw`. The game cannot run without proprietary Vice City assets, which were not obtained. |
| Scope | Every compilable game TU and every librw TU as separate modules; runtime checks only for self-contained functions |

Whole-program IR coverage (`clang -O1 -Xclang -disable-llvm-passes` with each TU's
real flags, then one real Core `llvm-shield` job per module, signed):

| Part | Modules | Definitions | Marked | Jobs succeeded | Sites / functions | Other jobs |
| --- | --- | --- | --- | --- | --- | --- |
| reVC game | 231 (of 246 TUs) | 11,134 | 615 | 8 | 12 / 10 | 223 `NO_TRANSFORMATIONS_APPLIED` |
| librw | 62 (of 62) | 1,798 | 59 | 12 | 38 / 19 | 50 `NO_TRANSFORMATIONS_APPLIED` |

Coverage is small because the game mostly uses signed `int` (adds carry `nsw` and are
skipped by design) and floats. Game functions changed include `CDarkel::CalcFade`,
`CPopulation::ChooseNextCivilianOccupation`, `CRadar::GetNewUniqueBlipIndex`,
`CTheScripts::GetNewUniqueScriptSphereIndex`, `CPickups::GetNewUniquePickupIndex`,
`CCarCtrl::ChoosePoliceCarModel`, `CSceneEdit::SelectWeapon`.

**Differential equivalence** (owned harness: `llvm-extract` each changed function from
the unprotected and protected module; only functions with no external calls or
globals run; 26 edge values in all 3-argument combinations plus 200,000 seeded random
inputs; traps guarded and compared): **13 of 29 changed functions executed, 13
equivalent, 0 mismatches** — `CDarkel::CalcFade`, `rw::d3d/xbox::calculateTextureSize`,
`rw::ps2::swizzle`, `rw::xbox::makeVertexFmt`, `rw::libraryIDUnpackVersion`,
4 × `MatPipeline::getVertCount` (divide-by-zero inputs trap identically in both),
lodepng `ilog2`, `lodepng_get_raw_size_idat` (×2 modules), `reverseBits` (inputs
bounded to 0..255 because its loop count is an argument). The other 16 read game
globals or call other functions and were **not executed**. An early harness run
reported a `getVertCount` mismatch; root cause was my harness passing different 4th
arguments to the two versions — fixed and documented here, not a Shield defect
(2,000,000 additional random non-zero-divisor inputs matched a C reference).

Shield + Mirage on `Darkel.cpp` (job `358bd983…`, and again via API and UI): chain
verified (`shield-stage.ll` `3392bff6…` → `protected.ll` `23cbe5a93094c7e1f11f43efb0e014c345b5ec62ae74280e9263377a3aa0e376`;
input `ffb4bd3d874a1a3978fbb442799d31c1955c61f08ce7eddf21253b463d542e5a`); all 3 decoys
present in the `-O2 -ffunction-sections` object; `.text` 3,887 → 3,901 (Shield) →
4,036 B (S+M). Final-executable retention not checked (game not linkable here).
Remaining blockers: GLFW (operator install approval), legal assets for any run, no
license, and an IR-substitution step in the game's CMake build (not implemented).

### C3. Mattermost — **unsupported**

| Item | Value |
| --- | --- |
| Repository | https://github.com/mattermost/mattermost, `master` @ `e8d166d8fcc6fdce43e7009dd1b1281bc288475e` (2026-10-30) |
| License | Source under AGPL-3.0 (or commercial) per `LICENSE.txt`; enterprise directories separately licensed (`LICENSE.enterprise`) |
| Languages | 2,619 Go files, 2,518 `.ts`, 2,960 `.tsx`, 567 `.js`; **0** C/C++/assembly; no `import "C"` in its source |
| Baseline | `go build ./cmd/mattermost` with a `go.work` (as `make setup-go-work` creates) **succeeded** (141 MB binary, 25 s, isolated `GOPATH/GOCACHE`); focused `go test ./public/shared/markdown/...` passes. cgo in the dependency graph: only stdlib `runtime/cgo`, `net`, `os/user` |
| AEGIS | Go's `gc` compiler and the TypeScript/webpack toolchain have no LLVM IR stage. Real artifacts submitted to the real API fail explicitly with no outputs: Go package archive → `UNSUPPORTED_FORMAT`; Go assembly listing → `LLVM_FAILED`; TypeScript source → `LLVM_FAILED` |

No genuinely supported component exists. gollvm or TinyGo would be a new, untested
front end (different LLVM versions; Mattermost's reflection-heavy packages are
unlikely to build under TinyGo) — not attempted, per the brief. Blocker: a Go backend
and a JavaScript bundle backend would each need independent implementation.

## D. NVIDIA / Nebius results

| Check | Result |
| --- | --- |
| Archive integrity | All 11 files of `/tmp/aegis-operator-review-i2Si6nvI/baseline-8192-live-run` match `/tmp/aegis-nebius-compat-original-hashes.json`; no extra files; unchanged after my exports |
| Public summary | Independent offline re-export (`scripts/export-product-evidence.py reconstruction … --post-hoc-report …`) is **byte-identical** to `/tmp/aegis-nvidia-baseline-public-summary.json`, SHA-256 `16be4b7bf0bfdbbe36389aca550fa703fe7f35c5e5dc3f4161b87d87e41292b6` |
| Model identity | requested = reported `nvidia/Nemotron-3_5-Lightning` (`matched`); reported identity hash and weight fingerprint absent — not independently attested |
| Usage / cost | 1,786 prompt + 8,039 completion = 9,825 reported tokens; estimated $0.002037 at archived prices ($0.06/M in, $0.24/M out); reservation $0.064881; invoice unknown |
| Original outcome | `invalid_output`, parser v1, null candidate — unchanged |
| Post-hoc | v2 review `candidate_text_revalidated_but_behaviorally_unscored`, candidate envelope valid, candidate SHA-256 `ff05b293…fd443`, report `a5fa0aae…da63b` binds the historical experiment `b6267283…126a` |
| Parser probe (synthetic, offline) | v1 flags `reasoning`/`reasoning_content` as unsupported; v2 accepts both only as null or valid text; wrong type, NUL and malformed JSON → `malformed_response`; unknown fields → `unsupported_fields`; tool calls/refusals flagged; unknown parser version refused |
| Dashboard import | Real Chromium, desktop and mobile: imported, wrong digest refused, 0 POSTs |
| Usefulness of the candidate | **Unknown.** It was never compiled or executed (no validated isolation environment, no execution authorization); only its text envelope is valid. No behavioral equivalence or reconstruction success is claimed. |
| Comparability | Baseline/Shield/Mirage share model, 8,192-token cap, temperature 0, one request, limits. Baseline was observed first (not randomized). **Shield and Mirage prompts are identical** (same selected function, decoys not disclosed), so a Mirage-specific effect cannot be measured with this design. |

**Pending live runs (authorization boundary — not executed).** The continuation drafts
from 02:10 Toronto expired at 03:10 Toronto. I re-prepared them offline (0 network
requests) in `/tmp/aegis-fsv/nvidia/remaining-fresh/` (`shield/`, `mirage/`, each
`manifest.json`, `approval.DRAFT.json`, request review); they expire at 08:34 Toronto,
so regenerate right before use with:
`PYTHONPATH=attack_lab/src .venv/bin/python -m aegis_lab.remaining_inference --output-dir <new dir> /tmp/aegis-operator-review-i2Si6nvI/baseline-8192-live-run /tmp/aegis-live-imagelab-ready/plan.json`.
Each request: Nebius Token Factory, model `nvidia/Nemotron-3_5-Lightning`, 1 request,
`max_tokens` 8,192, temperature 0, `store:false`, discloses one Ghidra-exported
function of the **AEGIS-owned ImageLab** binary (no third-party code), price ceiling
$10 per target (`max_spend_microusd` 10,000,000), worst-case reservation $0.064881,
expected cost ≈ $0.002 at the baseline's usage. Provider retention terms must be
reviewed by the operator (the approval file records that review). The operator must
fill and sign off the approval, then run `operator-commands.json`'s preflight and run
argv privately, once per target, without retries. No key was read or printed.

## E. Discovered bugs and fixes

| # | Bug | Root cause | Fix | Regression tests | Re-verified |
| --- | --- | --- | --- | --- | --- |
| 1 | Shield+Mirage refused all rustc IR (`MIRAGE_FAILED: target_triple_mismatch`) | Mirage compared the module triple to Clang's default byte-for-byte; rustc spells the same target `x86_64-unknown-linux-gnu` | `protectors/mirage/src/aegis_mirage/transform.py`: if two four-part triples differ **only in vendor**, compile decoys with `--target=<module triple>` and recheck exact equality; every other difference still fails | `protectors/mirage/tests/test_transform.py`: vendor-only success (fails on the unfixed code — verified), 5 other mismatches still fail, 8-case `same_target_except_vendor` table; `protectors/llvm/adapter/tests/test_shield_mirage_adapter.py::test_vendor_only_triple_difference_succeeds_with_module_triple` (through Core with the real plugin) | PhotoCraft color combined job + tests 30/30 + decoys retained |
| 2 | Closing the terminal (SIGHUP) left the token-gated API and dashboard running orphaned on their ports | `scripts/product.py serve` trapped only SIGINT/SIGTERM; its children run in their own sessions and never receive the hangup | trap SIGHUP with the same cleanup | `scripts/tests/test_product.py::test_serve_stops_its_api_and_dashboard_on_hangup_and_termination[SIGHUP/SIGTERM/SIGINT]` (real processes; SIGHUP case failed before the fix) | live repro now cleans up |
| 3 | Oversized module reported by Mirage as `invalid_regular_input` (operator raised adapter limits; Mirage silently keeps 64 MiB) | one condition covered both "not a regular file" and "too large" | separate `input_too_large`; document Mirage's fixed limit | `test_oversized_input_is_reported_as_too_large_not_irregular` (failed before) | algo combined job now `input_too_large` |

Not fixed (reported, §J): stale `running` jobs after an API crash; Mirage's fixed 64 MiB
limit. Test-harness bugs found in my own tools (UI case-sensitivity, wrong expected
initial state name, harness argument duplication) were corrected in the tools, not in
AEGIS.

## F. Automated testing results

Command (both runs): `AEGIS_GHIDRA_HEADLESS=/home/youss/Applications/ghidra_12.1.4_PUBLIC/support/analyzeHeadless PLAYWRIGHT_BROWSERS_PATH=/tmp/aegis-product-browsers .venv/bin/python scripts/product.py verify --workspace /tmp/aegis-fsv/baseline-ws --lab-profile integration --api-port <p> --dashboard-port <q>`
(after `product.py build` + `configure`, both probes passed).

| Suite | Baseline (untouched tree, 06:54–06:59) | Final (my changes) |
| --- | --- | --- |
| Core/API/CLI/Provenance/Sentinel/both real adapters/product scripts | 790 passed, 1 warning (Starlette/httpx deprecation) | **794 passed** (790 + 3 new `serve` signal tests + 1 new adapter triple test), same 1 warning |
| Shield CTest | 1/1 | 1/1 |
| ImageLab CTest | 12/12 | 12/12 |
| Mirage | 12 passed | **27 passed** (12 + 15 new) |
| Native final-link retention | 3 passed | 3 passed |
| Lab strict real-Ghidra (`--lab-profile integration`, skips refused) | 2105 passed (187 s) | 2105 passed (164 s), 0 skipped |
| Frontend contracts (`npm test`) | 14 passed, 0 skipped | 14 passed, 0 skipped |
| TypeScript/Vite production build | passed | passed |
| Playwright (real Chromium) | 22 passed | 22 passed |
| Gate exit | 0 | **0** (07:40–07:44); `git diff --check` clean |

Additional runs: own API walkthrough **66/66** (`/tmp/aegis-fsv/api-e2e-final/api-e2e.json`);
own UI walkthrough **19/19** (`/tmp/aegis-fsv/ui/ui-results.json`); PhotoCraft relinked
tests (§C1); reVC differential 13/13 (`/tmp/aegis-fsv/revc-diff.json`); NVIDIA re-export and
parser probe (§D); package/fresh install (§I). Logs: `/tmp/aegis-fsv/baseline-gate.log`,
`/tmp/aegis-fsv/final-gate.log`. Hosted CI and other platforms/versions: **NOT RUN**.

## G. Working demo walkthrough

Private workspace `/tmp/aegis-fsv/ws` (0700): fresh build, both probes passed, demo-only
Ed25519 identity `identity/demo-private.pem` (0600, never printed), public key ID
`547bbd6809626bfc42a4818b6f7babb2a6027bebd14482d74eecf660d13be762`, Sentinel
`cooperating_enforced` allowing `analyze`, `redistribute`. Server (left running):
dashboard **http://127.0.0.1:7093**, API **http://127.0.0.1:9920**, started with
`setsid /tmp/aegis-fsv/tools/start_ws.sh` (token from `identity/api-token` via environment
only). In the UI: Capabilities → paste the token → Protection jobs → load a job ID.
Stop it with `pkill -TERM -f 'product.py serve --workspace /tmp/aegis-fsv/ws '` (or Ctrl-C /
closing its terminal now that SIGHUP is handled).

| Job | ID | Outputs (all signature-verified) |
| --- | --- | --- |
| PhotoCraft color, Shield (API) | `2f2083df53304450aa669be730c7e220` | 2 |
| PhotoCraft color, Shield+Mirage (API) | `9e7443dd959d48f5aa3593dec51d7e83` | 4 |
| reVC Darkel.cpp, Shield+Mirage (API) | `a7e14faea51340eea701e297ed31c4eb` | 4; `protected.ll` `23cbe5a9…0e376` |
| Owned fixture, Shield (API) | `7998f64d4afe4470a0cac243f09df620` | 2 |
| reVC Darkel.cpp, Shield+Mirage (dashboard upload) | `893fa6c688a040e5902e33d176f30ea0` | 4 |
| PhotoCraft color, Shield (dashboard upload) | `3efa2d6255984fb592b5fcda67230952` | 2 |
| Invalid IR (dashboard) | `7d2cd61805214769b8fb79717c84dbb9` | failed, `LLVM_FAILED`, no outputs |

Screenshots: `/tmp/aegis-fsv/ui/desktop-0{1..6}-*.png`, `/tmp/aegis-fsv/ui/mobile-0{1,6}-*.png`.
The store also contains the deliberately tampered job from the walkthrough
(`tamper_job` in `api-e2e.json`), which correctly shows `ARTIFACT_TAMPERED`.

## H. Security review

- **Credentials:** `NEBIUS_API_KEY` never read, printed or used. API tokens were read
  from 0600 files into environments only; the UI walkthrough confirmed the token never
  reaches local/session storage or page text. Signing keys are 0600, outside Git and the
  store; offline verification with untrusted/missing keys fails.
- **Authorization:** all `/v1/*` routes required the bearer token; attack-lab stayed
  disabled in every config; Sentinel `attack_evaluate` never opens Core's gates.
- **Policy enforcement:** Sentinel is cooperating metadata enforced only by AEGIS's own
  download/evaluate routes; tampered policies fail closed; caller IDs are unauthenticated.
- **Untrusted input:** names sanitized to one path component; binary/non-IR rejected;
  oversized input rejected before processing; adapter timeouts kill the process group.
  LLVM parsing runs on the host (not a sandbox) — I only fed it IR I generated from the
  cloned sources.
- **Process hygiene:** SIGHUP orphaning fixed (§E-2). A SIGKILL of `serve` itself still
  cannot clean up children (inherent; documented).
- **Privacy/licensing:** reVC has no license; its IR, objects and reports stay in
  `/tmp/aegis-fsv` and must not be published. Shield reports contain function names.
- **Package boundary:** see §I.

## I. Release readiness

Built with `scripts/product.py package` from the final working tree (all suites above
already passed on it). Two archives, because a report inside an archive cannot contain
that archive's own digest:

| Archive | Location | SHA-256 |
| --- | --- | --- |
| A — fully installed and tested | `/tmp/aegis-fsv/pkgA/aegis-local-review.tar.gz` | `f442d32d5197736d3d594fe768556a6b3d5ac9a7424101f4b1b46eb8de18f05f` |
| B — **final review archive** | `/tmp/aegis-fsv/pkgB/aegis-local-review.tar.gz` | detached: `/tmp/aegis-fsv/pkgB/SHA256SUMS` |

B is built after this section was written; its `RELEASE-MANIFEST.json` must differ from
A's **only** in the digest of this report (checked after packaging; result in
`/tmp/aegis-fsv/pkgB/VERIFICATION.txt`).

Archive A checks (extracted to a new 0700 directory `/tmp/aegis-fsv/fresh-A/aegis`):

| Check | Result |
| --- | --- |
| Member names | 330 members, all under `aegis/`, no `..` |
| Completeness | all 326 tracked + untracked non-excluded source files present, plus the 3 built dashboard files and the manifest; 0 missing |
| `python3 scripts/product.py check-package` (before installing anything) | "Verified 329 file digests; no extra files; license=pending_owner_review" |
| Excluded content | no `.pem`/key files, `aegis.toml`, stores, private evidence, approvals, `experiment.json`, logs, native objects, `.venv`, `node_modules`, `.git` |
| Credential patterns | 0 private PEM payloads, AWS IDs, GitHub tokens or JWTs; my API token absent. Two benign hits: a test's presence-only `NEBIUS_API_KEY=object()` placeholder; this report's demo **public** key ID |
| Fresh install per INSTALL.md | `scripts/setup-python.sh` + `uv pip install …` (uv chose CPython 3.13.15; own `.venv`) + `npm ci` (own `node_modules`); warm caches, about 1–2 min; cold-network install not measured. Warnings: uv hardlink fallback to copy; npm 12 blocked esbuild's postinstall under its existing policy (build still succeeded). No policy relaxed. |
| `product.py build` / `configure` | Shield + ImageLab + dashboard built; both probes passed |
| CLI Shield+Mirage on the owned fixture | succeeded; `shield-stage.ll` `4a7da8c1…949d68a9a`, `protected.ll` `0fc986a8…460116b42` — the deterministic values documented in INSTALL.md |
| `product.py smoke` over HTTP | both backends succeeded; every output re-hashed |
| NVIDIA summary import (`scripts/check-research-dashboard.cjs`, real Chromium) | desktop, mobile and Results passed; 0 browser POSTs |
| Signing + Sentinel when configured | fresh Ed25519 key; incomplete config refused with `CONFIG_INVALID` (no unsigned fallback); complete config: 4/4 outputs `verified`, `execute` denied, `analyze` permitted |

The root `LICENSE` remains a **pending-owner-approval** proposal; `RELEASE-MANIFEST.json`
says `license_status: pending_owner_review`. The archive grants no redistribution rights.

## J. Remaining work (by severity / deadline relevance)

1. **Medium — stale `running` jobs after an API crash.** Core never reconciles jobs whose
   process died; `GET /v1/jobs/{id}` shows `running` indefinitely with no error. A safe fix
   needs job ownership/leases because CLI and API may share a store (touches Core storage,
   owner-A approval). Workaround: treat jobs older than their adapter timeout as dead.
2. **Medium — external targets are component-level only.** No cargo/CMake integration that
   substitutes protected IR during a normal application build. Mattermost needs entirely
   new backends.
3. **Medium — NVIDIA three-way comparison not run.** Needs explicit operator approval and
   a private run (§D); even then Shield and Mirage prompts are identical.
4. **Low — Mirage fixed 64 MiB limit**, independent of adapter limits (now reported
   correctly; large Rust crates exceed it).
5. **Low — reVC full build needs GLFW** (operator install approval) and legal assets.
6. **Operator actions:** approve/adjust the license and copyright holders; review all
   changed files; approve commit/push/PR; publication/video/submission.

## K. Modified-file inventory (this pass)

| File | Why |
| --- | --- |
| `protectors/mirage/src/aegis_mirage/transform.py` | §E-1 vendor-only triple support; §E-3 `input_too_large` |
| `protectors/mirage/tests/test_transform.py` | regressions for §E-1 and §E-3 |
| `protectors/mirage/README.md` | documents the triple rule |
| `protectors/llvm/adapter/tests/test_shield_mirage_adapter.py` | adapter-level regression for §E-1 |
| `protectors/llvm/adapter/README.md` | triple rule and Mirage's fixed 64 MiB limit |
| `scripts/product.py` | §E-2 SIGHUP cleanup |
| `scripts/tests/test_product.py` | §E-2 regression (3 signals, real processes); `import os` |
| `ARCHITECTURE.md` | contract note for the Mirage triple rule (AGENTS.md §7) |
| `docs/release/NATIVE_BACKEND_CONTRACT.md` | triple rule |
| `docs/release/RUNBOOK.md` | `target_triple_mismatch` / `input_too_large` guidance |
| `docs/release/INSTALL.md` | tested inputs and external-target support statement corrected |
| `docs/PROJECT_STATUS.md` | external benchmark row updated to measured status |
| `docs/release/FULL_SYSTEM_VALIDATION.md` | this report (new) |

No other repository file was changed; a checksum comparison against my 06:52 snapshot
showed no concurrent edits by the two idle Codex sessions. Historical evidence, approvals,
signing keys and archives were not modified.
