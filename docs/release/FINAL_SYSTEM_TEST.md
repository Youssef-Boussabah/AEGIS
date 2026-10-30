# AEGIS combined-tree system test — 30 October 2026

**Integration gate: PASS after one authorization fix. All four assigned system
tests completed. NVIDIA transport works, but the tested live responses did not
produce an accepted candidate. Whole-application protection and attack resistance
are not established.** Completed before the noon engineering cutoff.

Tested from 10:08 Toronto on `dev/integration` HEAD
`691ce2717934c22dd30883b5dd8a586ebf78bf20` **plus the combined uncommitted tree**,
coordinating the four existing agents with exclusive ownership. Central signing
tests used new ephemeral identities and a test-only token, never operator keys.
Validated host scope is Linux x86-64/LLVM 22. Dashboard protection accepts textual
LLVM IR; source wrappers compile trusted C/C++/Rust components first. Arbitrary
binary uploads and a cross-platform/version matrix were not supported/tested.

## What actually ran

| Area | Current-tree result | Scope / remaining failure |
| --- | --- | --- |
| Complete product gate, after fix | **805 companion Python tests**, **2105 strict real-Ghidra Lab tests**, **27 Mirage**, **3 native final-link**, **14 frontend contracts**, **22 Playwright tests** passed; Shield **1/1**, ImageLab **12/12**, TypeScript/Vite build passed. Gate exit **0**, zero skips. | One Starlette/httpx deprecation warning; browser startup also printed existing relative-venv prefix and Node color-environment warnings. No missing prerequisite counted as a pass. |
| Independent signed API/CLI walkthrough | **72/72 checks passed**, actual loopback API and both real backends. | Every output signature verified online and offline; exact-byte/hash/size downloads, manifests, policy decisions, CLI verify/evaluate, auth errors, invalid IR, no-op failure, path containment, artifact/policy tampering and recovery. |
| Independent browser walkthrough | **47/47 checks passed**, actual signed API/dashboard, desktop and 390px mobile. | Both profiles, combined seed limit, submission/polling, all output signatures, Sentinel deny/permit, artifact/manifest downloads, Results, reload/reopen, no token persistence, mobile layout, fresh NVIDIA-summary imports and rejection of wrong digests/private records. No HTTP fixture supplied successful protection. |
| reVC, native agent | Fresh baseline **293/308 TUs compile; 15 fail** with GLFW API incompatibilities. Selected **20/20 TUs protected per backend**, 29 function records / 50 sites, **60/60** Mirage symbols in objects. **5,740,206** bounded comparisons across 13 extracted instances: zero mismatches. Six linked full-Darkel-component executables at O2/O3 match **229,791 cases each**, with 3/3 decoys in combined binaries. | Game not linked/run; 16 changed functions not executed; no proprietary assets or redistribution. New native suite **69 passed**, adapter suite **140 passed**, fresh Shield CTest **1/1**. Details: [native system test](../../integrations/native_project/SYSTEM_TEST.md). |
| PhotoCraft, Rust agent | Fresh plugin build/CTest **1/1**, Rust suite **63 passed**. Color baseline/Shield/combined **30/30** in three samples; 3 decoys retained. Algo SSD Shield job, native compile/link succeed: 13 functions / 26 sites; original **725 pass / 2 fail / 27 ignored**, matched and protected **726 / 1 / 27** in all three samples. | Algo correctly exits **BASELINE_TEST_FAILURE**, despite equivalent named outcomes. Color changes only a std helper. Oversized combined mode refuses `MIRAGE_INPUT_TOO_LARGE`. Earlier `/tmp` attempt had `ADAPTER_IO_ERROR`, zero outputs, coinciding with full tmpfs; it remains a failed attempt. [Rust system test](../../integrations/rust/SYSTEM_TEST.md). |
| Automated selection, adaptive agent | **96 tests passed**, fresh four-job controller, **86 owned native launches**, **269 consistency checks**. Selected c003; c003/c004 are identical ELF bytes. | Decisions use correctness, retention, size and noisy process timing. No decisive real attack evidence drives them; resistance stays **UNMEASURED**. Missing decisive evidence refuses required-evidence selection; budget exhaustion preserves a verified incumbent. Fresh unrelated NVIDIA records correctly remain unmatched by artifact hash. [Adaptive system test](../../experiments/adaptive_mvp/SYSTEM_TEST.md). |
| Mattermost, benchmark agent | Fresh unprotected server baseline builds; focused Markdown suite records **556 passing test/subtest events**, one package, zero failed/skipped. Six real Core attempts across both backends reject Go archive/assembly/TS with explicit errors and zero outputs; native plans also reject Go/TS. | **Protection unsupported**, not successful. Entire server test suite/server execution not run. [Benchmark system test](../../benchmarks/reconstruction/SYSTEM_TEST.md). |
| Real reconstruction analysis, benchmark agent | Ghidra **12.1.4** freshly exported/decompiled **28/28 baseline**, **28/28 Shield**, **31/31 combined**; both selected functions completed, zero failures/truncation. All three imports and six ELF entry-point cross-checks pass. Benchmark suite **78 passed**, zero skips/warnings. | Structural/decompilation analysis only. Protected selected-function text is identical between Shield and combined; no behavioral reconstruction score or Mirage distraction effect. |

The plugin was rebuilt; isolated test servers were stopped cleanly. CLI smoke
also passed both real backends with output rehashing. The final gate supersedes
the initial 804-test run. A sandbox API connection was refused before the approved
loopback rerun passed. Duplicate suites are not summed into inflated totals.

## Release-blocking defect fixed

`scripts/live_evaluate.py run` automatically invoked `score` after receiving a
candidate despite **inference-only** approval. The new regression failed before
the fix; automatic compilation/execution is now removed and scoring records
`not_run: inference_approval_does_not_authorize_candidate_execution`.
All **11 wrapper tests**, then the complete gate, passed. Archive/export and
single-use safeguards remain intact. Architecture/README document the boundary;
the separate experimental scorer is not an approved Core execution runtime.

The native agent fixed a test-only `/proc` ESRCH race: **66 passed / 1 failed**
before, **69 passed** after two added regressions. Live-descendant assertions
remain intact; no backend/Core change was made.

## NVIDIA in the actual application workflow

Verified **signed Core job → fresh protected ELF → real Ghidra → production Lab
request/draft**, job `8d58153ea13743eeaa04a18f4b1fb923`, all signatures verified,
zero provider requests and drafts unapproved. Paid inference is operator CLI;
dashboard Evaluate imports evidence. The current verifier also checked and
re-exported these recent operator/Claude archives; browser imports made zero POSTs:

| Existing real request | Provider-reported usage | Observed outcome | Approved-price estimate |
| --- | --- | --- | ---: |
| Baseline, `live-baseline-20261030T133522Z` | 1786 prompt + 8192 completion = **9978** | `finish_reason: length`, `invalid_output`, no accepted candidate | **$0.002074** |
| Shield, `live-protected-20261030T132224Z` | 1944 prompt + 8192 completion = **10136** | `finish_reason: length`, `invalid_output`, no accepted candidate | **$0.002083** |

Requested/reported model: `nvidia/Nemotron-3_5-Lightning`, Nebius Token Factory.
v2 accepts the metadata, but non-`stop` completions and non-JSON content are
correctly refused. This proves inference integration, **not reconstruction or
protection**. Combined estimate **$0.004157** is not an invoice; reservations were
$0.064881 each. Billing/weights/provider origin are not independently attested.
No requests were duplicated or initiated by this campaign.

### Prepared operator-only diagnostic, not executed

**Superseded at final release preparation:** Codex 4 now exclusively owns the
new explicit no-thinking diagnostic and its operator handoff. Do not execute the
older commands below as an additional request; they are retained only as this
system test's historical preparation record. Use Codex 4's reviewed current
instructions and fresh single-use approval.

To investigate completion at a larger cap, one fresh **protected** request is
prepared at:

```text
/home/youss/aegis-system-test-scratch-20261030/integration/nemotron-prepared
```

One protected-only POST for owned `imagelab_color_adjust_pixel`: **16,384**
completion tokens, **120 seconds**, **$0.10** ceiling, **$0.066847** conservative
reservation; actual cost unknown, another invalid result possible. Its exact
artifact/request hashes and private review body are in `binding.json` and
`protected/approval.DRAFT.json.request-review.json`. Decoys are absent from the
selected-function prompt; this is not a Mirage-effect test or another baseline.

Only if the operator chooses this diagnostic after checking for overlap with
Claude's work and their shared **$20 total** accounting, run in the existing
key-enabled Fish terminal (no key value in any command):

```sh
.venv/bin/python scripts/live_evaluate.py approve \
  --workdir /home/youss/aegis-system-test-scratch-20261030/integration/nemotron-prepared \
  --target protected --budget-ledger /tmp/aegis-nv/nvidia-budget-ledger.jsonl
.venv/bin/python scripts/live_evaluate.py run \
  --workdir /home/youss/aegis-system-test-scratch-20261030/integration/nemotron-prepared \
  --target protected --use-environment-credential --max-output-tokens 16384 \
  --budget-ledger /tmp/aegis-nv/nvidia-budget-ledger.jsonl
```

The first command requires operator request/retention review. The second is
billable and **not run by test agents**. Keep reservations; no automatic retries
or candidate execution. Confirm the existing ledger's shared allocation first.

## Before release

1. Resolve valid NVIDIA output before claiming successful candidate generation;
   otherwise disclose the invalid-output result. Reconstruction correctness
   additionally needs separately authorized scoring with validated isolation.
2. Preserve upstream failures and component-only/unsupported scope. Use sufficient
   scratch space for large Rust IR; no historical evidence was deleted.
3. Complete frozen-source, licensing and publication review separately. Nothing
   was installed, committed, pushed, published or licensed by this campaign.

Central evidence: `/tmp/aegis-final-system-20261030-1010/` (0700): build/configure,
`final-integration-gate.log`, `api-results.json`, `browser-results.json`, screenshots,
before/final source inventories and the regression's before/after logs. Fresh
NVIDIA preparation is on the private SSD path above. Full exact commands,
toolchains, sample domains and artifact hashes are in the linked four system
reports. Central host: Linux x86-64, LLVM 22.1.8, Python 3.14.7, Node 26.8.1,
Ghidra 12.1.4/JDK 21; shared host, no controlled performance inference.

Final-gate source check found no implementation/test changes during that gate;
only the Rust owner's in-progress Markdown report changed. Repository files
edited by the release owner in this campaign: `scripts/live_evaluate.py`,
`scripts/tests/test_live_evaluate.py`, `ARCHITECTURE.md`, `README.md`, this report,
and the refreshed `STAGING_INVENTORY.md`, `STAGING_PATHS.txt`, `STAGING_SNAPSHOT.json`.
Coordinated owner changes: `integrations/native_project/tests/test_runner.py`
and the four linked `SYSTEM_TEST.md` reports. Existing uncommitted work is preserved.
