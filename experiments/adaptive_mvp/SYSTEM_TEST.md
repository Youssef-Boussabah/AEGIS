# Current combined-tree adaptive system test — 30 October 2026

Tested at 14:09–14:13 UTC / 10:09–10:13 Toronto. **The real bounded
protection-selection workflow passes. Resistance remains UNMEASURED.** No
release-blocking defect was found in the exercised module paths. No implementation
or test changes were needed; this report is the only repository file added in
this follow-up. No credentials, paid requests, inference approvals/reservations,
commits, pushes, publication or generated reconstruction execution occurred.

Private run root: `/tmp/aegis-adaptive-system-20261030T1409Z`.
The fresh controller captured current production Core/Shield/Mirage sources.
A post-run comparison found **zero source digest changes** relative to that
capture. Experiment/Lab Python source identities are additionally recorded in
`current-source-hashes.json`. This is a snapshot of the tested combined tree,
not a claim that other concurrent work is frozen.

## Actual execution and decision evidence

```sh
.venv/bin/python -m pytest experiments/adaptive_mvp/tests -q \
  --basetemp /tmp/aegis-adaptive-system-20261030T1409Z/pytest
.venv/bin/python experiments/adaptive_mvp/controller.py \
  --output-dir /tmp/aegis-adaptive-system-20261030T1409Z/run \
  --plugin /tmp/aegis-shield-build/AegisShield.so --samples 9
.venv/bin/python experiments/adaptive_mvp/verify.py \
  /tmp/aegis-adaptive-system-20261030T1409Z/run/report.json
```

Results: **96 passed in 31.04 seconds, no warnings or skips**. The separate
default run completed four real production-adapter jobs, 86 trusted native
launches, independent million-input checksum checks, paired timing measurements,
final ELF inspection and 269 persisted hash/consistency checks. It stopped at
`FEEDBACK_PLAN_COMPLETE`, selected `c003`, and declared `security_claim: none`.

Report SHA-256:
`00e3829b7a3a61949afc1929bbe034a138c997322fb636cfe87c6cd07078f6ab`.
Source, plugin, tool identities, Core reports and exact argv are captured under
`run/inputs/`, `run/store/` and `run/report.json`. Same conditions as the first
run: Linux x86-64, Clang/LLVM 22.1.8, trusted hash-pinned owned `signal.c`,
Python 3.14.7, Intel Core Ultra 9 185H. Builds/sources were private; the shared
host was unpinned and other test work was running.

| Decision | Evidence actually available | Observed result and resulting choice |
| --- | --- | --- |
| Start c001, Shield / two sites / seed 42 | Declared finite initial probe, fixed trusted baseline | Build succeeded and checksum matched; final ELF and target bytes equal baseline, zero decoys. Reject for no observed final retention. |
| Start c002, Shield + three Mirage decoys | c001's measured unchanged final bytes | All three decoy code definitions retained; 16032 bytes, time ratio 1.019921. Eligible incumbent. No attack result caused this probe. |
| Start c003, Shield + one Mirage decoy | Verified c002 retention and measured 16032-byte cost; declared minimum-size objective | One decoy retained; 15920 bytes, time ratio 0.934590. Becomes the smaller incumbent. This is cost feedback, not attack feedback. |
| Start c004, one Shield site + one Mirage decoy | Verified c003 cost/retention and bounded site-reduction hypothesis | Same final ELF as c003, 15920 bytes, time ratio 0.985051. c003 remains selected under the measured-time tie-break. |
| Stop | Four permitted probes complete; no justified further configuration | `FEEDBACK_PLAN_COMPLETE`; all candidate resistance values UNMEASURED and numeric scores null. |

Timing includes process startup, supervision/log I/O and shared-host noise. Each
candidate had one warmup and nine samples, alternating with fresh baseline
controls. The original final run chose c004; this fresh run chose c003, **which
is the identical binary**. Neither differing tie-break nor ratio below one
establishes a speedup. No timing, IR expansion or retained unreachable code is
presented as security evidence.

Final hashes reproduce the original run:

| Artifacts | Bytes | SHA-256 |
| --- | ---: | --- |
| Baseline, c001 | 15864 | `237480ee41d33496db3aa68e9e8bafe3411e88c72727a833266accdcfbc1e424` |
| c002 | 16032 | `edc04a6d8e3af803c1c0db311fdcf0b4c6de801078273617800a23bca1d91574` |
| c003, c004 | 15920 | `13c449c061c38049818b42c90df1b279a822365d18f898b43be202f6a27f0f7c` |

## Real Ghidra and evidence import

Fresh preparation used the current run through `lab_bridge.py prepare` with
Ghidra 12.1.4 and model proposal `nvidia/Nemotron-3_5-Lightning`, writing
`lab-prepared/preparation.json`. Real analysis exported 17/20/18 functions for
the three distinct ELF hashes. Target decompilation was identical across all:
`526060832b49372d1e4ae4d35cd771f55ea09dd33efad43185d161d3331b9b25`.
Baseline/c001 and c003/c004 were deduplicated by final-artifact hash. All exact
production Lab request drafts remained unapproved; no requests were sent.

The module tests replayed archive validation/import with a **FakeOffline test
provider**, not NVIDIA inference, and refused subprocess creation during import.
Its same-target `unscored` receipt was also supplied to a separate real native
controller run, `with-synthetic-unscored/`. The receipt matched c003/c004's ELF,
but their resistance remained UNMEASURED. The synthetic receipt is integration
test data, not attack evidence. Synthetic decisive success/failure policy tests
exercise the bounded six-decoy branch/veto; neither is a real reconstruction
result in this system test.

Separately, existing **fresh operator/Claude NVIDIA archives** were independently
reloaded using production `aegis_lab.experiment.verify_experiment` through
`lab_bridge.py import-generation`. This test initiated no inference:

| Existing source archive under `/tmp/aegis-nv/eval10/` | Record SHA-256 | Provider-reported tokens | Approved-price estimate |
| --- | --- | ---: | ---: |
| `live-baseline-20261030T133522Z` | `aed9d8c0089f088508d77b8c571b8dd07d03ba1d4ef1aacb03fc31b838acda5c` | 1786 prompt + 8192 completion = 9978 | 2074 micro-USD |
| `live-protected-20261030T132224Z` | `084a9314efa528a340b684541c566d3da4cecb52e442157c1abb286d1c31fc99` | 1944 prompt + 8192 completion = 10136 | 2083 micro-USD |

Both archives declare external Nebius inference with requested model
`nvidia/Nemotron-3_5-Lightning`, original `generation_status: invalid_output`,
null candidate digest and `execution_performed: false`. Their original states
were preserved. Parser failure is **not** reconstruction failure or protection
success. Estimates sum to $0.004157 for these two existing records; actual billed
cost is null/unknown. Their recorded conservative reservations are 64881
micro-USD each, already part of operator-managed activity, not new reservations
by this test. These two records do not establish a shared-account spending total.
Unsigned archive consistency cannot independently authenticate provider origin,
weights, token counts or billing.

These records target **different ImageLab ELF hashes**, respectively
`f5090a8da14f21da10f1516184d51d9c6dc650861c618461a552f511b8f598df`
and `8e76ecf4c6927e32e172c5824648f8c45540015139653a7cb9a6fc3802c5be2a`.
Their imported receipts were fed into `with-fresh-nvidia/`. Both were explicitly
recorded as `unmatched_target_hash`; no candidate received their evidence, every
resistance remained UNMEASURED, and the controller continued its measured-cost
policy. No unrelated NVIDIA result was treated as adaptive attack feedback.

## Negative paths and persisted verification

Separate CLI runs used the same real plugin, `--samples 1`, new directories:

| Run | Additional option/input | Exit / result | Read-only checks |
| --- | --- | --- | ---: |
| `require-evidence/` | `--require-attack-evidence` | 2; four builds verified, no selection because decisive attack evidence absent | 125 passed |
| `budget/` | `--max-native-runs 9` | 0; `NATIVE_RUN_BUDGET_EXHAUSTED`, c003 incomplete/failed, prior verified c002 selected; exactly nine native launches | 103 passed |
| `with-synthetic-unscored/` | Index from explicitly FakeOffline test archive | 0; matching unscored evidence does not establish resistance | 127 passed |
| `with-fresh-nvidia/` | Two production-verified fresh, unrelated NVIDIA archives | 0; both hashes unmatched, no attack evidence attached | 129 passed |

Their exact report hashes are in `system-summary.json` and
`all-verifications.json`. The latter rechecks all five reports, including the
269-check default run, without running artifacts. The 96-test suite also reran
real invalid-plugin adapter failures, malformed/tampered receipts, report/hash/
lineage/selection/retention tampering, wall and candidate budgets, missing tools,
secret-environment exclusion, source/output path restrictions and process-group
cleanup on normal exit and timeout. No skipped/modified test was used to pass.

The import/budget checks used one timing sample to exercise integration rather
than benchmark performance. The unrelated-NVIDIA rerun selected c004 while the
nine-sample default run selected c003: both are the same final ELF. Different
candidate IDs reflect fresh noisy timing measurements, not an attack score or
an effect established by the imported, unmatched evidence.

## Scope and handoff

No code or regression fix was required. This follow-up changed only
`experiments/adaptive_mvp/SYSTEM_TEST.md`. Current-tree module/native/Ghidra/import
and negative tests passed. Root/API/dashboard/full Lab/LLVM and ImageLab CTest
suites were not repeated in this module-specific follow-up; earlier broader
validation remains documented in RESULTS.md and is not labeled current-tree
validation here.

No paid adaptive requests are scheduled: their identical target decompilation
does not justify duplicating Claude/operator's existing evaluation. If needed,
exact request/draft bindings and production CLI argv are already in
`lab-prepared/preparation.json`, with $0.10 per unique target proposed caps;
the existing independent operator approval and central $20 total coordination
remain mandatory. There is no agent-accessible shared ledger to assume exists.

There is **no demonstrated adversarial improvement loop**: no decisive behavioral
attack receipt for these signal hashes and no validated reconstruction execution
occurred. Release descriptions may claim automated measured protection selection
with correctness/retention/cost feedback, and a working evidence-import boundary.
They must not claim autonomous attack resistance improvement or a real scored
six-decoy response. Source/module hash inventory, raw reports, logs and production
evidence verification remain in the private run root above.
