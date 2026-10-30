# Independent evaluation validation — 30 October 2026

Implementation and native validation finished before the 10:15 AM Toronto feature
cutoff. This task changes only `benchmarks/reconstruction/`. The benchmark is
optional and is not added to root configuration, CI, public APIs or release flows.
No packages were installed, no secrets were read, and nothing was committed,
pushed or published. No other analyst's jobs were started, stopped or changed.

## Checks performed

Exact command from repository root:

```sh
env AEGIS_RECONSTRUCTION_PLUGIN=/tmp/aegis-shield-build/AegisShield.so \
  .venv/bin/python -B -m unittest discover -s benchmarks/reconstruction/tests -v
```

Final result: **78 tests passed, 0 failures, 0 errors, 0 skips, 0 warnings**;
unittest reported 1.753 seconds. Log: `/tmp/aegis-reconstruction-tests.log`.
This includes real native Shield/Mirage builds, two independent build directories
with identical final binary hashes, owned oracle checks, single-function scope,
final ELF decoy retention, read-only reporting/import, and production Lab draft
preparation. The draft-preparation test uses clearly labeled synthetic Ghidra
reports, exercises the actual offline draft command, and confirms both approval
booleans remain false. It performs no Ghidra job, networking or provider request.
All replay receipts and parser records used in tests are synthetic unit fixtures,
never genuine attack evidence. Earlier test-discovered import-name and preparation
directory-collision defects were corrected before this final passing run.

The recorded benchmark command was:

```sh
.venv/bin/python -B benchmarks/reconstruction/benchmark.py demo \
  --plugin /tmp/aegis-shield-build/AegisShield.so \
  --output-dir /tmp/aegis-reconstruction-final-archive-20261030 \
  --samples 9 --iterations 2000000
```

All three variants passed the **24 predefined public oracle cases**, one warmup,
and nine timing samples with an independently calculated timing-loop checksum.
Baseline, Shield and Shield+Mirage are **three distinct final ELF hashes**. Shield
reports 5 IR sites across the selected targets; target machine bytes differ from
baseline. Three exact Mirage decoy bodies survive the final O2/GC link. These are
structural and finite correctness observations, not attack resistance.

`report_archive` re-read and hashed all artifacts, remeasured the final ELF data
and validated recorded oracle/output bindings before generating the delivered
`RESULTS.md` and `measured-results.json`. The delivered Markdown exactly matches
`render(measured-results.json)`. Actual archive comparison identity:

```text
b769899ebc28ccbdc50ca94cf0f82637d0e1786b4759174470062b210da0ba1f
```

LLVM `llvm-size -A` independently agreed with the reader's `.text` byte counts:
**777 / 809 / 953**. `llvm-nm --defined-only --print-size` independently showed
both selected function bodies and all three Mirage decoy bodies in the combined
ELF. The measurements record LLVM 22.1.8, Python 3.14.7, Intel Core Ultra 9 185H,
Linux x86-64, exact source/tool/plugin hashes, flags, commands, order and samples.
Timings are shared-host process wall measurements including startup; no CPU pinning
or general performance/security conclusion is supported.

## Not run / pending evidence

- **Real Ghidra/REA jobs: not run by this task.** Existing Claude jobs were left
  alone. Ghidra parser compatibility was tested offline, not claimed as real
  decompilation evidence. Completed handoff paths were requested for exact binding.
- **Live NVIDIA requests: not run by this task; 0 requests, $0 new estimated
  inference spend, $0 reservations.** The operator's separate Fish terminal holds
  the credential and centrally accounts for the shared $20 cap. Claude owns the
  active baseline/Shield live requests. Other engineering agents agreed to hold
  overlapping requests. No agent-accessible ledger was supplied or invented.
  Fresh live evidence remains pending the Claude/operator handoff; historical
  revalidation and synthetic fixtures are not substitutes.
- **Candidate compilation/execution and behavioral scoring: not run.** No
  validated isolation was available to this task. Behavioral scores are unavailable.
  The external replay-receipt import requires an explicitly trusted independent
  review, and is tested using synthetic receipts only.
- **Core/API/CLI, dashboard, LLVM plugin CTest and ImageLab CTest suites: not rerun
  by this task.** Their code and configuration were not changed. Results reported
  by other agents are not represented as checks performed here. This module's
  actual native protector builds and offline production Lab bridge were tested.

General NVIDIA budget authorization is preserved. The existing production
single-use, exact-request disclosure/retention approvals still apply; no approval
booleans, usage reservations or runtime safeguards were bypassed. The optional
`prepare_live.py` produces reviewable proposals and exact production argv, never
an approval or a provider. Do not launch overlapping baseline/Shield requests.

## Files created by this task

- `.gitignore`: excludes local Python/pytest caches.
- `benchmark.py`: strict comparison/oracle validation, owned builder, final ELF
  reader, native correctness/timing, verification and generated results.
- `evidence.py`: Ghidra, REA projection, Nemotron summary, production archive and
  independent isolated-replay receipt import; no execution entry point.
- `prepare_live.py`: optional production-Lab preparation from pinned owned builds
  and completed reports; explicit lower-priority static analysis option only.
- `fixtures/target.c`: two owned unsigned arithmetic targets.
- `fixtures/runner.c`: bounded owned correctness/timing executable.
- `fixtures/oracle.json`: 24 frozen expected results, including error-prone edges.
- `tests/test_benchmark.py`: manifest, file, ELF, oracle, evidence and failure tests.
- `tests/test_lab_imports.py`: current Ghidra/Nemotron format compatibility.
- `tests/test_native.py`: actual toolchain/build/retention/reproducibility checks.
- `tests/test_production_bridge.py`: production request and preparation controls.
- `README.md`: usage, safety boundaries, reproduction and integration workflow.
- `FORMATS.md`: exact local formats, classifications and explicit trust anchors.
- `RESULTS.md`: table generated from the actual measured archive.
- `measured-results.json`: raw samples, exact conditions, commands and manifest.
- `VALIDATION.md`: this validation and complete file inventory.

Open limitations: unsigned local provenance and reviewer trust; timestamps without
an attested clock; public finite oracle data; ELF64 little-endian only; explicit
unsupported interfaces; operator-supplied REA projection semantics; public research
summaries' incomplete prompt metadata; pending matching live records and unavailable
candidate isolation. No decompiler complexity score proves resistance.
