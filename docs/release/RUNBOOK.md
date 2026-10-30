# Local release and demonstration runbook

This runbook uses the merged checkout and existing contracts. It never executes
generated reconstruction candidates or enables live inference. Use owned inputs;
the protection smoke compiles only `protectors/llvm/tests/fixtures/annotated.c`.

## Prerequisites and setup

Use Linux/POSIX, Python ≥3.11, uv, Node ≥22.18/npm, LLVM/Clang 22.x, CMake and
Ninja. Verify `llvm-config --version`, `clang --version`, `opt --version` and
`llvm-link --version` report the same LLVM major. For versioned installations,
put the installation’s `bin` directory first on PATH. Install these tools
explicitly according to your machine’s policies; no product script installs them.

From a clean extracted package or checkout:

```sh
sh scripts/setup-python.sh
uv pip install --python .venv/bin/python -c core/requirements-dev.lock \
  -e './attack_lab[dev]' -e ./protectors/mirage
npm --prefix platform/dashboard ci
.venv/bin/python scripts/product.py build
.venv/bin/python scripts/product.py configure
.venv/bin/python scripts/product.py serve
```

Default scratch root: `/tmp/aegis-product`. It contains native builds, the
compiled fixture, config and private job store. Keep it private. The configure
command refuses an existing config. To start fresh without deleting evidence,
use a new `--workspace /tmp/aegis-demo-2` for **every** product command.

The API binds `127.0.0.1:8000`. The built dashboard preview binds
`127.0.0.1:5173`; Vite proxies `/healthz` and `/v1` to the API. No CORS exception
or public bind is needed. The launcher rejects occupied ports and stops sibling
services on exit. Vite preview is a local demonstration server, not production
hosting. Ctrl-C stops the launcher and both process groups.

For API authentication, set `AEGIS_API_TOKEN` privately before `serve`, then enter
that value under dashboard **Capabilities**. The UI retains it only in memory.
Never put it in screenshots, the package, command arguments, or tracked files.
Health stays public. Browser tests assume this optional variable is unset.

## Shield through the dashboard

1. Open `http://127.0.0.1:5173`. Confirm the backend readiness text lists
   `llvm-shield`. This checks the adapter executable, not plugin usability.
2. Choose **Protect LLVM IR**. Select `/tmp/aegis-product/annotated.ll`.
   The input is compiled from the checked-in owned fixture. Seed `42` is sent as
   a decimal **string**; maximum sites is 16.
3. Submit once. The job moves through pending/running to a terminal status.
   The dashboard polls every 1.5 seconds and shows the terminal Core report.
4. For this fixture the real adapter reports one transformed site. Inspect the
   input and output SHA-256 digests, evidence-source labels and limitations.
   Download the report; it may disclose function names and stays local.
5. Copy the job ID. Reload the page, choose **Protection jobs**, enter that ID
   and load it. There is no historical list endpoint; accepted session jobs
   are in browser memory. The local config’s store retains the real jobs.
6. To demonstrate a truthful failure, submit a file named `invalid.ll` containing
   invalid IR text. Expect `failed`, `ADAPTER_FAILED`, an adapter failure code,
   a failure report and no registered outputs. Do not describe it as protected.

While `serve` is running, a separate terminal can reproduce the API/proxy path:

```sh
.venv/bin/python scripts/product.py smoke
```

This command submits the owned fixture, waits for a terminal report, checks a
nonzero adapter transformation claim and independently hashes every local output
against Core’s recorded SHA-256. Its printed job ID can be loaded in the UI.
Neither changed IR nor matching hashes establishes attack resistance.

## ImageLab

`product.py build` creates the owned native, IR-baseline and Shield variants:

```sh
ctest --test-dir /tmp/aegis-product/imagelab-build --output-on-failure
/tmp/aegis-product/imagelab-build/shield/imagelab-cli enhance \
  demo/image_processor/tests/fixtures/gradient_17x9.pam \
  /tmp/aegis-product/enhanced.pam
.venv/bin/python demo/image_processor/tools/compare_variants.py \
  --build /tmp/aegis-product/imagelab-build --quick \
  --output /tmp/aegis-product/imagelab-compare.json
.venv/bin/python scripts/export-product-evidence.py benchmark \
  /tmp/aegis-product/imagelab-compare.json \
  --output /tmp/aegis-product/benchmark-summary.json
```

The exporter checks the comparison record’s local artifact digests. It does not
re-measure the timings or independently establish that a measurement was made.
The quick setting is a smoke check: 64×48, one round, two samples, no warmup,
one repeat, seed 1. It cannot establish a stable performance change. Full
measurement guidance is in [ImageLab README](../../demo/image_processor/README.md).
All records remain under `/tmp`; no new benchmark results are tracked here.

## Mirage local report

Mirage is a separate transformer, not a registered protection backend. Its CLI
currently defaults to `/usr/bin/clang`, `/usr/bin/llvm-link` and `/usr/bin/opt`;
these must be LLVM 22. The Python `transform` function also accepts explicit tools.

```sh
clang -O1 -S -emit-llvm protectors/mirage/tests/fixtures/signal.c \
  -o /tmp/aegis-product/signal.ll
.venv/bin/python -m aegis_mirage /tmp/aegis-product/signal.ll \
  --output-dir /tmp/aegis-product/mirage --seed 42
.venv/bin/python scripts/export-product-evidence.py mirage \
  /tmp/aegis-product/mirage --original-ir /tmp/aegis-product/signal.ll \
  --output /tmp/aegis-product/mirage-summary.json
```

Both input and transformed-IR hashes are checked. Inserted counts do not imply
that decoys survive a final link. Run the existing Mirage suite locally and the
explicit-tool product retention test for the owned executable:

```sh
.venv/bin/python -m pytest protectors/mirage/tests scripts/native_tests -q
```

The test compiles and runs **only the checked-in trusted fixture**, compares its
outputs and inspects retained symbols after O2 and linker GC. It makes no claim
about model target selection or attack resistance.

## Lab records and local imports

The UI accepts only `aegis.product.evidence.v1` summaries from the exporter,
not raw experiments, requests, candidate source, private Core records, hidden
cases or full analysis comparisons. It sends no imported report to a server.

For an existing authorized experiment directory containing `experiment.json`
and its `private-evidence/` archive:

```sh
.venv/bin/python scripts/export-product-evidence.py reconstruction \
  /absolute/private/experiment-directory \
  --output /tmp/aegis-product/reconstruction-summary.json
```

The exporter uses the merged Lab’s `verify_experiment` to recheck every bound
blob, response provenance and candidate linkage. Only trial/pair identity,
digests, provider/model identity, aggregate token/step counts and generation/
scoring states reach the summary. No provider call, compiler or candidate runtime
is invoked. These unsigned checks establish consistency, not authorship.

To produce new owned research records with real Ghidra and the offline scripted
provider, follow [Role B’s exact command](../../attack_lab/docs/role-b-delivery.md#reproduce):

```sh
PYTHONPATH=attack_lab/src:protectors/mirage/src .venv/bin/python attack_lab/scripts/role_b_demo.py \
  --output-dir /tmp/aegis-product/lab-demo \
  --ghidra-headless /absolute/ghidra/support/analyzeHeadless \
  --shield-plugin /tmp/aegis-product/shield-build/AegisShield.so \
  --authorized-owned-fixture
.venv/bin/python scripts/export-product-evidence.py reconstruction \
  /tmp/aegis-product/lab-demo/baseline-vs-shield/controlled/baseline \
  --output /tmp/aegis-product/reconstruction-summary.json
```

This needs the separately installed Ghidra 12.1.4/JDK tools and a new output
directory. It uses the checked-in owned `signal.c`; no arbitrary target or live
provider is authorized by this runbook. Candidates are scripted, unexecuted and
behaviorally unscored. Placeholder scoring bindings are not valid scoring inputs.
Missing Ghidra is an explicit **not run**, not a successful reconstruction test.

In **Research evidence**, select one exported JSON file and paste the SHA-256
printed by the exporter from your trusted terminal. Choose **Verify and load
summary**. A mismatch, unsupported schema or extra private fields is an error.
Import multiple reconstruction summaries to compare trial/pair IDs and generation
states. Pending behavioral scoring never becomes a success badge. There is no
safe backend Lab endpoint; [Agent 1 contract notes](AGENT1-CONTRACT.md) record the
boundary. A raw Phase 4 score is deliberately not imported because it contains
private case/worker data and depends on unmerged Core verification.

## Validation and package

Stop any manual `serve` before the browser suite. Install Chromium locally:

```sh
PLAYWRIGHT_BROWSERS_PATH=/tmp/aegis-product-browsers \
  npm --prefix platform/dashboard exec -- playwright install chromium
PLAYWRIGHT_BROWSERS_PATH=/tmp/aegis-product-browsers \
  .venv/bin/python scripts/product.py verify
.venv/bin/python scripts/product.py package
```

The verification command runs complete Core/API/CLI/provenance/Sentinel/real
adapter regressions, product-script tests, Shield and ImageLab CTest, Mirage,
explicit-tool native smoke, offline Lab, frontend contract checks and the real
browser suite. Lab offline skips are reported as NOT RUN. Strict Core+Lab is a
separate pending integration dependency, not covered by the word “offline”.

The archive includes working-tree source and the built dashboard with a
`RELEASE-MANIFEST.json` file inventory. Native binaries must be rebuilt locally.
License status remains `pending_owner_review`. The package command refuses to
overwrite an existing archive. To verify a received archive, first inspect its
contents and SHA-256, extract into a new directory, then recompute each file hash
in the manifest. It records Git HEAD plus exact source bytes; HEAD alone is
insufficient while the product changes are uncommitted.

## Failure guide

| Symptom | Meaning / next step |
| --- | --- |
| `UNSUPPORTED_BACKEND` | Start API with the generated `AEGIS_CONFIG`; bare `aegis-api` does not register Shield |
| `ADAPTER_FAILED` | Read the report’s adapter error code; plugin mismatch, invalid IR and zero eligible sites all remain errors |
| `NO_TRANSFORMATIONS_APPLIED` | No eligible arithmetic was transformed; use annotated trusted LLVM 22 IR |
| Port bind / occupied-port error | Stop your own local API/preview or resolve the conflict; no automatic public-port fallback |
| HTTP 401 | Enter the configured bearer token in Capabilities |
| Request timeout | Acceptance is uncertain; inspect local store job IDs before resubmitting |
| Report request fails | Keep the known job ID; use Refresh to retry; no empty report is substituted |
| Local summary verification fails | Check source schema, dependencies, artifact/blob hashes and trusted exporter digest; raw private records are unsupported |
| Native/browser tool missing | Install explicitly or report the affected suite NOT RUN; no fake backend fallback |
