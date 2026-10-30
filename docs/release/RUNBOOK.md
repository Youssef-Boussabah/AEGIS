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
use a new `--workspace /tmp/aegis-demo-2` for **every** product command. A
workspace built from a deleted or different checkout is refused; build a new one.

`configure` registers a backend only after a **real probe job** on the owned
fixture succeeds through `python -m aegis_cli` in a throwaway store:
`llvm-shield` (required; no config is written if it fails) and
`llvm-shield-mirage` (Shield followed by Mirage decoys; omitted with a printed
warning if its probe fails). Its contract is
[NATIVE_BACKEND_CONTRACT.md](NATIVE_BACKEND_CONTRACT.md).

The API binds `127.0.0.1:8000`. The built dashboard preview binds
`127.0.0.1:5173`; Vite proxies `/healthz` and `/v1` to the API. No CORS exception
or public bind is needed. The launcher rejects occupied ports and stops sibling
services on exit. Vite preview is a local demonstration server, not production
hosting. Ctrl-C stops the launcher and both process groups.

To run a second local instance (for example the browser suite beside a running
demo), pass the same loopback ports to `serve`, `smoke` and `verify`:
`--api-port 8100 --dashboard-port 5273` (or set `AEGIS_API_PORT` /
`AEGIS_DASHBOARD_PORT`). `serve` refuses to start, with the listed problems, when
API health is degraded, or when the config references a path that no longer
exists. `build` and `verify` refuse native build directories configured from a
different checkout. New workspaces and their job store are created with mode
0700; an existing workspace readable by other users is reported, never chmodded.
The dashboard URL is printed only after the preview proxies API health.

Output signing and Sentinel policies are **not configured** by `configure`; jobs
then report `signing.state = "not_configured"`, never "verified". To enable them,
stop `serve`, create your own Ed25519 key pair outside Git and outside the store
(private key mode 0600; AEGIS never generates keys), and append the `[provenance]`
and `[sentinel]` sections from [FINAL_API_CONTRACT.md](FINAL_API_CONTRACT.md#8-operator-configuration-aegistoml-additive-off-by-default)
to the workspace `aegis.toml` yourself. A broken signing configuration stops the
API with `CONFIG_INVALID`; it never falls back to unsigned. Every registered output
of both backends (all four for `llvm-shield-mirage`) is then signed before the job
becomes terminal. A valid signature is an attestation, not evidence of protection.

For API authentication, set `AEGIS_API_TOKEN` privately before `serve`, then enter
that value under dashboard **Capabilities**. The UI retains it only in memory.
Never put it in screenshots, the package, command arguments, or tracked files.
Health stays public. Browser tests assume this optional variable is unset.

## Shield through the dashboard

1. Open `http://127.0.0.1:5173`. Confirm the backend readiness text lists
   `llvm-shield`. This checks the adapter executable, not plugin usability.
   A degraded API (HTTP 503) shows **API degraded** with Core's problem list.
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

This command submits the owned fixture to every registered real backend
(`llvm-shield`, then `llvm-shield-mirage` if registered), waits for terminal
reports, checks a nonzero adapter transformation claim and independently hashes
every local output against Core’s recorded SHA-256. For Shield + Mirage it also
checks that `mirage-report.json` names Core's hashes of `shield-stage.ll` (input)
and `protected.ll` (output). The top-level printed job ID is the `llvm-shield` job
and can be loaded in the UI; `backends` lists every job.
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

## Shield + Mirage through Core

Select the Shield + Mirage profile in **Protect LLVM IR** when the backend is
registered, or use the CLI with the same Core config:

```sh
AEGIS_CONFIG=/tmp/aegis-product/aegis.toml .venv/bin/python -m aegis_cli protect \
  /tmp/aegis-product/annotated.ll --backend llvm-shield-mirage --option 'seed="42"' --json
```

Outputs: `protected.ll` (Shield + 3 decoys), `shield-stage.ll` (byte-identical to
the `llvm-shield` output for the same input and options), `shield-report.json`,
`mirage-report.json`. `--option mirage-enabled=false` is the no-decoy control
(`protected.ll` equals `shield-stage.ll`). `--option enabled=false` fails with
`NO_TRANSFORMATIONS_APPLIED`. Decoy names appear only in the private report.

To check retention in a real executable, build ImageLab's `external` variant from
the job's `protected.ll` (input: `<workspace>/imagelab-build/ir/kernels.input.ll`,
options `seed="42"`, `max-sites=64`); see
[NATIVE_INTEGRATION.md](NATIVE_INTEGRATION.md#imagelab-with-shield--mirage) for the
exact commands and recorded results.

## Mirage local report

The standalone Mirage CLI (outside Core) defaults to `/usr/bin/clang`,
`/usr/bin/llvm-link` and `/usr/bin/opt`; these must be LLVM 22. The Python
`transform` function also accepts explicit tools.

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
.venv/bin/python -m pytest protectors/mirage/tests scripts/native_tests -q \
  --shield-plugin /tmp/aegis-product/shield-build/AegisShield.so
```

The native tests compile and run **only checked-in trusted code** (Mirage's
`signal.c` fixture and ImageLab's own CLI/tests). They run the real
`llvm-shield-mirage` adapter through Core, link its outputs with O2 and linker GC,
compare program outputs with the baseline and Shield-only builds, and inspect
retained symbols. Without `--shield-plugin` the Shield+Mirage cases fail (NOT RUN),
never pass. They make no claim about model target selection or attack resistance.

## Lab records and local imports

The UI accepts v1 benchmark/Mirage summaries and strict
`aegis.product.evidence.v2` reconstruction/comparison summaries from the exporter,
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
backend Lab execution endpoint in the dashboard; [Agent 1 contract notes](AGENT1-CONTRACT.md) record the
boundary. A raw Phase 4 score is deliberately not imported because it contains
private case/worker data and requires an authorized execution runtime that is unavailable here.

## Validation and package

Stop any manual `serve` before the browser suite. Install Chromium locally:

```sh
PLAYWRIGHT_BROWSERS_PATH=/tmp/aegis-product-browsers \
  npm --prefix platform/dashboard exec -- playwright install chromium
AEGIS_GHIDRA_HEADLESS=/absolute/ghidra/support/analyzeHeadless \
PLAYWRIGHT_BROWSERS_PATH=/tmp/aegis-product-browsers \
  .venv/bin/python scripts/product.py verify --lab-profile integration
.venv/bin/python scripts/product.py package
```

The verification command runs complete Core/API/CLI/provenance/Sentinel/real
adapter regressions, product-script tests, Shield and ImageLab CTest, Mirage,
explicit-tool native tests, strict Lab with real Ghidra, frontend contract checks
and the real browser suite (including signed outputs). The integration profile
refuses missing prerequisites and skips. For development without Ghidra, omit
`--lab-profile integration`; offline skips are NOT RUN and do not satisfy the final gate.

The archive includes working-tree source and the built dashboard with a
`RELEASE-MANIFEST.json` file inventory. Native binaries must be rebuilt locally.
The operator approved MIT for the four named contributors on 30 October 2026;
the manifest records `license_status: approved` and `license: MIT`.
Publication still needs separate approval. The package command refuses to
overwrite an existing archive. To verify a received archive, first inspect its
contents and SHA-256, extract into a new directory, then run `python3 scripts/product.py check-package` from the extracted root
**before** installing dependencies. It rejects changed/missing/unlisted files,
symlinks and unsafe inventory paths. This verifies inventory consistency, not publisher identity. It records Git HEAD plus exact source bytes; HEAD alone is
insufficient while the product changes are uncommitted.

## Failure guide

| Symptom | Meaning / next step |
| --- | --- |
| `UNSUPPORTED_BACKEND` | Start API with the generated `AEGIS_CONFIG`; bare `aegis-api` does not register Shield |
| `ADAPTER_FAILED` | Read the report’s adapter error code; plugin mismatch, invalid IR and zero eligible sites all remain errors |
| `NO_TRANSFORMATIONS_APPLIED` | No eligible arithmetic was transformed; use annotated trusted LLVM 22 IR |
| `MIRAGE_FAILED` (Shield + Mirage) | The message names Mirage's reason: `decoy_symbol_collision` (choose another `mirage-seed`), `target_triple_mismatch` (IR not for the host target; a vendor-only difference such as `x86_64-unknown-linux-gnu` is accepted), `matching_llvm22_required` (clang/llvm-link/opt differ), `input_too_large` (module over Mirage's fixed 64 MiB limit; use `llvm-shield` alone or a smaller module) |
| `configure`: `llvm-shield probe failed …` | The plugin or tools do not work together (for example a plugin built against another LLVM); rebuild in a new workspace. No config was written |
| `configure`: `llvm-shield-mirage NOT registered` | Its probe failed (reason printed); Shield-only operation continues. Check `clang`/`llvm-link` are LLVM 22 on PATH |
| Port bind / occupied-port error | Stop your own local API/preview, or choose `--api-port`/`--dashboard-port`; no automatic public-port fallback |
| `API health is degraded: …` / dashboard **API degraded** | Fix the listed problem (adapter executable missing, store not writable) |
| `… was configured from …` / `… references missing paths` | The workspace was built or configured from another (possibly deleted) checkout; use a new `--workspace` |
| HTTP 401 | Enter the configured bearer token in Capabilities |
| Request timeout | Acceptance is uncertain; inspect local store job IDs before resubmitting |
| Report request fails | Keep the known job ID; use Refresh to retry; no empty report is substituted |
| Local summary verification fails | Check source schema, dependencies, artifact/blob hashes and trusted exporter digest; raw private records are unsupported |
| Native/browser tool missing | Install explicitly or report the affected suite NOT RUN; no fake backend fallback |


## Archived NVIDIA baseline in Research

Agent 2 exported `/tmp/aegis-nvidia-baseline-public-summary.json` with SHA-256
`16be4b7bf0bfdbbe36389aca550fa703fe7f35c5e5dc3f4161b87d87e41292b6`.
Import that public projection in **Research evidence** with the independently
supplied digest. It shows original `invalid_output`, no original candidate, and a
separate post-hoc `candidate_text_revalidated_but_behaviorally_unscored` review.
The file remains a local operator artifact, outside the distribution; synthetic
schema fixtures ship for reproducible UI tests. Never substitute a synthetic
fixture for the observed baseline. See [NVIDIA_NEBIUS.md](NVIDIA_NEBIUS.md) for
usage, costs, parser boundaries and observed provider feedback.
