# AEGIS

AEGIS is a local software transformation and evaluation research preview. Submit
**trusted textual LLVM 22 IR**, run the real Shield adapter, and inspect a job’s
status, SHA-256 artifact digests, transformation claims and limitations through
the dashboard, API or CLI. **Shield has no established security property.**
Arbitrary binaries, websites, mobile apps and consoles need future backends.

## Start the supported product

Prerequisites: Linux/POSIX, Python ≥3.11, uv, Node ≥22.18 and npm, matching
LLVM/Clang **22.x** tools (`llvm-config`, `clang`, `clang++`, `opt`, `llvm-link`,
`llvm-nm`), CMake and Ninja on PATH. The verified local toolchain and exact test
results are in [final release report](docs/release/FINAL_RELEASE_REPORT.md).
The current licensed candidate, contents approval and clean-install evidence are
in [the final release review](docs/release/RELEASE_CONTENTS_READY.md); the complete
combined-tree results are in [FINAL_SYSTEM_TEST.md](docs/release/FINAL_SYSTEM_TEST.md).
No startup command installs global packages or binds a public address.

From the repository root, explicitly install repository-local dependencies:

```sh
sh scripts/setup-python.sh
uv pip install --python .venv/bin/python -c core/requirements-dev.lock \
  -e './attack_lab[dev]' -e ./protectors/mirage
npm --prefix platform/dashboard ci
```

Build Shield, ImageLab and the dashboard, register the actual adapter in a private
scratch config, and compile the checked-in owned fixture:

```sh
.venv/bin/python scripts/product.py build
.venv/bin/python scripts/product.py configure
.venv/bin/python scripts/product.py serve
```

Open **http://127.0.0.1:5173**. Choose **Protect LLVM IR**, upload
`/tmp/aegis-product/annotated.ll`, and submit. The dashboard polls Core and renders
the terminal report, including failure details. A successful fixture job reports
one transformed arithmetic site. This measures transformation, not protection
against an attack. Ctrl-C stops both local services. Existing configs are never
overwritten. Use `--workspace /tmp/another-aegis-demo` consistently for a fresh run.

[Full demonstration runbook](docs/release/RUNBOOK.md) includes ImageLab, local
research imports, authentication, diagnostics and the review package.

## Feature and limitation matrix

| Component | Working implementation | Boundary |
| --- | --- | --- |
| Core / API / CLI | Local jobs, adapter execution, hashes, terminal reports and explicit errors | Explicit registration required; local filesystem store |
| Dashboard | Real upload, polling, reports/download, job-ID reload, verified local summary import | No historical job-list API, telemetry or license counts |
| LLVM Shield | LLVM 22 textual-IR arithmetic rewriting through the real adapter | Prototype; zero-transform jobs fail; optimization can undo rewrites; no established security property |
| ImageLab | Owned image app, reference tests, native / IR baseline / Shield comparisons | Local measurements and sampled correctness only |
| Mirage | Standalone transformer and real `llvm-shield-mirage` Core backend; retained decoys checked in two owned ELF programs | Tested LLVM 22 / O2 / linker-GC conditions only; no measured attack resistance |
| Adversarial Lab | Bound Ghidra evidence, scripted reconstruction, private archive verification and approval-gated inference | Generated candidates remain uncompiled, unexecuted and behaviorally unscored; authorized execution runtime unavailable |
| Nebius / NVIDIA | One operator-supplied archived response from requested/reported `nvidia/Nemotron-3_5-Lightning`, verified offline; separate post-hoc candidate-envelope review | Provider-reported identity/usage; GPU hardware and weights unverified; no completed three-way behavioral comparison |
| Provenance / Sentinel | Optional automatic Ed25519 output signing, fresh verification and cooperating download-policy enforcement; dashboard inspection | Off by default; operator key custody; signatures attest bytes, not security or authorship; external tools need not cooperate |
| Other ecosystems | Future compatible backends | Arbitrary binaries, web/mobile and console protection unsupported today |

The [NVIDIA research deliverable](attack_lab/docs/nvidia-research-deliverable.md)
documents the archived live result and its limits. The [merged Role B handoff](attack_lab/docs/role-b-delivery.md) is the source for
its research claims. In its one owned `signal.c` experiment, final baseline and
Shield binary digests were identical after optimization. Mirage retained three
decoys, but AI target-selection effects and behavioral reconstruction resistance
were not measured. See that handoff for commands, hardware, samples and limits.

## Tests and reproducible review package

Install the optional local browser once, then run the required product checks:

```sh
PLAYWRIGHT_BROWSERS_PATH=/tmp/aegis-product-browsers \
  npm --prefix platform/dashboard exec -- playwright install chromium
PLAYWRIGHT_BROWSERS_PATH=/tmp/aegis-product-browsers \
  .venv/bin/python scripts/product.py verify
```

Stop a manually started product server before `verify`, or give `verify` free
ports (`--api-port 8100 --dashboard-port 5273`); the browser suite starts and
stops its own servers. Missing native/browser prerequisites fail explicitly.
Lab’s **offline** suite labels skips as **NOT RUN**; it does not substitute for
strict Core+Lab integration. The [CI integration plan](docs/release/CI-INTEGRATION.md)
records historical CI prerequisites. For the final local gate, set
`AEGIS_GHIDRA_HEADLESS=/absolute/ghidra/support/analyzeHeadless` and add
`--lab-profile integration` to `verify` (Ghidra 12.1.4 and JDK 21+ required).

```sh
.venv/bin/python scripts/product.py package
```

This produces `/tmp/aegis-product/aegis-local-review.tar.gz`: source, the built
dashboard and a per-file SHA-256 inventory. No runtime store, private research
archive, credentials, virtualenv, node_modules or native plugin is included.
It is a local review package, not a published release or a portable binary build.
Build native components on the recipient’s matching LLVM 22 installation.
AEGIS is licensed under the standard [MIT License](LICENSE), copyright 2026
Youssef Bossabah, Karim Lahyani, Nevan Vu, and Riche Anyadike. The operator
confirmed all four contributors' approval on 30 October 2026. Third-party
components retain their own notices. Commit, push and publication of this final
working-tree release still require separate approval.
See the [license approval record](docs/release/LICENSE-MIT-DRAFT.md).

## NVIDIA / Nebius runtime integration

The local product requires no cloud account. Separately, Lab can send an explicitly
approved, bounded HTTPS chat-completion request to Nebius Token Factory with an
NVIDIA model ID. Credentials stay in the operator process environment; the
dashboard imports only an allowlisted public summary and a separately supplied
SHA-256. It makes no inference request and uploads no imported summary.

`scripts/live_evaluate.py prepare` connects an owned, signed Core protection job
to fresh ImageLab/Ghidra evidence and unapproved request drafts. After independent
operator approval, its `run` command uses the production Lab transport and exports
verified public metadata. **Inference-only approval never authorizes compilation
or execution of the returned candidate**: `run` records scoring as `not_run` and
does not invoke the separate experimental scorer. The full fresh-input route is
in [the judge runtime guide](docs/release/JUDGE_RUNTIME_INFERENCE.md).
An explicit `--disable-thinking` option is bound into the reviewed Nebius request
and archived sampling parameters; omission preserves historical requests. Use a
new approval for any changed request configuration. Final live-demo evidence is
coordinated separately from local packaging; no key is bundled or requested by
the dashboard.

In the supplied baseline archive, the requested and reported model is
`nvidia/Nemotron-3_5-Lightning`: 1,786 prompt and 8,039 completion tokens, 9,825 total
(provider reports). Actual billing and GPU/weight identity are unknown. The
historical result remains `invalid_output` under parser v1. A separate v2 review
accepts typed reasoning metadata and validates the candidate text envelope as
**post-hoc, behaviorally unscored**. It neither compiles nor runs the candidate.
Shield and Mirage inference continuations still need separate operator approvals;
this release task makes no paid requests. See the [runtime and evidence guide](docs/release/NVIDIA_NEBIUS.md).

## Documentation

- [Release runbook](docs/release/RUNBOOK.md), [validation](docs/release/VALIDATION.md),
  [demo video script](docs/release/DEMO-SCRIPT.md), [Devpost draft/checklist](docs/release/SUBMISSION.md).
- [Core](core/README.md), [API contract](platform/api/README.md), [CLI](platform/cli/README.md),
  [Shield adapter](protectors/llvm/adapter/README.md), [dashboard](platform/dashboard/README.md).
- [ImageLab](demo/image_processor/README.md), [Lab](attack_lab/README.md),
  [Mirage](protectors/mirage/README.md), [Provenance](provenance/README.md), [Sentinel](sentinel/README.md).
- [Contributor rules](AGENTS.md), [architecture](ARCHITECTURE.md),
  [workstreams](docs/TEAM_WORKSTREAMS.md), [contributing](CONTRIBUTING.md).
  Older PDF guides and project-status notes are historical; current code,
  module handoffs and this release’s validation record determine present behavior.

Adapters run through Core’s bounded subprocess protocol; reports distinguish
orchestrator observations from adapter claims. The local API and dashboard bind
to loopback. Attack-lab API tasks still require both the config switch and a
per-request authorization record; the product launcher leaves the switch disabled.
