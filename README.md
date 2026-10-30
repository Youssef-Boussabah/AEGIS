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
results are in [release validation](docs/release/VALIDATION.md).
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
| Mirage | LLVM 22 / ELF retained unreachable arithmetic decoys; standalone transformer | Final retention needs checking; no web honeypots or measured attack resistance |
| Adversarial Lab | Bound Ghidra evidence, offline scripted reconstruction, private evidence verification, scoring interfaces | Core execution dependency unmerged here; no verified real candidate execution or live inference |
| Nebius / NVIDIA | Offline-tested Nebius chat-completion transport; configurable model ID | No verified live request or NVIDIA GPU run; live inference remains disabled |
| Provenance / Sentinel | Separate offline Ed25519 signing/verification and cooperating rights-policy CLIs | No automatic job signing; advisory metadata does not force external tools to cooperate |
| Other ecosystems | Future compatible backends | Arbitrary binaries, web/mobile and console protection unsupported today |

The [merged Role B handoff](attack_lab/docs/role-b-delivery.md) is the source for
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

Stop a manually started product server before `verify`; the browser suite starts
and stops its own servers. Missing native/browser prerequisites fail explicitly.
Lab’s **offline** suite labels skips as **NOT RUN**; it does not substitute for
strict Core+Lab integration. The [CI integration plan](docs/release/CI-INTEGRATION.md)
records the merge prerequisites and future strict job.

```sh
.venv/bin/python scripts/product.py package
```

This produces `/tmp/aegis-product/aegis-local-review.tar.gz`: source, the built
dashboard and a per-file SHA-256 inventory. No runtime store, private research
archive, credentials, virtualenv, node_modules or native plugin is included.
It is a local review package, not a published release or a portable binary build.
Build native components on the recipient’s matching LLVM 22 installation.
The [license draft](docs/release/LICENSE-MIT-DRAFT.md) awaits owner approval;
no final open-source license is granted by that draft.

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
