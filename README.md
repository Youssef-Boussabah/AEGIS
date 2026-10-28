# AEGIS

AEGIS is an open-source software-protection platform intended to work across desktop software, websites and web apps, mobile apps, games, backend services, embedded software and authorized console builds through **separate compatible protection backends**. Its current working foundation is a local orchestration platform and a prototype LLVM 22 textual-IR protection backend. No general cross-platform protection or measured reverse-engineering resistance is established.

It takes an input artifact and a protection policy, then runs a registered
backend through a subprocess adapter. It records SHA-256 hashes and evidence
for every artifact, and writes a report for every finished job, including
failed ones.

## Status

| Component | Path | State |
| --- | --- | --- |
| Core contracts, local store, orchestrator | `core/` | implemented, tested |
| HTTP API (FastAPI) | `platform/api/` | implemented, tested |
| CLI (`aegis`) | `platform/cli/` | implemented, tested |
| AEGIS Shield LLVM pass | `protectors/llvm/` | prototype, tested on its own; **no established security property** |
| Shield ↔ core adapter | `protectors/llvm/adapter/` | implemented; explicit registration, textual IR and LLVM 22 |
| ImageLab controlled test harness | `demo/image_processor/` | implemented C++ app and baseline/direct/external IR comparisons |
| Adversarial Lab, Mirage, Signature, Sentinel, Dashboard | `attack_lab/`, `protectors/mirage/`, `provenance/`, `sentinel/`, `platform/dashboard/` | planned; workstream issues created |

AEGIS ships with **no registered protection backend**. Until an adapter is
registered in `aegis.toml`, `aegis protect` fails with `UNSUPPORTED_BACKEND`.
For real Shield jobs, follow the [adapter registration and CLI instructions](protectors/llvm/adapter/README.md).
Zero-transform runs fail explicitly; a successful transformation establishes no
security guarantee.

## Start here

- [AEGIS User Guide](docs/AEGIS_USER_GUIDE.pdf) — project introduction, four roles and first steps.
- [AEGIS Technical Documentation](docs/AEGIS_TECHNICAL_DOCUMENTATION.pdf) — architecture, contracts, runbook and detailed briefs for the same four roles. Historical implementation evidence remains attributed to `c995857`.
- [Four engineering roles](docs/TEAM_WORKSTREAMS.md) — A Core/Shield/Integration; B Lab/Mirage; C Frontend; D Signature/Sentinel. No person assignments.
- [Contributing](CONTRIBUTING.md) — branch map, checkout, synchronization and review workflow.
- [Project status](docs/PROJECT_STATUS.md) — historical evidence, pending work, and update protocol.
- [Contributor/agent rules](AGENTS.md) and [architecture](ARCHITECTURE.md) — current repository guidance.

The implementation and tests are authoritative for behavior. Current work is tracked in GitHub issues [#9–#12](https://github.com/Youssef-Boussabah/AEGIS/issues) and external evaluation in [#7](https://github.com/Youssef-Boussabah/AEGIS/issues/7).

## Repository layout

```
core/               aegis_core: contracts, store, orchestrator, adapter runner
  docs/adapter-protocol.md
platform/api/       aegis_api: FastAPI service
platform/cli/       aegis_cli: `aegis` command
protectors/llvm/    AEGIS Shield LLVM pass plugin and adapter
demo/image_processor/ Controlled C++ image-processing benchmark
attack_lab/         Adversarial evaluation (planned)
protectors/mirage/ Defensive decoys (planned)
provenance/         Signed provenance (planned)
sentinel/           Rights notices (planned)
platform/dashboard/ Frontend interface (planned)
docs/adr/           architecture decision records
AGENTS.md           rules for contributors and agents (read first)
ARCHITECTURE.md     how the pieces fit together, and open issues
```

## Setup

The Python side needs Python ≥ 3.11 (verified with 3.14.7) and
[uv](https://docs.astral.sh/uv/). From the repository root:

```bash
uv venv .venv
uv pip install --python .venv/bin/python \
  -c core/requirements-dev.lock \
  -e './core[dev]' -e './platform/api[dev]' -e './platform/cli[dev]'
```

`core/requirements-dev.lock` pins the third-party versions the tests were
verified against. Install the three packages together, because `aegis-core`
isn't published to an index.

The LLVM Shield needs LLVM/Clang ≥ 22 (verified with 22.1.8), CMake and
Ninja. See [protectors/llvm/README.md](protectors/llvm/README.md).

## Tests

```bash
.venv/bin/pytest                                   # Core, API and CLI only
cmake -S protectors/llvm -B /tmp/aegis-shield-build -G Ninja \
  -DLLVM_DIR="$(llvm-config --cmakedir)" \
  -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/aegis-shield-build
ctest --test-dir /tmp/aegis-shield-build --output-on-failure
```

For full Python + adapter regression coverage run:

```bash
.venv/bin/python -m pytest core/tests platform/api/tests platform/cli/tests protectors/llvm/adapter/tests -q
```

ImageLab is built separately with CMake; see [ImageLab README](demo/image_processor/README.md) and the Technical Documentation §09. Compiler tests may require an explicitly supplied matching LLVM 22 plugin path.

## Usage

```bash
.venv/bin/aegis init            # write ./aegis.toml and create ./.aegis/
.venv/bin/aegis inspect         # health check
# register a backend under [adapters.<name>] in aegis.toml, then:
.venv/bin/aegis protect <file> --backend <name>
.venv/bin/aegis report <job_id>
.venv/bin/aegis-api             # HTTP API on 127.0.0.1:8000
```

Details:

- [core/README.md](core/README.md): configuration, contracts, error codes
- [platform/api/README.md](platform/api/README.md): API endpoints
- [platform/cli/README.md](platform/cli/README.md): CLI commands and exit codes
- [core/docs/adapter-protocol.md](core/docs/adapter-protocol.md): how to write a backend adapter

## Security notes

- Adapters run without a shell, with a timeout and a minimal environment.
- The API binds to loopback by default.
- Attack-lab tasks need an operator config switch **and** a per-request
  authorization record.

See ARCHITECTURE.md §6 for the full requirements.
