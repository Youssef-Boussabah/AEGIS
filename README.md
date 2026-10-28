# AEGIS

AEGIS is a local orchestration platform for software-protection backends.

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
| Shield ↔ core adapter | (none yet) | **not implemented**: AEGIS cannot invoke the Shield yet |

AEGIS ships with **no registered protection backend**. Until an adapter is
registered in `aegis.toml`, `aegis protect` fails with `UNSUPPORTED_BACKEND`.

## Repository layout

```
core/               aegis_core: contracts, store, orchestrator, adapter runner
  docs/adapter-protocol.md
platform/api/       aegis_api: FastAPI service
platform/cli/       aegis_cli: `aegis` command
protectors/llvm/    AEGIS Shield LLVM pass plugin (C++/CMake)
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
.venv/bin/pytest                                   # all Python suites
cmake -S protectors/llvm -B /tmp/aegis-shield-build -G Ninja \
  -DLLVM_DIR="$(llvm-config --cmakedir)" \
  -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/aegis-shield-build
ctest --test-dir /tmp/aegis-shield-build --output-on-failure
```

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
