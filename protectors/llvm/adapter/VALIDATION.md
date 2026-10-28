# Milestone 002 validation

Run on 2026-10-27, Linux x86-64, Python 3.14.7, LLVM/Clang 22.1.8,
CMake 4.4.3, Ninja 1.13.2. This is functional regression evidence, not a
benchmark, security evaluation or attack-resistance measurement.

This worktree had no `.venv`. Tests used the existing repository environment
at `/home/youss/Projects/aegis/.venv` without installing or updating packages.
`PYTHONPATH` selected this worktree's sources for the test process. The unchanged
core test double's subprocess import uses that environment's existing editable
installation; it applies no protection and is not evidence for Shield. All
adapter-success cases invoke this worktree's script and newly built real plugin.
Key environment packages: pytest 9.2.0, pydantic 2.14.1, FastAPI 0.162.0,
Starlette 1.10.0, httpx 0.28.1.

## Commands and results

From `/home/youss/Projects/aegis-adapter`:

```sh
cmake -S protectors/llvm -B /tmp/aegis-adapter-build -G Ninja \
  -DLLVM_DIR=/usr/lib/cmake/llvm -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/aegis-adapter-build -j2
ctest --test-dir /tmp/aegis-adapter-build --output-on-failure
python3 protectors/llvm/tests/test_shield.py \
  --plugin /tmp/aegis-adapter-build/AegisShield.so \
  --opt /usr/bin/opt --clang /usr/bin/clang

env PYTHONPATH=core/src:platform/api/src:platform/cli/src \
  /home/youss/Projects/aegis/.venv/bin/python -m pytest \
  protectors/llvm/adapter/tests \
  --shield-plugin /tmp/aegis-adapter-build/AegisShield.so \
  --shield-opt /usr/bin/opt --shield-clang /usr/bin/clang -q

timeout -k 5 60 env PYTHONPATH=core/src:platform/api/src:platform/cli/src \
  /home/youss/Projects/aegis/.venv/bin/python -m pytest -q
```

| Suite | Passed | Failed | Skipped | Warnings |
| --- | --- | --- | --- | --- |
| Adapter integration (including orchestrator and CLI end-to-end) | 94 | 0 | 0 | 0 |
| Core + API + CLI | 105 (70 core, 17 API, 18 CLI) | 0 | 0 | 1 |
| Original Shield CTest | 1 CTest entry, containing 14 Python cases | 0 | 0 | 0 |
| Original Shield Python runner, same cases run directly | 14 | 0 | 0 | 0 |

The direct Shield run and CTest execute the **same 14 cases**; do not count
them twice. No relevant suite was omitted. The Python warning is the existing
`StarletteDeprecationWarning` about using httpx with `starlette.testclient`.
No dependency was changed to suppress it. CMake's optional feature probes
included failed probes; configuration and compilation themselves succeeded.

The first sandboxed all-Python run was interrupted after completing core's
70 cases and hanging in the first API health request. A single-test diagnostic
run showed the Starlette/AnyIO TestClient blocked on its asyncio portal and was
also interrupted. The complete 105-case run above passed outside the execution
sandbox, with approval. These interrupted diagnostic runs are not counted as
successful suite runs.

## Coverage and limits of the evidence

- Successful jobs run actual LLVM on the checked-in trusted annotated C fixture,
  compiled to IR by the test setup. Tests verify transformed instructions,
  string uint64 seed preservation, explicit schema-version conversion, both
  output hashes/sizes against stored bytes, evidence provenance and CLI reports.
- Error cases cover malformed requests, wrong option types/ranges, native and
  bitcode input, invalid IR, missing/unloadable tools/plugins, unsupported LLVM,
  empty/unselected/ineligible/disabled/zero-budget runs, hash mismatch, path
  traversal, symlinks/hardlinks, existing outputs and metacharacter store paths.
- Fault wrappers delegate protection to actual opt before corrupting real
  reports or IR. Cases reject wrong schema versions, backend/module/config/LLVM
  mismatches, wrong totals, invalid status/reason/selection/site data, duplicate
  functions/sites, unknown fields, invalid JSON, missing/empty/linked artifacts,
  unchanged IR and IR that fails independent verification. No protection-success
  report is fabricated.
- Size-limit cases exercise input, report, IR and live stdout/stderr growth.
  The timeout case confirms core kills an LLVM wrapper's descendant process as
  part of the inherited process group. No untrusted native artifact is executed.
  The original Shield suite executes only its trusted regression fixtures.
- Only this Linux/Python/LLVM toolchain was exercised. Python 3.11–3.13,
  other LLVM 22 patch versions, other operating systems, bitcode input and
  native runtime equivalence through the adapter were not tested. The original
  Shield runtime regression cases are narrower evidence documented in its README.
- Report checks do not establish a security property or independently prove
  the plugin's transformation claims. There is no compiler sandbox or aggregate
  resource quota. Smaller individual file limits can be exceeded transiently
  up to the hard per-file cap; see the adapter README. Hard timeouts and I/O
  failures may leave private partial files, never registered as successful
  artifacts. Existing generic core buffering/recovery limitations remain.

## Changed files

- `protectors/llvm/adapter/aegis_llvm_adapter.py`
- `protectors/llvm/adapter/report.py`
- `protectors/llvm/adapter/tests/conftest.py`
- `protectors/llvm/adapter/tests/test_adapter.py`
- `protectors/llvm/adapter/README.md`
- `protectors/llvm/adapter/VALIDATION.md`
- `protectors/llvm/README.md`
- `ARCHITECTURE.md`
- `README.md`
- `docs/adr/0002-llvm-shield-adapter.md`

No core, API, CLI, plugin implementation, existing test, existing schema,
adapter protocol or attack-lab control was modified.
