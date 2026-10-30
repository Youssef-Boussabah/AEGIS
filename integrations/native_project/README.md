# Native C/C++ project integration

This optional, standalone module consumes the existing production Shield adapters.
It changes no Core, adapter, backend or release contract. Python 3.11+ standard
library runtime; Linux x86-64, matching LLVM 22 tools and an already built Shield
plugin are required. Run only on operator-owned or otherwise authorized, trusted
projects. Native execution is opt-in. This is a build tool, **not a sandbox**.

No established security property or whole external application protection is
claimed. See [RESULTS.md](RESULTS.md) for measured achievements and limitations.

## Quick start

From the repository root, using the existing LLVM 22 plugin and interpreter:

```sh
.venv/bin/python integrations/native_project/native_project.py plan \
  integrations/native_project/examples/owned/project.json

.venv/bin/python integrations/native_project/native_project.py build \
  integrations/native_project/examples/owned/project.json \
  --output /tmp/aegis-native-owned --plugin /tmp/aegis-shield-build/AegisShield.so \
  --execute

.venv/bin/python integrations/native_project/native_project.py verify \
  /tmp/aegis-native-owned/report.json
```

The output directory must be new and outside both the repository and project
source root. It is created private (0700). Reusing a directory fails; nothing is
overwritten. Omit `--execute` to build and link without running any binary. The
sample's four translation units include real calls across C and C++ objects;
two units request protection and two remain unprotected. This builds the whole
**owned example**, with **partial protection coverage**.

To use Shield alone, add `--backend llvm-shield`. The example options work for
both backends. A backend override does not remove options: Mirage-only options
in a Shield-only manifest are errors. Paths can contain spaces and LLVM pipeline
metacharacters. Tools can be set with `--clang`, `--clang++`, `--opt`, and
`--llvm-link`. Their full LLVM 22 version numbers must match. No tools, Python
packages or backends are installed or globally registered by this module.

## Manifest

The strict JSON interface uses integer `schema_version: 1`. Unknown fields and
duplicate JSON keys fail. Paths resolve relative to the manifest, except unit
sources, which resolve relative to `project_root`.

```json
{
  "schema_version": 1,
  "project_root": "/path/to/trusted/project",
  "backend": "llvm-shield-mirage",
  "options": {"seed": "42", "max-sites": 16},
  "optimization": "2",
  "units": [
    {
      "source": "src/arithmetic.cpp",
      "arguments": ["-std=c++17", "-Iinclude", "-fPIC"],
      "selection": {"mode": "symbols", "symbols": ["integer_helper"]}
    },
    {"source": "src/main.cpp", "arguments": ["-std=c++17"], "protect": false}
  ],
  "link": {
    "arguments": ["-Wl,--gc-sections", "-lm"],
    "runs": [{"args": ["--self-test"], "expected_exit": 0}]
  }
}
```

`symbols` uses exact LLVM linkage names, including C++ mangling. The example
above assumes `integer_helper` has C linkage. Every explicitly selected symbol
must be a defined, non-`optnone` function with scalar integer return/arguments;
absent and unsupported symbols fail. This is candidate selection, not a promise
of an eligible arithmetic site. Source functions with signed overflow flags,
no suitable adds, or an exhausted site budget may still be skipped by Shield.

| Field | Behavior |
| --- | --- |
| `backend` | `llvm-shield` (default) or `llvm-shield-mirage`; always the existing production adapter |
| `options` | Existing adapter options, validated by that adapter; seed is a decimal **string**, not a JSON integer |
| `optimization` | String `0`, `1`, `2` (default), `3`, `s` or `z`; used consistently for native object code generation |
| `units` | 1–128 unique `.c`, `.cc`, `.cpp`, `.cxx` or `.C` sources contained in the project root |
| `arguments` | Compile flags, without compiler/source/output; evaluated in the project root when no database is supplied |
| `protect` | Boolean, default `true`; at least one unit must request protection |
| `selection.mode` | `annotated` (default), `symbols`, or explicit opt-in `integer-signatures` |
| `link` | Optional; omission produces objects only. The link includes exactly the declared units |
| `link.arguments` | `-Wl,--gc-sections`, `-pthread`, `-no-pie`, and ordinary `-lNAME` library arguments |
| `link.runs` | Up to 256 cases; exact argv and expected exit 0–255 (default 0); executed only with `--execute` |

`annotated` preserves the source's existing `annotate("aegis.protect")` selection.
The other two modes **add** function attributes in private generated IR, and
preserve existing source annotations. `integer-signatures` conservatively marks
every supported signature in a selected TU, including compiler/header-generated
definitions; it is not a selection by source ownership or a security analysis.
LLVM verifies the edited IR before the adapter runs. Original sources and headers
are never rewritten. Unsupported signatures are not automatically marked.

For combined builds, the integration derives a distinct Mirage seed for each
unit as `SHA256("aegis.native-project.mirage.v1:<base>:<relative source>")`, first
eight bytes interpreted big-endian, modulo `2^63`. The base is `mirage-seed`, or
`seed`, default `"0"`. It must be below `2^63`; supply `mirage-seed` separately
when using a larger Shield seed. Effective per-unit options are recorded. This
avoids duplicate external decoy symbols when linking several protected units.

## Existing compile databases

Add `compile_database` with a path relative to the manifest (or absolute).
Declare only the units to process, and omit their `arguments`. Each source must
match exactly one database entry. Ambiguous configurations fail; they are never
chosen silently. Both `arguments` arrays and `command` strings are accepted.
Command strings are tokenized with `shlex`, **never evaluated by a shell**.
Only a direct clang/clang++ driver is accepted; wrappers and GCC commands fail.
The compiler in the database is not executed: configured, verified LLVM tools
are used, with each entry's original working directory and supported flags.

Owned example, using CMake's real database:

```sh
cmake -S integrations/native_project/examples/owned -B /tmp/aegis-native-cmake \
  -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=/usr/bin/clang -DCMAKE_CXX_COMPILER=/usr/bin/clang++

.venv/bin/python - <<'PY'
import json, os
from pathlib import Path
os.umask(0o077)
source = Path('integrations/native_project/examples/owned').resolve()
manifest = json.loads((source / 'project.json').read_bytes())
manifest['project_root'] = str(source)
manifest['compile_database'] = '/tmp/aegis-native-cmake/compile_commands.json'
for unit in manifest['units']:
    unit.pop('arguments')
with Path('/tmp/aegis-native-cdb.json').open('x') as stream:
    json.dump(manifest, stream, indent=2)
PY

.venv/bin/python integrations/native_project/native_project.py build \
  /tmp/aegis-native-cdb.json --output /tmp/aegis-native-cdb-build \
  --plugin /tmp/aegis-shield-build/AegisShield.so --execute
```

The supported flag subset includes ordinary defines/includes, C/C++ standards,
warnings, debug levels, PIC/PIE, pthread, exception/RTTI switches, selected aliasing
and visibility switches, and function/data sections. See `normalize_flags` in
[workflow.py](workflow.py) for the exact allowlist. Optimization flags and output/
dependency bookkeeping are recorded and replaced, not replayed into the original
build directory. `-Ofast` is rejected because it changes language semantics.
Unknown flags, compiler plugins, response files, sanitizers, LTO, PCH/modules,
assembly, CUDA, cross-target and custom linker invocations are unsupported.
No unsupported option is silently discarded or retried as an unprotected unit.

For an existing project, use object-only mode first. Validate `protected.o` and
the report before integrating it into the original build. This tool does not
rewrite CMake/Ninja files or automatically discover/replay arbitrary link commands,
archives or generated-source steps. Configure/generate trusted projects first.

## Build and evidence model

For each declared unit the workflow:

1. Hashes the source and validates compile flags.
2. Compiles a normal source baseline with the requested optimization level.
3. Emits pre-optimization IR using `-O1 -Xclang -disable-llvm-passes` so eligible
   helpers survive to Shield without `optnone`.
4. Adds requested private IR selection and verifies it with plugin-free `opt`.
5. Compiles a matched unprotected IR baseline.
6. Invokes the production adapter with an unchanged `aegis.adapter.v1` request in
   its required job layout, supervises its process group, hashes the input and
   outputs, rechecks Mirage's chain if present, and verifies final IR again.
7. Compiles the selected output IR to a native object, validates ELF64 structure
   and compares exact function machine bytes against the matched baseline.
8. Optionally links three complete declared-unit executables: `native.elf`,
   `baseline.elf`, `protected.elf`. Runs compare exit code, stdout and stderr
   byte-for-byte for every declared case, in separate initially empty directories.

This is a separate protocol consumer, **not a Core job store**. Private
`adapter-jobs/<id>/` directories satisfy the adapter layout, but have no Core
`job.json`, signing hook, Sentinel policy or fabricated `EvidenceRecord`.
Adapter claims stay under `adapter_claims` and `adapter_reported_coverage` with
`source: "adapter"`. Native consumer observations include tool exits, execution
comparisons, ELF function bytes, artifact sizes and SHA-256 hashes.

`report.json` inventories all generated files, including bounded logs, intermediate
IR, local adapter reports and partial failures; `report.sha256` hashes the report.
`verify` rehashes the report and every inventoried file and rejects incomplete
inventories. These are unsigned consistency checks, not attestations against an
attacker who can rewrite the whole output directory. Report/artifact paths and
local reports can reveal function names; keep the directory private.

Coverage is per declared TU and per observed IR function, not lines or application
bytes. Included/template definitions can occur in several TUs. Database entry count
is recorded to show excluded work. A successful adapter report does not mean every
function transformed. Native observations distinguish different bytes, identical
bytes (e.g. optimized away), and unavailable/ambiguous symbols. Final Mirage symbol
presence is checked separately. Byte differences may include relocations and
layout effects; they are not a proof of the semantic form of an expansion or
reverse-engineering resistance. The module never claims entire-application
protection.

## Bounds and failures

All child launches use argv arrays, null stdin, a minimal environment and their
own process group. Environment includes only PATH, locale, and private HOME/TMPDIR.
Timeout, interruption and normal exit trigger process-group cleanup, including
descendants left behind by the leader. SIGTERM/SIGHUP are handled as interruption.
The adapter's LLVM children inherit its supervised group. This is for trusted
tools/programs, not containment against processes deliberately escaping the group.

| Limit | Default |
| --- | --- |
| Per command, including the whole adapter job | 60 seconds (`--timeout`, 1–3600); not a whole-workflow deadline |
| Source/generated input IR | 64 MiB (`--max-input-bytes`) |
| Accepted objects/binaries/output IR | 128 MiB (`--max-output-bytes`) |
| Diagnostic/execution stream | 64 KiB each |
| Child hard per-file ceiling | max(output limit, 4 MiB); polling/final checks enforce smaller limits |
| Manifest / compile database | 1 MiB / 16 MiB |

There is no aggregate disk, memory or CPU quota. A small file limit can be exceeded
briefly before polling, up to the hard ceiling. Mirage retains its own fixed
64 MiB module limit. Headers/libraries/tool binaries are not sealed; only the main
source and plugin receive before/after hash checks. No full dependency or source
provenance claim is made. Parallel hostile writers are outside the trust model.

Failed units remain explicit and do not register protected objects. Other declared
units are still attempted for a complete coverage report, but linking/execution
are withheld if any unit fails. A link or execution failure fails the build even
when adapter jobs succeeded. Partial private files remain inspectable. Invalid
manifests, unsafe/existing output directories and startup I/O failures return
structured errors before a build report can be created. Exit code is 0 for a
successful build/plan/hash verification, 1 for handled failure (argparse uses 2).
`verify` includes `build_status`, so verifying a failed run's file integrity never
turns that run into successful protection.

Notable error codes include `INCOMPATIBLE_UNIT`, `INCOMPATIBLE_SELECTION`,
`UNSUPPORTED_LLVM`, `TOOL_UNAVAILABLE`, `PLUGIN_UNAVAILABLE`, `INPUT_TOO_LARGE`,
`OUTPUT_TOO_LARGE`, `TIMEOUT`, `ADAPTER_TIMEOUT`, `TOOL_FAILED`, `EXECUTION_MISMATCH`,
`ARTIFACT_INTEGRITY_ERROR`, `UNSAFE_PATH`, and `INCOMPLETE_INVENTORY`. A handled
backend failure is `ADAPTER_FAILED`; its exact production code (including
`NO_TRANSFORMATIONS_APPLIED` or `MIRAGE_FAILED`) is preserved in
`details.adapter_error`. Nothing falls back to fake or unprotected success.

## Tests and evaluation handoff

```sh
.venv/bin/python -m pytest integrations/native_project/tests -q \
  -p no:cacheprovider --native-plugin /tmp/aegis-shield-build/AegisShield.so
```

Without `--native-plugin`, native integration cases are explicitly skipped and
must be reported as not run. With it, the real production adapters, installed LLVM
tools, CMake database and native execution cases run. No fake adapter establishes
success. Tests also cover invalid manifests/selections, unsupported flags, no-op
jobs, input/output limits, compiler errors, missing files/tools/plugin, unsafe
artifacts, altered hashes, execution mismatch, environment and group cleanup.

Fresh owned `baseline.elf` and the Shield/combined `protected.elf` artifacts can be
handed to the existing Lab production inference pipeline. Exact hashes, flags,
selection and adapter reports are in the native build reports. This module never
sends a provider request or compiles a generated candidate. The operator's
credential-enabled terminal owns single-use approvals and the shared $20 budget;
Claude owns baseline/Shield live experiments. Coordinate with the evaluation
owner before preparing duplicate requests. No reVC source, IR or derived artifact
was sent to a provider. Live model output without isolated behavioral scoring is
not an equivalence result or evidence of attack resistance.

## Excluding the module

This module adds no production entry point, package dependency or root CI/release
hook. Exclude the entire `integrations/native_project/` directory to remove the
optional workflow. Existing Shield, Mirage, Core, API and dashboard behavior is
unchanged by this task.
