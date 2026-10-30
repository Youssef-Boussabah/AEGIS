# Install and test AEGIS (for judges and reviewers)

This builds everything from source on your own machine and runs it on loopback
only. Nothing is installed system-wide, no account or API key is needed, and the default local demonstration makes no cloud inference request. Optional live
Lab inference is separate and requires explicit operator approval. Time was not measured
from a clean machine; most of it is dependency download and the native build.

The release review identifies the exact approved archive and detached checksum.
It is a **source/test-build archive with bundled dashboard**, not a standalone
native installer. Native components are rebuilt against your matching LLVM 22.
Current review and clean-install receipt: [RELEASE_CONTENTS_READY.md](RELEASE_CONTENTS_READY.md).

## What is actually supported

| Item | Status |
| --- | --- |
| Host OS | **Linux x86-64**: built and tested (CachyOS, kernel 7.2, glibc 2.44). Other Linux distributions with the same tools should work but were not tested. macOS and Windows: **not supported** (Mirage needs ELF section retention; nothing was tested there). |
| Input | **Textual LLVM 22 IR** (`.ll`) for the host target, for example from `clang -S -emit-llvm`. Tested inputs: C (owned fixtures), C++ (ImageLab kernels; reVC/librw translation units) and Rust 1.98.1 pre-optimization IR from two PhotoCraft crates (see [FULL_SYSTEM_VALIDATION.md](FULL_SYSTEM_VALIDATION.md)). Shield only changes functions explicitly marked `aegis.protect`; Rust has no source annotation, so a separate marking step is required. Other LLVM front ends (Swift, …) were not tested. |
| Protection backends | `llvm-shield` (LLVM pass plugin) and `llvm-shield-mirage` (Shield, then retained decoy functions). Both are registered only after a real probe job succeeds. |
| Final binaries | ELF executables linked by the operator's own build. Decoy retention was checked after `-O2` and `--gc-sections` for two owned programs only. |
| Not supported | Native executables or bitcode as input, websites, mobile apps, consoles, other LLVM major versions, Go and JavaScript/TypeScript (Mattermost: no LLVM IR stage, unsupported). PhotoCraft and reVC are supported only at component level (individual crates / translation units through a manual IR pipeline), not as whole applications; see [FULL_SYSTEM_VALIDATION.md](FULL_SYSTEM_VALIDATION.md). |
| Security | **No established security property.** Changed IR, changed machine code, matching outputs and retained decoys are not evidence of attack resistance. |

## Requirements

Install these with your system's package manager first (the AEGIS scripts never
install system packages and never use `sudo`):

- Python ≥ 3.11 and [uv](https://docs.astral.sh/uv/)
- Node.js ≥ 22.18 and npm
- LLVM/Clang **22.x**, all from the same installation: `llvm-config`, `clang`,
  `clang++`, `opt`, `llvm-link`, `llvm-nm`. Check that
  `llvm-config --version`, `clang --version`, `opt --version` and
  `llvm-link --version` all report 22.x. For a versioned install, put its `bin`
  directory first on `PATH`.
- CMake ≥ 3.20 and Ninja
- Disk, measured on the tested host: `.venv` 45 MB, dashboard `node_modules` 121 MB,
  workspace builds under 10 MB, Chromium for the optional browser test 681 MB

Tested toolchain: Python 3.14.7, Node 26.8.1, npm 12.0.2, LLVM/Clang 22.1.8, CMake
4.4.3, Ninja 1.13.2. A fresh extracted-package installation also selected and
tested CPython 3.13.15 with the existing uv cache. Python 3.11 is the declared
minimum, not a platform/version matrix independently validated in this release.

## Build and run

From the extracted package (`aegis/`) or a checkout, at its root:

```sh
sh scripts/setup-python.sh
uv pip install --python .venv/bin/python -c core/requirements-dev.lock \
  -e './attack_lab[dev]' -e ./protectors/mirage
npm --prefix platform/dashboard ci

W=/tmp/aegis-review          # any new directory outside the source tree
.venv/bin/python scripts/product.py build     --workspace $W
.venv/bin/python scripts/product.py configure --workspace $W
.venv/bin/python scripts/product.py serve     --workspace $W
```

`configure` should print `Probe passed: llvm-shield` and
`Probe passed: llvm-shield-mirage`. `serve` prints the dashboard URL once it is
ready (default `http://127.0.0.1:5173`; API on 8000). If those ports are busy, add
`--api-port 8100 --dashboard-port 5273` to `serve`, `smoke` and `verify`.

## Try it

1. Open the dashboard → **Protect LLVM IR** → choose `$W/annotated.ll` → **Submit**.
   Expect `succeeded`, "1 transformed sites", input/output SHA-256 digests and a
   limitations list.
2. In a second terminal: `.venv/bin/python scripts/product.py smoke --workspace $W`.
   It runs a real job on each registered backend through the dashboard proxy and
   re-hashes every output against Core's records.
3. Shield + Mirage from the CLI:

   ```sh
   AEGIS_CONFIG=$W/aegis.toml .venv/bin/python -m aegis_cli protect $W/annotated.ll \
     --backend llvm-shield-mirage --option 'seed="42"' --json
   ```

   The seed needs the inner quotes (it is a decimal string). On the tested
   toolchain the outputs are deterministic: `shield-stage.ll`
   `4a7da8c1…949d68a9a`, `protected.ll` `0fc986a8…460116b42`.
4. A failure stays a failure: submit a file containing `not IR` as `bad.ll`, or
   add `--option enabled=false`; both fail with a named error and no outputs.

## Run the full test gate (optional)

Stop `serve` first (or use other ports), then:

```sh
PLAYWRIGHT_BROWSERS_PATH=/tmp/aegis-browsers \
  npm --prefix platform/dashboard exec -- playwright install chromium   # downloads Chromium
PLAYWRIGHT_BROWSERS_PATH=/tmp/aegis-browsers \
  .venv/bin/python scripts/product.py verify --workspace $W
```

For the release gate, also install Ghidra 12.1.4 with JDK 21+ explicitly and run:

```sh
AEGIS_GHIDRA_HEADLESS=/absolute/ghidra/support/analyzeHeadless \
PLAYWRIGHT_BROWSERS_PATH=/tmp/aegis-browsers \
  .venv/bin/python scripts/product.py verify --workspace "$W" --lab-profile integration
```

This runs the Python suites (Core, API, CLI, Provenance, Sentinel, both real
adapters, product scripts), Shield and ImageLab CTest, Mirage, native final-link
tests, the offline Lab suite, frontend checks, a production build and the real
browser suite. The strict integration profile refuses missing prerequisites and any skips. The
default offline profile reports omitted Ghidra cases as NOT RUN and is insufficient
for final release certification. Current results and package verification are in
[FINAL_RELEASE_REPORT.md](FINAL_RELEASE_REPORT.md); older native measurements
remain in [NATIVE_INTEGRATION.md](NATIVE_INTEGRATION.md).

## Verify an extracted review package

Compare the archive SHA-256 with the separately delivered release report, inspect
its member names, and extract into a **new private directory**. From `aegis/`, run
`python3 scripts/product.py check-package` before installing anything. It validates
every inventoried file digest and rejects missing, changed, unlisted or symlink
files. The inventory is an integrity check, not a publisher signature. Install
repository-local dependencies and build native components using the steps above;
no plugin, virtualenv, node_modules, private evidence or signing key ships.

The dashboard build is included, but Vite preview still requires local Node
packages. Third-party notices accompany the bundled frontend. The root LICENSE
is the standard MIT License, approved by all four named contributors on
30 October 2026. The review archive is prepared locally; publication requires
separate operator approval.

## Clean up

Stop `serve` with Ctrl-C and delete `$W`. Nothing else was written outside the
source tree except the optional Chromium download directory.
