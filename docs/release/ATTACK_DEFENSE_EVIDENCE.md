# AEGIS attack/defense evidence — blinded REA reverse-engineering trial (30 October 2026)

> **UNFINISHED HISTORICAL DRAFT — excluded from final experimental conclusions.**
> Placeholders below were never resolved by its author. Preserved for review,
> not certified as a completed trial. Current release conclusions and verified
> NVIDIA evidence are in [RELEASE_CONTENTS_READY.md](RELEASE_CONTENTS_READY.md).

VERDICT_PLACEHOLDER

All work ran on 30 October 2026, 08:04–END_TIME Toronto, on the host described in
[FULL_SYSTEM_VALIDATION.md](FULL_SYSTEM_VALIDATION.md) (Linux x86-64, Clang/LLVM 22.1.8,
Ghidra 12.1.4 + OpenJDK 21.0.12). Scratch and private material: `/tmp/aegis-ade` (0700
directories). No commit, push, publication, license edit, Nebius request, credential
access or reuse of an approval happened. The archived NVIDIA/Nebius experiment was not
touched.

## 1. Target and why

**Target:** `imagelab_color_adjust_pixel(uint32 rgba, uint32 saturation_q8, uint32 contrast_q8,
uint32 brightness_biased) -> uint32` in ImageLab's `imagelab-cli`, an AEGIS-owned C++
program. It is a pure function, so a reconstruction can be scored exactly against hidden
tests. Shield transforms it (24 of the kernel module's 43 sites), and the transformation
survives the `-O2` backend.

**Why not reVC:** reVC has no license ("We don't feel like we're in a position to give this
code a license"). Giving its code to an AI attacker would be third-party code disclosure,
and its game cannot be linked here (no GLFW) or run (no legal assets). reVC's transformed
functions were already shown equivalent in FULL_SYSTEM_VALIDATION §C2; they are not used here.

## 2. Artifacts (same source, same build configuration)

`kernels.input.ll` (SHA-256 `a2921c8e8bddc324334f3d32e0425a9ed79edf3f81cad04b0d13ff36da076138`)
is produced by ImageLab's own recipe (`clang++ -std=c++20 -O0 -Xclang -disable-O0-optnone`
then `opt -passes=function(sroa),verify`). Protected IR came from **real AEGIS Core jobs**
(signed workspace `/tmp/aegis-fsv/ws`, options `seed="42"`, `max-sites=64`):

| Variant | Core job | IR output SHA-256 |
| --- | --- | --- |
| Shield (`llvm-shield`) | `a6809b152fa649bbb56b9fb76b174413` | `protected.ll` `dd5d3c61b343bde0…` |
| Shield + Mirage (`llvm-shield-mirage`) | `1a2b83d2dafc4e7294d0fdd35f2c1100` | `protected.ll` `2f339866d3225fc1…`; `shield-stage.ll` identical to the Shield job's output |

All three executables were built by ImageLab's CMake with identical flags
(`-DCMAKE_BUILD_TYPE=Release -DIMAGELAB_ENABLE_IR_VARIANTS=ON`, backend `-O2`):
baseline = the `ir-baseline` variant (from unprotected `kernels.input.ll`), Shield and
Shield+Mirage = the `external` variant fed with the Core output.

```sh
cmake -S demo/image_processor -B /tmp/aegis-ade/build-<v> -G Ninja -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_BUILD_TYPE=Release -DIMAGELAB_ENABLE_IR_VARIANTS=ON \
  -DIMAGELAB_EXTERNAL_KERNELS_IR=/tmp/aegis-ade/build/kernels.<v>.ll
cmake --build /tmp/aegis-ade/build-<v> && ctest --test-dir /tmp/aegis-ade/build-<v>
```

| Final `imagelab-cli` | SHA-256 | File | `.text` | Target fn instructions | Decoys present |
| --- | --- | --- | --- | --- | --- |
| baseline | `f5090a8da14f21da10f1516184d51d9c6dc650861c618461a552f511b8f598df` | 62,096 B | 31,687 B | 135 | 0 |
| Shield | `8e76ecf4c6927e32e172c5824648f8c45540015139653a7cb9a6fc3802c5be2a` | 62,096 B | 31,834 B | 157 | 0 |
| Shield + Mirage | `b06fa4130d9492ac18df4ef169c56784ce8422c2630f66937551d0c4ebd42a90` | 62,264 B | 31,981 B | 157 | 3 |

The baseline is byte-identical across both build directories, and the baseline and
Shield+Mirage hashes equal the targets recorded in the archived NVIDIA experiment
(`artifact_sha256` `f5090a8d…` and the prepared Mirage continuation `b06fa413…`): the
ImageLab build is reproducible.

**Functional equivalence:** ImageLab CTest 11/11 in both build directories (unit and
reference tests for `ir-baseline` and `external`). On one 3000×3000 random image, `color`,
`tone` and `enhance` outputs are byte-identical across the three binaries (`color`
`05a62231…`, `tone` `dacae605…`, `enhance` `ea9411cc…`).
**Overhead:** `color` on that image, 7 runs: baseline 131–146 ms, Shield 132–163 ms,
Shield+Mirage 136–167 ms (I/O-dominated; no difference distinguishable from noise).
Size: Shield `.text` +147 B; Shield+Mirage `.text` +294 B, file +168 B.

## 3. Attacker setup (source-blind, comparable)

**REA:** official `morluto/rea` (MIT), npm package `rea-agents@6.8.0` (repository
`git+https://github.com/morluto/rea.git`; `npm audit signatures`: 39 packages with verified
attestations). Installed into `/tmp/aegis-ade/rea-install` with an isolated `HOME`, npm
cache and XDG dirs. `rea setup` was **not** run, so no agent or MCP configuration was
changed. REA 6.8.0 requires Node ≥22.23.4/24.22.1/26.12.1; the host has 26.8.1, so REA uses
the official Node v24.22.2 tarball (SHA-256 checked against nodejs.org `SHASUMS256.txt`)
in `/tmp/aegis-ade/node`. Launcher `/tmp/aegis-ade/rea.sh` sets
`GHIDRA_INSTALL_DIR=/home/youss/Applications/ghidra_12.1.4_PUBLIC`.
`rea doctor --provider ghidra --json` → `healthy: true` (Ghidra 12.1.4, native decompiler,
JDK 21.0.12).

**Blinding:** the three binaries were copied as `target` into `/tmp/aegis-ade/attack/W1..W3`
under a random permutation (`secrets.SystemRandom`), sealed in a 0600 key file until scoring.
During the trial, ImageLab's `kernels.cpp`, `kernels.h`, my build directories, final binaries
and hidden tests were `chmod 000`. Attackers were three fresh Claude agents (same model, no
shared context) with **identical** instructions differing only in workspace path: read only
their workspace; static analysis only (no execution of `target`, no compiling or running
anything); REA (`--provider ghidra`) plus `file/strings/readelf/llvm-nm/llvm-objdump`;
budget 30 REA calls and 25 minutes; goals (A) reconstruct `imagelab_color_adjust_pixel`
exactly as freestanding C, (B) triage up to 10 important functions with reachability.
They were not told about AEGIS, protection or variants.

**Hidden correctness tests and safe execution:** 128,672 cases (edge-value grid of 16 values
over the three parameters × 7 pixels, plus 100,000 seeded random cases, 10% with full-range
parameters), expected outputs from the trusted owned kernel compiled natively
(`cases.txt` SHA-256 `beffcfc25b798fc08497ce2b7b6b7878a4adf32466642905c5553095d20de948`).
Candidates are **never run on the host**: each is compiled freestanding to `wasm32`
(`-nostdlib -ffreestanding`, `wasm-ld` refuses undefined symbols), the module must declare
**zero imports** (checked before instantiation), and it runs in a Node worker with heap
limits and a 60 s timeout. Validation: the real kernel compiled the same way scores
128,672/128,672; a wrong candidate scores 5,883; a candidate calling `puts` does not compile.

RESULTS_PLACEHOLDER
