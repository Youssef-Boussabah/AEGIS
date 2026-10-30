# Demo video script and shot list — 2 minutes 55 seconds

Record the built dashboard on loopback from a **fresh workspace built from this
checkout** (`W=/tmp/aegis-demo-…`; see [INSTALL.md](INSTALL.md)). Use real captured
jobs and reports. Do not show tokens, private archives, model requests, hidden
suites, decoy names or function-detail reports in the public recording. No video
file is claimed by this script; recording and editing are operator tasks.

## Before recording

1. `product.py build`, `configure` (both probes pass), `verify` → all green.
2. `product.py serve --workspace $W`; in a second terminal keep the repository root open.
3. Prepare the ImageLab Shield+Mirage build and comparison from
   [NATIVE_INTEGRATION.md](NATIVE_INTEGRATION.md#imagelab-with-shield--mirage) so the
   terminal shots replay real output (do not fake terminal text).
4. Generate fresh research summary exports (RUNBOOK) and copy their printed digests.

## Shot list (2 minutes 55 seconds)

| Time | Shot / action | Narration |
| --- | --- | --- |
| 0:00–0:15 | Dashboard overview and real backend readiness | “AEGIS makes compiler transformations and their evidence inspectable. This local preview accepts trusted textual LLVM 22 IR on Linux.” |
| 0:15–0:45 | Protect LLVM IR → owned `$W/annotated.ll` → Shield + Mirage profile → submit → terminal result | “The registered backend runs Shield, then Mirage on the verified Shield output. Core hashes every output. These four artifacts expose the whole chain.” |
| 0:45–1:00 | Input/output hashes, transformation claim, limitations | “Shield rewrites arithmetic; Mirage adds uncalled decoys. Transformation and retention do not establish attack resistance.” |
| 1:00–1:15 | Load a captured real invalid-IR job and its explicit error | “Invalid input fails with an error report and no outputs. Failure is never displayed as protection.” |
| 1:15–1:40 | Verify artifact: signed fixture job, fresh verification, Sentinel deny/permit | “With an operator-provided key, outputs are signed before completion. Verification checks current bytes. Sentinel gates cooperating downloads; it cannot control outside tools. Default demo jobs are unsigned until signing is configured.” |
| 1:40–2:20 | Exact signed job, approved runtime command and genuine NVIDIA summary | “This workflow sends fresh Ghidra evidence to NVIDIA Nemotron through Nebius Token Factory. Single-use approval binds the model, request and limits. The report records the actual response and token usage. Generation remains separate from validated behavioral scoring.” |
| 2:20–2:40 | Actual ImageLab/native gate output; show final linked decoy count with names blurred | “Our owned-program tests check matching outputs and final-link retention under the tested LLVM 22 configuration. They are regression results, not a security score.” |
| 2:40–2:55 | Final report, strict gate summary and review-package inventory | “The source and frontend rebuild locally, with a strict verification gate and per-file digests. The team approved MIT; publication of the final release still requires owner approval.” |

Before the signing shot, configure a separate private demo key and workspace using
[FINAL_API_CONTRACT.md](FINAL_API_CONTRACT.md); do not show private paths or keys.
If signing is not configured, show **Not signed** and omit the signed-success shot.
Import only the public projection identified in [NVIDIA_NEBIUS.md](NVIDIA_NEBIUS.md),
not private archives or synthetic fixtures presented as observed results.

If any step is unavailable on recording day, state that and omit its success shot.
Use [RELEASE_CONTENTS_READY.md](RELEASE_CONTENTS_READY.md) for current gate counts and
[the final NVIDIA record](../../benchmarks/reconstruction/NVIDIA_DEMO.md) for the actual inference result.
No recording, editing, video upload or Devpost publication was performed by this task.
