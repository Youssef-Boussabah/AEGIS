# AEGIS hackathon submission readiness — 30 October 2026

**Supported integration gate passed; public submission awaits operator approval,
asset/video publication and final URLs.** The approved MIT license is finalized.
Read [the exact final release review](RELEASE_CONTENTS_READY.md) and detached
archive receipt for the final bytes and fresh-install results. Target readiness
11:40 EDT; engineering cutoff noon; submission deadline 13:00 EDT.

## Completed scope, platforms and real-software results

The final review records real protection jobs, checked artifacts, Ed25519 signing,
Sentinel decisions, Ghidra and runtime inference. It includes independently tested
reVC/librw components, PhotoCraft's passing color path and failing Algo path,
Mattermost's unsupported protection paths, and the adaptive selector's actual
cost/correctness evidence. Linux x86-64 with matching LLVM 22 is supported;
whole-game, arbitrary-binary and cross-platform support are not claimed.
Attack resistance remains UNMEASURED and generated candidates behaviorally
unscored. Exact scope/results: [final review](RELEASE_CONTENTS_READY.md).

## Nebius/NVIDIA runtime and reproducible demo

[JUDGE_RUNTIME_INFERENCE.md](JUDGE_RUNTIME_INFERENCE.md) supplies a fresh-owned-input
build and real `aegis_lab.live` draft/preflight/run commands. The production
provider sends HTTPS requests to Nebius Token Factory using
`nvidia/Nemotron-3_5-Lightning`. Judges use their own credentials and independently
approve disclosure, retention, exact request hashes and spend/token/time limits.
The optional no-thinking setting is included in request/hash bindings; an older
approval cannot authorize a changed setting. A dashboard summary import is offline.
[Codex 4's final runtime record](../../benchmarks/reconstruction/NVIDIA_DEMO.md)
records the genuine operator call, usage, estimated cost and signed-job browser
walkthrough. Private requests/responses/candidates are excluded from release.

## Test build, installation and public links

The local approval packet is `build-release-candidate-20261030/`; its archive,
SHA256SUMS and detached receipt identify exact reviewed bytes. Follow
[INSTALL.md](INSTALL.md) inside a fresh extraction, first run
`python3 scripts/product.py check-package`, then create local dependencies/builds
and fresh signing keys. Seven independent package imports, native builds,
backend probes and real Chromium workflows are verified in the detached receipt.
Cached installs do not certify a cold network machine. No private key is needed.

Public links still needed: approved revision/tag; downloadable test-build asset;
SHA256SUMS asset; recorded video; Devpost event/project/submission confirmation.
The repository is https://github.com/Youssef-Boussabah/AEGIS. No localhost URL is
presented as a public demo. A source/test-build bundle is not a native installer.
MIT adoption is approved for all four named contributors; publication remains
separately blocked on operator review. [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
retains external licenses. Current-source and archive scans are bounded and do
not inspect credentials or private inference artifacts.

## Devpost submission description

## Inspiration

A changed binary is not proof of protection. We built AEGIS to connect real
compiler transformations with evidence a reviewer can inspect: what ran, which
bytes shipped, whether behavior still matches, and what an attack actually found.

## What it does

AEGIS accepts owned LLVM 22 IR through a React dashboard, local API or CLI.
Shield rewrites eligible integer additions; Mirage adds retained arithmetic
decoys. Core tracks real jobs and errors and computes artifact SHA-256. Optional
Ed25519 signatures verify exact output bytes. Sentinel applies declared rights
in cooperating tools, including artifact download decisions.

Optional native C/C++ and Rust component workflows compile trusted source,
protect eligible IR, relink and compare actual native outcomes. An experimental
bounded controller selects configurations using observed correctness, retention,
size and process timing. Its resistance remains UNMEASURED: cost feedback is not
an autonomous proof of attack resistance.

## NVIDIA and Nebius integration

The application workflow binds a real signed Core job to fresh native artifacts,
Ghidra decompilation and an operator-approved NVIDIA Nemotron request through
Nebius Token Factory. The exact model is `nvidia/Nemotron-3_5-Lightning`.
Credentials stay in the operator runtime. Single-use approvals bind disclosure,
model, parameters, token/spending limits and retention. Inference-only approval
never compiles or executes returned candidates. Judges can prepare fresh owned
inputs and reproduce the runtime CLI with their own approved account.

The final operator-run request explicitly disabled thinking and returned an
accepted candidate envelope: 1,944 prompt + 1,585 completion = **3,529 tokens**,
`finish_reason=stop`, with estimated cost **$0.000498**. Its immutable archive
was independently verified. The candidate remains **behaviorally unscored**;
no correctness or protective benefit is inferred from generation.
Earlier baseline/Shield calls hit their 8,192-token caps and remain invalid_output
(9,978/10,136 tokens; combined estimate $0.004157). These are usage estimates,
not invoices. Dashboard imports are evidence display, not model requests.

## What we demonstrated

- Real Core/API/CLI/dashboard jobs, signed outputs, cooperating Sentinel decisions
  and hash-checked downloads, including failure/tampering paths in Chromium.
- reVC/librw: a fresh baseline compiles 293/308 TUs; selected 20 TUs protected with
  each backend. Bounded comparisons of 13 function instances found zero mismatches;
  a real linked Darkel component also passed. The game was not linked or run.
- PhotoCraft: color passes 30/30 through both backends. Algo matched/protected
  outcomes remain 726 pass, 1 upstream failure and 27 ignored; the workflow
  truthfully reports failure rather than hiding that baseline problem.
- Mattermost builds unprotected; its Go/TypeScript protection is explicitly
  unsupported. Real Ghidra analysis completed for baseline/protected owned targets.

These are component and finite-test results, not whole-application support or
an established security property. Third-party research artifacts remain private.

## How we built it and what is next

C++/LLVM 22 passes, Python/Pydantic subprocess contracts, FastAPI, React/TypeScript,
Ghidra, Ed25519 and Nebius Token Factory form the workflow. The main challenges
were preserving exact artifact bindings, separating model transport from candidate
correctness, and keeping failures and authorization boundaries explicit.

Next: validated isolated candidate scoring, independent held-out attack evidence,
and broader application build integration. Supported release scope is Linux
x86-64 with matching LLVM 22, not arbitrary binaries, Windows/macOS or web/mobile.


## Specific feedback for Nebius and NVIDIA

- Token Factory's OpenAI-compatible HTTPS transport fits a hash-bound research
  workflow. Per-response model identity and token usage support auditable records.
- For this exact Nemotron model, document `chat_template_kwargs.enable_thinking`
  beside structured-output examples, including how reasoning consumes completion
  limits. Our two 8,192-token-cap requests truncated before valid candidate JSON.
- Expose consistent machine-readable context/pricing limits and clarify token
  accounting, reasoning visibility and retention. Our estimates are not invoices.
- We need reliable structured candidate output and explicit truncation diagnostics;
  valid JSON alone still requires independent isolated behavioral evaluation.

## Video recording script — 165 seconds

Use actual captured jobs, no credential/prompt/candidate/private-path shots.
Record a fresh local dashboard; public video hosting is a separate operator step.

| Time | Shot | Narration |
| --- | --- | --- |
| 0:00–0:15 | Dashboard and real backend readiness | “AEGIS connects native software transformations to evidence you can inspect. This Linux preview accepts trusted LLVM 22 IR.” |
| 0:15–0:45 | Submit owned IR to Shield+Mirage; show real completion | “Shield transforms eligible integer additions. Mirage adds retained decoys. Core runs the real pipeline and hashes each artifact.” |
| 0:45–1:05 | Inspect hashes, download, then show invalid-input failure | “Downloads match the recorded bytes. Invalid input returns an explicit failed job. Changed code and matching outputs are not a security score.” |
| 1:05–1:30 | Signed job and Sentinel permit/deny; tamper rejection | “A configured identity signs outputs. Verification checks current bytes. Sentinel enforces declared rights in cooperating downloads; a valid signature and permission are separate decisions.” |
| 1:30–2:00 | Exact signed job, runtime command, verified NVIDIA summary | “Our application binds fresh artifacts and Ghidra evidence to an approved NVIDIA Nemotron request through Nebius Token Factory. The operator uses their own account and bounded single-use approval. This report shows the actual response and usage. Generation does not establish candidate correctness, and inference approval never executes candidate code.” |
| 2:00–2:25 | Real-software result table and limitations | “Selected reVC components and PhotoCraft color pass finite native comparisons. PhotoCraft Algo retains an upstream failure; Mattermost protection is unsupported. We report those limits directly.” |
| 2:25–2:45 | Final gate and downloadable approved release frame | “The combined integration gate passes, including real signing, Sentinel and browser workflows. The team approved MIT. Use the published source/test-build, checksum and install guide to reproduce the supported scope.” |

Replace the last frame's URLs only with actual approved public assets. Before
recording the NVIDIA shot, reconcile its narration with the final verified
[NVIDIA_DEMO.md](../../benchmarks/reconstruction/NVIDIA_DEMO.md). Do not label a
pending, truncated or unscored result as successful reconstruction.
