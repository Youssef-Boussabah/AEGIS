# Devpost submission copy — final operator review

**AEGIS — native transformation, verifiable artifacts, honest reconstruction research**

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

## License and public links

Standard MIT License, copyright 2026 Youssef Bossabah, Karim Lahyani, Nevan Vu,
and Riche Anyadike; the operator confirmed all four contributors' approval.
Third-party notices remain independent. Publishing the final contents still
requires separate operator approval.

- Source: https://github.com/Youssef-Boussabah/AEGIS — final approved revision/tag needed.
- Test build: approved release asset URL needed; local source/test-build is not a public download.
- Integrity: final detached SHA256SUMS URL needed.
- Video: record the existing 165-second script; approved video URL needed.
- Devpost/event URL and submission confirmation: operator to supply.

Use [the release review](RELEASE_CONTENTS_READY.md), [install guide](INSTALL.md),
[runtime guide](JUDGE_RUNTIME_INFERENCE.md), [system results](FINAL_SYSTEM_TEST.md)
and [video script](HACKATHON_SUBMISSION_READY.md#video-recording-script--165-seconds).
No localhost address is a public demo link. Verify organizer/track requirements
before submitting; eligibility has not been asserted by the engineering tests.
