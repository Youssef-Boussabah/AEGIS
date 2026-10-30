# Real NVIDIA demonstration — 30 October 2026

This record distinguishes completed real operations from pending operator work.
It does not substitute synthetic candidates or test providers for inference.
No API key was requested, read or exposed by the evaluation agent.

## Verified preparation and output-control fix

The pre-existing 16,384-token diagnostic at
`/home/youss/aegis-system-test-scratch-20261030/integration/nemotron-prepared`
was inspected read-only. Exact ELF, manifest, Ghidra and request-review hashes
match its binding. It targets the signed Core job
`8d58153ea13743eeaa04a18f4b1fb923`, combined backend, owned
`imagelab_color_adjust_pixel`. Both original approval booleans are false.
The original diagnostic and historical archives remain unchanged.

The earlier two actual NVIDIA requests finished with `length`, not `stop`, and
their visible content was invalid JSON. The baseline reported 9978 total tokens
and estimated 2074 micro-USD; Shield reported 10136 and 2083 micro-USD. Their
11-file archives were independently verified before/after with identical hashes.
Neither produced an accepted candidate. Reasoning metadata was null in those two
responses; the compatibility parser alone cannot fix truncated visible text.

Nebius's own [deployment verification](https://raw.githubusercontent.com/nebius/nebius-physical-ai/main/docs/workbench/token-factory-deprecation-verification.md)
reports that `chat_template_kwargs.enable_thinking=false` worked for the exact
`nvidia/Nemotron-3_5-Lightning` model. This supports an explicit prospective
diagnostic, not a claim that our account has already honored the flag.

The narrow fix adds a strict optional `enable_thinking` request field and
`--disable-thinking` to controlled Lab draft/preflight/run. The wire control is
bound into the sampling digest, reviewed body and archived requests. Omission
preserves old wire bodies and identities. Replay verification reconstructs the
recorded option; a changed option without matching manifest/approval fails.
No `length`/JSON/envelope/model checks or single-use safeguards were weakened.

Implementation was frozen at 11:15 AM Toronto. Regression results:

| Check | Result |
| --- | --- |
| Focused Lab/provider/reconstruction tests | 484 passed, 27.07 s |
| Full strict Lab with real Ghidra, outside sandbox | 2117 passed, 0 skipped/warnings, 169.82 s |
| Benchmark/import tests | 79 passed, 0 skipped/warnings, 2.051 s |
| Existing two genuine archives | Verified immutable, 11 files each |

The initial strict run inside the sandbox had 2116 passed and one Unix-socket
test not run; strict mode correctly failed. The authorized unrestricted rerun
exercised that test and passed without skips. Unit tests establish implementation
behavior only; no simulated generation is presented as actual inference.

## Exact one-shot operator commands

A new, deliberately unapproved preparation is at
`/tmp/aegis-nvidia-demo-nothinking-20261030`. Only one protected POST is proposed.
Its protected artifact SHA-256 is
`b06fa4130d9492ac18df4ef169c56784ce8422c2630f66937551d0c4ebd42a90`;
manifest SHA-256 is
`bbef54f49aea6b8ff4669b9c0a888b870203d93086016bf10945616a9c7f0450`;
request-review SHA-256 is
`17272c5d79ad088a75c604284591b198ed3f76c7d83142b45b7775122f99a0ed`.
The exact body sets thinking false and both completion caps to 16384. Existing
real Ghidra evidence and the original protected binary are reused by exact hash.

The operator runs these **once** in the existing credential-enabled Fish terminal:

```fish
cd /home/youss/Projects/aegis

.venv/bin/python scripts/live_evaluate.py approve \
  --workdir /tmp/aegis-nvidia-demo-nothinking-20261030 \
  --target protected \
  --budget-ledger /tmp/aegis-nv/nvidia-budget-ledger.jsonl

.venv/bin/python scripts/live_evaluate.py run \
  --workdir /tmp/aegis-nvidia-demo-nothinking-20261030 \
  --target protected --use-environment-credential \
  --max-output-tokens 16384 --disable-thinking \
  --budget-ledger /tmp/aegis-nv/nvidia-budget-ledger.jsonl
```

Approval is interactive and requires exact request/artifact/retention review.
Limits: one request, 120-second request timeout, $0.10 ceiling and a conservative
$0.066847 reservation at the proposed price caps. The runner rechecks account
availability and catalogue/prices before POST. A reservation is not an invoice.
The existing ledger reported 387812 micro-USD committed before this request;
shared accounting remains operator owned. No automatic retry or candidate
execution is authorized by these commands. The operator subsequently executed
the one approved protected request; its actual result is verified below.

## Genuine new NVIDIA result: candidate generation succeeded

The operator's completed archive is
`/tmp/aegis-nvidia-demo-nothinking-20261030/live-protected-20261030T152350Z`.
`verify_experiment` independently checked the complete private request/response,
approval, model/catalogue, artifact, Ghidra, manifest, workflow and usage bindings.
All **12 archive files** were unchanged before/after verification. Experiment
JSON SHA-256 is
`6165bf2a322ab6dd4945a3b764aba9c217b0ad0cd74177dac1e9882c6cd83ad5`.

| Actual observation | Verified value |
| --- | --- |
| Requested and reported model | `nvidia/Nemotron-3_5-Lightning` |
| Actual saved request | `chat_template_kwargs.enable_thinking=false`; 16384 completion caps |
| Finish reason | `stop` |
| Generation status | `generated_but_behaviorally_unscored` |
| Provider-reported reasoning tokens | 0 |
| Provider-reported usage | 1944 prompt + 1585 completion = **3529 total** |
| Approved-price estimate | **498 micro-USD = $0.000498**, not an invoice |
| Conservative reservation | **66847 micro-USD = $0.066847** |
| Candidate size | 2506 exact UTF-8 bytes |
| Candidate SHA-256 | `aa69bc31ed70a18a49f9e5a7a1170a05b909982db4075d00359e0e906e2eddff` |
| Target final ELF SHA-256 | `b06fa4130d9492ac18df4ef169c56784ce8422c2630f66937551d0c4ebd42a90` |
| Candidate compilation/execution | **Not performed** |
| Behavioral correctness / attack resistance | **Not established** |

The candidate was read only to recompute its hash and verify the archived
envelope. No source correction, replacement candidate, truncation recovery or
simulated provider output was substituted. The actual source declares `opaque`,
matching the archived interface; this observation is not C compilation or a
behavioral score. No further paid inference is authorized.

The strict privacy-filtered public export is
`/tmp/aegis-nvidia-demo-verified-public-summary.json`, exact SHA-256
`9006046db669414bcbac7847dd55f2bf43f497cb48c2aaa0f0ca030fc44b2f91`.
It contains no raw prompt, reasoning, candidate source, approval or credential.
Raw files remain outside the repository. Provider identity, reasoning counts,
usage and billing estimates remain provider/local records, not independently
attested weights or an invoice.

## Real browser journey completed so far

A separate actual API/dashboard was configured through successful real Shield
and combined probes at API port **21410**, dashboard **21483**, workspace
`/tmp/aegis-nvidia-demo-ui-20261030`. Playwright used installed Chromium and the
real API, with no mocked protection or research responses.

The user journey uploaded the exact owned ImageLab input
`a2921c8e8bddc324334f3d32e0425a9ed79edf3f81cad04b0d13ff36da076138`,
selected Shield+Mirage and submitted a real successful job
`ee504e102b19479a9ceb3730092e2c44`. Every output was independently hashed against
Core's record. The verification page correctly showed unsigned outputs in this
separate unsigned workspace. The genuine earlier 10136-token NVIDIA public
summary was hash checked and imported, displayed as `invalid_output`, with its
actual model and artifact digest. Desktop, mobile layout and Results passed;
the evidence import made **zero POSTs**. Screenshots and machine results are in
`/tmp/aegis-nvidia-demo-browser-before-complete/`.

This browser job is **not** silently equated with the paid diagnostic: the UI
hardcodes max-sites 16, while the prepared signed job used 64, and their protected
IR hashes differ. The actual diagnostic remains bound to its own signed job and
final ELF. The same-session UI has no automatic LLVM-IR-to-linked-ELF research
binding. Loading the exact existing diagnostic job is a separate user action;
standalone Research import does not manufacture that missing association.

An initial browser harness used a relative API URL without a configured base URL;
that automation error was fixed only in its private `/tmp` driver. The subsequent
complete journey passed. No product behavior was changed to accommodate the test.

The exact prepared signed job was then loaded in a separate actual API/dashboard
at ports **21411/21484**, using its existing configuration and store. Playwright
loaded job `8d58153ea13743eeaa04a18f4b1fb923`, confirmed max-sites 64 and the
combined backend, verified **all four artifact signatures**, and downloaded
`protected.ll` through the UI. The download SHA-256 exactly matched
`2f339866d3225fc1ff6e765ebd1eb78deb681f2fadfb6728917c9fc189e4079a`.
The existing job walkthrough made **zero POSTs** and did not read a private key;
the configured application performed its normal verification. Screenshots and
machine results are in `/tmp/aegis-nvidia-demo-exact-job-before/`. This closes the
user-facing job selection/verification step without falsely equating the earlier
16-site upload with the 64-site diagnostic. The final linked ELF remains separately
bound by the diagnostic's build/Ghidra records; the dashboard does not automatically
derive that IR-to-ELF link.

After the genuine request completed, Playwright repeated the exact signed-job
verification/download and imported the **new actual candidate-generation summary**
by its verified SHA-256. It confirmed the exact target ELF, candidate digest,
requested/reported NVIDIA model, 3529 reported tokens, and
`generated_but_behaviorally_unscored` state. Desktop, 390-pixel mobile layout and
Results display passed. The complete existing-job/evidence walkthrough made
**zero POSTs**, including zero evidence-upload or inference requests. Actual
screenshots and `result.json` are in
`/tmp/aegis-nvidia-demo-exact-job-real-result/`. The UI correctly retains the
unscored state; no behavioral result or protection effect was invented.

## Scoring and adaptive connection blockers

Core's candidate isolation is not validated and refuses real execution. The
standalone experimental Wasm scorer is not an approved boundary: its host compiler
and Wasm resource controls do not establish the required containment. Therefore
no generated candidate is compiled or executed by this demonstration. A valid
candidate envelope would still be **behaviorally unscored**, not reconstructed.
This prevents claiming a fully behavior-scored end-to-end demonstration today.

The adaptive workflow can import a verified production generation archive as an
**unscored** receipt. It cannot turn generation or parser acceptance into a
behavioral score. Its fixed owned `signal_mix` target is different from ImageLab;
an ImageLab artifact hash must remain unmatched and cannot influence a signal
candidate's resistance or selection. Direct REA execution and a general
ImageLab-to-adaptive behavioral-feedback connection are not implemented.

Only safe public summaries may be imported into the dashboard. Raw prompts,
reasoning, candidates, approvals, reservation state and private archives remain
outside the repository and browser. No paid request was initiated by the agent.
