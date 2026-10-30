# Demo video script — 2 minutes 45 seconds

Record the built dashboard on loopback with a prepared LLVM 22 build and owned
fixture. Use real captured jobs and reports. Do not show tokens, private archives,
model requests, hidden suites or function-detail reports in the public recording.
No video file is claimed by this script; recording/editing is an operator task.

| Time | Shot / action | Narration |
| --- | --- | --- |
| 0:00–0:15 | Overview, visible research-preview badge and backend readiness | “AEGIS is a local research workspace for software transformation and evaluation. Today’s supported backend takes textual LLVM 22 IR. We track what ran and what the result does—and does not—show.” |
| 0:15–0:35 | Protect LLVM IR, select `/tmp/aegis-product/annotated.ll`; briefly show its checked-in fixture path in terminal | “This is our owned annotated fixture, compiled with LLVM 22. The dashboard submits a real protection job through the Core API to the existing Shield adapter.” |
| 0:35–1:00 | Submit once; capture pending/running if visible; show real succeeded state and report | “Core records the job lifecycle and hashes the input and outputs. Here Shield reports one transformed arithmetic site. Adapter claims and Core observations are labeled separately.” |
| 1:00–1:20 | Scroll through SHA-256s and limitations; download report, keep content private | “A completed transformation is not proof of security. This report does not establish attack resistance, and later compiler optimization may undo a rewrite. The report remains available by this job ID.” |
| 1:20–1:35 | Submit deliberately invalid `.ll`; show failed state and error code | “Failures stay failures. Invalid IR produces an explicit adapter error and no registered output artifacts.” |
| 1:35–1:55 | ImageLab CTest terminal and locally loaded quick benchmark summary with conditions | “Our owned ImageLab compares native, IR baseline and Shield variants against reference tests. These are sampled correctness checks and local measurements, not a general performance or security guarantee.” |
| 1:55–2:20 | Research evidence; import a real verified local reconstruction export and Mirage export, matching terminal digests | “The Lab archive verifier exports only safe summary fields. These reconstruction candidates come from a scripted offline provider and remain behaviorally unscored. Mirage inserts decoy functions; retention is checked separately. No live attack-resistance result is claimed.” |
| 2:20–2:35 | Capabilities matrix, focus on provider and unsupported backends | “Nebius transport is offline-tested. No live NVIDIA model or GPU run has been verified. Websites, arbitrary binaries and consoles require future backends.” |
| 2:35–2:45 | Runbook, test command and local package filename | “The source, built dashboard, file-digest inventory and exact local runbook form a testable review package. The next milestones are merged Core scoring, authorized live evaluation and measured results.” |

Before recording, run `product.py verify`, generate fresh local summary exports
and copy their printed digests. Avoid editing out failures in a way that implies
a failed job succeeded. If a step is unavailable, state that and omit its success
shot. Use [validation](VALIDATION.md) for actual counts, not historical baselines.
