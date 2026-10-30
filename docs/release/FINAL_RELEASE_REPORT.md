# AEGIS final release engineering report — 30 October 2026

**Release state: ready for owner review; complete local gate passed.** The
operator confirmed Agent 1 finished and explicitly authorized Agent 4's repair
of the newly discovered signing-key ancestry bug. The corrected implementation
passed the final strict gate with zero skips. License adoption, public assets and
publication still require operator action.
No commit, push, history rewrite, deployment, video upload, Devpost submission,
live inference request or credit spending was performed by this release task.

Submission deadline supplied by the operator: **30 October 2026, 13:00 Toronto
(17:00 UTC)**. This report does not assert organizer eligibility or a public URL.

## Scope, ownership and inspected changes

Checkout: `dev/integration`, HEAD `691ce2717934c22dd30883b5dd8a586ebf78bf20`, with
uncommitted changes from all workstreams. Git HEAD alone does not identify this
release. [CHANGED_FILES.md](CHANGED_FILES.md) lists every modified/untracked file
that must be reviewed for the final commit, including all new source/tests/assets.
The package's `RELEASE-MANIFEST.json` binds each distributed file's actual bytes.

All changed-file bytes were inventoried; changed Python files were parsed as ASTs
and JSON fixtures/schema were parsed. Focused implementation review covered the
Nebius parser policies/history, independent sidecar recomputation and public
projection, strict frontend schemas and import states, job-signing/download/policy
boundaries, combined adapter chain and compiler supervision, and release paths.
This is release verification, not an independent security audit of every module.
The only cross-module source edit was the operator-authorized signing-key fix in
`provenance/src/aegis_provenance/jobs.py`, with three regression cases in
`provenance/tests/test_prov_jobs.py`, its module README and the architecture note.
Core/API/CLI/Sentinel, Lab, Mirage and dashboard source was preserved. The stale
architecture Lab entry was synchronized to the verified archive's actual scope.

Release-owned changes: package exclusions, immutable per-file byte snapshots,
private archive permissions, retained executable modes, extracted-inventory
verification, strict Lab profile selection, package regression tests, actual public
summary browser walkthrough, current public README/install/runbook/submission/demo
copy, historical-document labels, root license proposal and bundled-frontend
third-party notices. The exact file inventory separates this task's edits from
pre-existing workstream changes.

## Package and fresh-install evidence

Private verification root: `/tmp/aegis-final-release-st3ud__p` (0700).
The preliminary candidate archive is
`/tmp/aegis-final-release-st3ud__p/candidate/aegis-local-review.tar.gz`.
It contains **325 inventoried files** plus the inventory; SHA-256
`74d6be512a77f86c043b33e8da42a6da8be2f663220289e621ead10389959bd8`.
This is an intermediate snapshot, **not the final package**: later release-doc
and packaging-test refinements are excluded from that preliminary archive.

A new private `candidate-extracted/aegis` directory was created; all 325 digests
matched, with no unlisted files, links or unsafe members. An offline cached install
created its own `.venv` (CPython 3.13.15) and `node_modules`; nothing was borrowed
from the source checkout's installed packages. Shield, ImageLab and the dashboard
rebuilt there. Both real adapter probes and HTTP smoke jobs succeeded. The smoke
independently rehashed every registered output and checked the Mirage stage chain.
Actual NVIDIA summary import also passed in the extracted product at desktop and
mobile sizes and in Results, with zero browser POSTs.

Install warnings: uv could not hardlink across cache/filesystem boundaries and
copied files; npm 12 blocked esbuild's postinstall under its existing policy.
The installed platform binary nevertheless built the dashboard successfully.
No package-install policy was relaxed. This used warm caches; cold-machine
network/download behavior and installation time were not measured.

Final review archive location:
`/tmp/aegis-final-release-st3ud__p/final/aegis-local-review.tar.gz`.
Its detached SHA-256 is in sibling `SHA256SUMS` and verification results in
`VERIFICATION.json`. Fresh final extraction will be
`/tmp/aegis-final-release-st3ud__p/final-extracted/aegis`, with independent
`.venv`/`node_modules` and rebuilt native workspace `final-workspace`.
Use the detached receipt for the final extraction, all per-file digests, fresh
installation, backend smoke, signing tests and actual-summary browser results.
The receipt and checksum are generated after packaging so this report does not
attempt to contain its own archive digest. The preliminary snapshot above is retained only as audit evidence.

## Tests and validation

Authoritative logs are private files under `/tmp/aegis-final-release-st3ud__p`.
Historical counts in other handoffs are not substituted for this task's runs.

| Check | Observed result | Log |
| --- | --- | --- |
| Initial scripts-only command with `--shield-plugin` | **NOT RUN**, pytest rejected an option registered by the adapter conftest; corrected by including adapter tests | Captured tool result |
| First packaging/adapter attempt inside sandbox | 4 failed, 182 passed; all four failures were forbidden local sockets | Captured tool result; no production change made to bypass it |
| Same packaging/adapter regressions outside sandbox | **186 passed**, zero skips/warnings | `packaging-regressions.log` |
| Fresh native/dashboard build and configure | Passed; both real probes passed | `build.log`, `configure.log` |
| Source-workspace HTTP smoke | Both real backends succeeded; all hashes and combined chain checked | `smoke.log` |
| Offline re-export of actual NVIDIA archive and sidecar | Exact public-summary bytes/digest reproduced | `nvidia-reverified-summary.json` |
| Actual summary browser walkthrough | Desktop 1440×1000, mobile 390×844, Results passed; **0 POSTs** | `research-browser.log`, `research-browser/*.png` |
| Extracted candidate install/build/probes/smoke | Passed, separate CPython 3.13.15 environment | `candidate-install.log`, `candidate-build.log`, `candidate-configure.log`, `candidate-smoke.log` |
| Extracted candidate actual-summary walkthrough | Passed, **0 POSTs** | `candidate-research-browser.log` |
| Extracted candidate companion Python | **782 passed**, zero skips, 1 Starlette/httpx deprecation warning; 40.37 s | `candidate-gate.log` |
| Extracted candidate Shield / ImageLab CTest | **1/1**, **12/12 passed** | `candidate-gate.log` |
| Extracted candidate Mirage / native final-link controls | **12 passed**, **3 passed**; includes ImageLab external variant CTest in native test | `candidate-gate.log` |
| Extracted candidate strict Lab/Ghidra | **2105 passed**, zero skips/warnings; 169.22 s | `candidate-gate.log` |
| Extracted candidate frontend contracts / build | **14 passed**, zero skips; TypeScript/Vite build passed | `candidate-gate.log` |
| Extracted candidate Playwright | **22 passed**, zero skips; 18.4 s; Node printed existing NO_COLOR/FORCE_COLOR warnings | `candidate-gate.log` |
| Earlier source strict gate | 787 companion + 2105 Lab passed; other suites passed, but **superseded** because the authorized key fix changed two implementation/test files during it | `source-gate.log`, `source-gate-superseded.json` |
| New Git ancestry regressions before fix | **2 failed, 1 passed, 23 deselected**; both Git-parent-alias cases reproduced the bug | `key-alias-before.log` |
| Focused signing/API/CLI/Core/Sentinel after fix | **100 passed**, one Starlette/httpx deprecation warning; 6.56 s | `key-alias-after-unsandboxed.log` |
| Same focused run in sandbox | Stalled after 52 cases; terminated (143), then rerun outside sandbox; never reported as passed | `key-alias-after.log` |
| Corrected final companion Python | **790 passed**, zero skips; 1 Starlette/httpx warning; 43.52 s | `final-gate.log` |
| Corrected final Shield / ImageLab CTest | **1/1**, **12/12 passed** | `final-gate.log` |
| Corrected final Mirage / native controls | **12 passed**, **3 passed**; native control includes real ImageLab external CTest | `final-gate.log` |
| Corrected final strict Lab / real Ghidra | **2105 passed**, zero failures/skips/warnings; 167.26 s | `final-gate.log` |
| Corrected final frontend contracts / build | **14 passed**, zero skips; TypeScript/Vite build passed | `final-gate.log` |
| Corrected final Playwright | **22 passed**, zero skips; 18.5 s | `final-gate.log` |
| Corrected final gate process | **Exit 0**; 261 implementation/config/test/asset file digests identical before/after | `final-gate-start.json`, `final-gate-end.json` |
| Latest package/inventory focused tests | **36 passed, 16 deselected**, no warnings; focused selection only | `final-package-unit.log` |
| Diff hygiene | `git diff --check` passed at latest check; rerun at handoff | Pending final receipt |
| Credential scan | All 326 preliminary archive members scanned; zero matches for complete private PEM payloads, AWS access IDs, GitHub tokens or JWT shapes | `candidate-credential-scan.json` |

The strict command uses `scripts/product.py verify --lab-profile integration` and
requires Ghidra 12.1.4/JDK 21, real LLVM 22 and existing Chromium. It covers full
Core/API/CLI/Provenance/Sentinel/real adapter/scripts, Shield CTest, ImageLab CTest,
Mirage, final-link native controls, strict Lab/Ghidra, frontend contracts, production
build and Playwright (including real signing, denial and tampering). Strict Lab
refuses skips. Only owned trusted fixture code is compiled/executed; generated
reconstruction candidates are never run.

Host: Linux 7.2.3-1-cachyos x86-64, Intel Core Ultra 9 185H, 22 logical CPUs,
glibc 2.44, source CPython 3.14.7, fresh install CPython 3.13.15, Node 26.8.1,
npm 12.0.2, LLVM/Clang 22.1.8, CMake 4.4.3, Ninja 1.13.2, Ghidra 12.1.4,
OpenJDK 21.0.12. Hosted GitHub Actions and a cross-platform/version matrix were
**not run**. Final browser startup printed the existing Python relative-venv `sys.prefix` /
`sys.exec_prefix` RuntimeWarnings and Node NO_COLOR/FORCE_COLOR warnings. They did
not cause failures. There were no final skipped cases. No missing prerequisites
were represented as passes. No held-out candidate behavior was measured.

## NVIDIA/Nebius evidence and accurate product representation

The actual public summary digest is
`16be4b7bf0bfdbbe36389aca550fa703fe7f35c5e5dc3f4161b87d87e41292b6`.
Offline re-export independently verified the original experiment and every sidecar
field before projecting safe metadata. Browser tests used those exact public bytes;
raw private evidence is excluded from the package.

The archive reports `nvidia/Nemotron-3_5-Lightning`, matched requested/reported
identity, 1,786 prompt + 8,039 completion = 9,825 tokens. Original `invalid_output`
and null candidate remain under legacy parser v1. A separate v2 metadata review
shows `candidate_text_revalidated_but_behaviorally_unscored` with its own candidate
hash. No compilation, execution, behavioral success or protective effect follows.
Estimated reported-token cost is $0.002037, conservative reservation $0.064881,
actual invoice unknown. Model weights, GPU hardware and provider origin are not
independently attested by unsigned local records. Two protected inference
continuations remain separately unapproved; no successful three-way comparison
exists. Full runtime explanation and concrete observed provider feedback:
[NVIDIA_NEBIUS.md](NVIDIA_NEBIUS.md).

## Distribution boundary and license

The archive includes source, tests and synthetic fixtures, Java Ghidra exporter,
owned image assets, schemas, package manifests/locks, documentation and the built
frontend. It excludes credentials, approval files, private evidence/plan/use stores,
local config/job stores, private/public signing-key files, `.git`, `.venv`,
`node_modules`, caches, test reports, native binaries and build scratch. The only
included build is `platform/dashboard/dist`. The empty `.env.example` is retained.
Names alone are insufficient for keys/approvals: complete private-key payloads
and approval-shaped JSON under an unexpected name are refused before archiving.
A bounded credential-pattern scan is an additional check, not proof that no
conceivable secret format exists.

Root [LICENSE](../../LICENSE) is a prominent **pending owner approval** MIT proposal
with unconfirmed copyright holders. It is not an adopted license. Owner approval
and removal of the pending header/filling holders are still required before a
public MIT claim. Manifest status remains `pending_owner_review`. Bundled React,
React DOM, Scheduler and Lucide notices are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md); they retain their own licenses.

## Signing-key path issue: found, authorized and repaired

`_load_signing_identity` originally checked Git ancestry on the unresolved
configured key path. A parent symlink hid a key physically inside a Git worktree;
`O_NOFOLLOW` covers only the final component. A synthetic `/tmp` reproduction
returned `CONFIG_INVALID` for the direct path but accepted its parent alias.
No real key was inspected.

The operator explicitly authorized Agent 4 to fix this issue. The loader now
checks both configured and resolved ancestry, preserving final-component symlink
refusal. New regression cases cover ordinary Git markers, linked-worktree markers
and a safe parent alias outside Git/store. Before the fix: 2 failed / 1 passed.
The same original reproduction now returns `CONFIG_INVALID`; the post-fix focused
100-case suite passes. The final full gate passed with these regressions. This is a
repair of the documented control, with no API/storage/authorization-gate change.
Architecture and the Provenance README were updated in the same change.

The frozen implementation inventory SHA-256 (canonical sorted filename/digest
map) is `d335ec594cf9b8a0fb2686110d3b0f216b22ca05888c2f0cde94e584ff092b1f`.
Only release documentation/inventory was finalized after that gate; implementation,
tests and package scripts remained byte-identical.

## Public-release blockers and exact operator actions

1. Review the corrected source and final gate/installation receipt. Agent 1's
   completion was confirmed; Agent 4's specifically authorized path fix is included.
   Any subsequent implementation change invalidates the frozen-tree gate and needs
   relevant checks plus a new archive. Exact repeat command:

   ```sh
   AEGIS_GHIDRA_HEADLESS=/home/youss/Applications/ghidra_12.1.4_PUBLIC/support/analyzeHeadless \
   PLAYWRIGHT_BROWSERS_PATH=/tmp/aegis-product-browsers \
     .venv/bin/python scripts/product.py verify \
       --workspace /tmp/aegis-final-release-st3ud__p/workspace \
       --lab-profile integration --api-port 9900 --dashboard-port 7073
   git diff --check
   ```

2. Compare `final/SHA256SUMS` and inspect `final/VERIFICATION.json`. The final
   package is a local review artifact, not a published release or a portable
   native binary distribution. See the fresh installation instructions below.
3. Review all files in [CHANGED_FILES.md](CHANGED_FILES.md), the third-party notices
   and the root MIT proposal. Confirm contributors' rights and actual holders;
   approve the final license separately. Any changed source needs relevant checks
   and a newly built archive; never publish an older digest as the new revision.
4. Build a new archive in an unused private output directory, compare its checksum,
   extract into a new 0700 directory, run `python3 scripts/product.py check-package`
   before dependencies, then follow [INSTALL.md](INSTALL.md). Preserve the detached
   checksum/installation receipt; a report inside an archive cannot contain its
   own final archive digest without a circular dependency.
5. Approve commit/push/PR explicitly; none has been performed. Stage only the exact
   reviewed inventory, including untracked implementation/tests. Built frontend
   ships in the archive and is intentionally Git-ignored. Runtime/private files
   never belong in the commit.
6. Record/edit the [2:55 demo script](DEMO-SCRIPT.md), supply approved repository,
   archive and video URLs, confirm event rules/deadline/attribution, then approve
   publication and submit the [Devpost description](SUBMISSION.md). No video or
   public links were invented by this task.

Research limits (not reasons to invent results): no established Shield/Mirage
security property; optimizer removal is observed in an owned fixture; retention
was checked only under tested LLVM/linker conditions. Trusted textual host-target
LLVM 22 IR on Linux x86-64 is supported; arbitrary binaries, other LLVM majors,
macOS/Windows/web/mobile/consoles are unsupported or untested. Compiler parsing
runs on the host. Jobs run in-process without crash recovery; no historical-list
API exists. Sentinel caller identity is asserted, and outside tools need not
cooperate. Optional signatures attest bytes/key-holder metadata, not authorship.
