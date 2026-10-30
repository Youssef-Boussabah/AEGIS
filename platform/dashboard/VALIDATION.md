# Agent 3 dashboard validation — 30 October 2026 UTC

Scope: this agent changed only `platform/dashboard/`. Existing uncommitted edits
from the integration audit and other agents were preserved. No commit, push,
reset, package installation, live inference, public deployment or signing of
operator artifacts was performed.

## Implemented and exercised

Protect → Verify → Evaluate → Results uses the real existing job lifecycle and
Agent 1's final attestation/download/policy contract. Both Shield and combined
Shield+Mirage require actual available `protect` registrations from health.
Unsupported profiles remain disabled. Results open verification for the selected
job, preserve selection across pages and show imported v2 comparison results.

The real browser walkthrough exercised Shield and combined protection, output
hashes, report download, byte-verified output download, unsigned configuration,
trusted Ed25519 signatures, current Sentinel deny/permit decisions, signed-manifest
download, artifact tampering, refusal to download changed bytes and verification
recovery after restoring the original bytes. Signing tests use only an ephemeral
0600 test key in a private `/tmp` directory, never sent to the browser or compiled.
The signing server also exercises the real bearer-token gate.

Synthetic HTTP tests separately exercise untrusted and mismatched attestations,
unsigned outputs despite recorded signing, signature/policy creation failures,
download policy denial, client-side hash mismatch and verification-request failure.
They are test fixtures, not evidence of protection or external inference.

Agent 2's public v2 schema is pinned in the frontend and compared byte-structure
for drift. Both reconstruction and comparison imports exercise hash checking,
recursive allowlists, known/partial/unknown usage and unknown billing. Synthetic
Nebius/comparison fixtures remain visibly synthetic. No prompts, candidate source,
private execution records or raw provider fingerprints are imported. Mobile layout
and keyboard skip/navigation paths are included. ImageLab import uses an actual
fresh local comparison and exporter, with zero browser uploads.

## Environment and exact commands

Observed host: Node 26.8.1, npm 12.0.2, CPython 3.14.7, LLVM 22.1.8; existing
Playwright Chromium in `/tmp/aegis-product-browsers`. Not validated on Node 22.

Fresh scratch workspace: `/tmp/aegis-dashboard-final-3vi18vjw` (private). Its native
build directories link to the existing `/tmp/aegis-shield-build` and
`/tmp/aegis-imagelab-build`, which identify this checkout as their source. The
current product configure command compiled the owned fixture and successfully
probed both `llvm-shield` and `llvm-shield-mirage` before writing the new config.
The operator's `/tmp/aegis-product` workspace was not reconfigured or stopped.

```sh
.venv/bin/python scripts/product.py configure \
  --workspace /tmp/aegis-dashboard-final-3vi18vjw
npm --prefix platform/dashboard test
npm --prefix platform/dashboard run build
PLAYWRIGHT_BROWSERS_PATH=/tmp/aegis-product-browsers \
AEGIS_PRODUCT_WORKSPACE=/tmp/aegis-dashboard-final-3vi18vjw \
AEGIS_API_PORT=9100 AEGIS_DASHBOARD_PORT=6273 \
npm --prefix platform/dashboard run test:e2e
git diff --check -- platform/dashboard
```

Initial unified-workspace contract tests: **12 passed, 0 failed, 0 skipped, no warnings**.
Initial unified-workspace TypeScript checks and production build: **passed**, Vite 6.4.5;
JS 220.52 kB (65.78 kB gzip), CSS 9.18 kB (2.87 kB gzip).
Initial unified-workspace browser run: **21 passed, 0 failed, 0 skipped**, 18.2 seconds on isolated
ports 9100/6273. The signed-artifact API used its own free loopback port.

The browser launcher emitted two Python `sys.prefix`/`sys.exec_prefix` runtime
warnings from its existing relative virtualenv path, and Node's repeated
`NO_COLOR`/`FORCE_COLOR` warning. No suite result was converted to success because
of a warning. An early sandboxed browser launch was refused (local listening
blocked); the suite was rerun with approved execution. An occupied-port attempt
stopped without reusing or terminating that server. All subsequent runs used new
isolated ports.

Earlier expanded runs caught disabled-option/hidden-detail locator mistakes,
an ambiguous navigation locator and an inconsistent absent-policy fixture; these
were corrected. No original test was removed, skipped or weakened. Original eight
browser workflows remain, with real artifact/verification assertions added.

Diff hygiene: passed. A final compiled-bundle marker scan found no private-key
PEM marker, private test-record marker, generated test credential, Nebius API key
variable or browser storage calls. This is a bounded marker scan, not a proof
that arbitrary secrets cannot exist.

Final screenshots (local artifacts, not public releases):
`/tmp/aegis-dashboard-combined-report.png`,
`/tmp/aegis-dashboard-signed-verification.png`,
`/tmp/aegis-product-browser-report.png`.
Playwright results/traces: `/tmp/aegis-dashboard-browser-results-6273`.

## Limitations and suites not run by this agent

- **Live Nebius calls: not run.** Agent 3 implements public-summary consumption;
  paid inference and disclosure approval remain operator-run Lab responsibilities.
- **Behavioral reconstruction scoring: not run.** Imported records explicitly
  remain pending the authorized Core runtime; no success rate is inferred.
- **Standalone Core/API/CLI/adapter, Lab, Provenance/Sentinel Python suites and
  LLVM/ImageLab CTest: not rerun by this frontend agent.** Those modules are outside
  this assignment's edit scope. Real backend/signing/policy paths and ImageLab
  comparison were exercised through browser tests; this is not a claim that their
  complete independent suites ran here.
- Native decoy retention after linking, attack resistance, GPU hardware/utilization,
  independent model-weight identity and provider invoices are not established.
- No job-list endpoint exists. Job reopening needs a known ID; browser state and
  API bearer tokens are memory-only. Verification shown in Results is explicitly
  last checked; Verify refresh recomputes the server result.

## Files changed by Agent 3

All paths below are relative to `platform/dashboard/`:

| File | Change |
| --- | --- |
| `src/App.tsx` | Existing pages, registered profiles, real downloads, workflow navigation and shared job verification state |
| `src/WorkspaceViews.tsx` | Workflow and unified Results, selected-job verification and comparison display |
| `src/VerificationView.tsx` | Attestation configuration, verification, policy decisions and public-document downloads |
| `src/ResearchView.tsx` | Labelled model identity/usage, billing limits and recorded comparison tables |
| `src/attestation.ts` | Runtime contract validation, artifact binding and verified download helper |
| `src/research.ts` | Public schema validation and cross-field semantic checks |
| `src/research-schema.json` | Exact snapshot of Agent 2's published schemas |
| `src/contracts.ts` | v2 imports and health-task validation; preserves prior degraded-health repair |
| `src/style.css` | Responsive workflow/results, verification/research panels and keyboard skip link |
| `index.html` | Workspace title |
| `package.json` | Individual contract-case reporting without test process isolation |
| `playwright.config.ts` | Validated isolated ports and per-port test artifacts; preserves prior port support |
| `tests/contracts.test.ts` | Attestation, denial, byte integrity, Lab privacy/usage and schema drift checks |
| `tests/attestation-fixtures.ts` | Explicitly synthetic API fixtures |
| `tests/browser/product.spec.ts` | Preserved real workflows plus downloads, unsigned verification and profile/flow coverage |
| `tests/browser/workspace.spec.ts` | Synthetic failure/privacy cases, keyboard/mobile and selection coverage |
| `tests/browser/real-attestation.spec.ts` | Real combined/signing/Sentinel/tamper/download workflows |
| `tests/prepare_attestation.py` | Private scratch-only key/config setup for the real browser signing test |
| `README.md` | Supported workflow, exact contracts, setup and limits |
| `FRONTEND_HANDOFF.md` | Final integration handoff |
| `VALIDATION.md` | This record |

The already-dirty `vite.config.ts` was read and preserved; it was not edited by
this agent. Built `dist/` files are ignored generated artifacts, not source edits.

## Post-hoc public-summary extension — latest validation, 06:13 UTC

This section supersedes the initial workspace test counts above. The extension
consumes Agent 2's published optional `completion_parser` and `post_hoc_review`
fields, without changing original generation/candidate states. Old exports and
null optional fields remain supported. Reviews bind their historical source hash;
accepted/rejected envelope and candidate-hash states are checked separately.
Comparison rows retain their original state and bind any review to their own
source record. Additional nested private fields fail closed.

Commands run:

```sh
npm --prefix platform/dashboard test
npm --prefix platform/dashboard run build
PLAYWRIGHT_BROWSERS_PATH=/tmp/aegis-product-browsers \
AEGIS_PRODUCT_WORKSPACE=/tmp/aegis-dashboard-final-3vi18vjw \
AEGIS_API_PORT=9300 AEGIS_DASHBOARD_PORT=6473 \
npm --prefix platform/dashboard run test:e2e
git diff --check -- platform/dashboard
```

Results: **14 contract tests passed**, no failures/skips/warnings; TypeScript and
production build passed (JS 227.43 kB / gzip 67.33 kB, CSS 9.18 kB / gzip 2.87 kB).
**22 browser tests passed**, no failures or skips, 18.8 seconds. Existing Python
prefix and Node color warnings remain as described above. An initial extension
run found an ambiguous new notice locator; corrected before this passing run.
Diff hygiene and the same bounded bundle-marker scan passed. No standalone
backend suite or live inference request was run by this frontend agent.

An additional desktop/mobile local-import walkthrough used only the supplied
privacy-filtered `/tmp/aegis-nvidia-baseline-public-summary.json`, verified against
its separately supplied SHA-256:
`16be4b7bf0bfdbbe36389aca550fa703fe7f35c5e5dc3f4161b87d87e41292b6`.
It passed on isolated ports 9400/6573, at 1440×1000 and 390×844, with **zero browser
POSTs**. The original state stayed `invalid_output` and original candidate digest
stayed null. The separate post-hoc state was
`candidate_text_revalidated_but_behaviorally_unscored`, with legacy v1 and
revalidation v2 parsers labeled distinctly.

The supplied record reports `nvidia/Nemotron-3_5-Lightning`, matched reported model,
1786 prompt / 8039 completion tokens and estimated 2037 microUSD. These are
provider-record observations in an unsigned local summary, not independent proof
of provider origin, model weights or usage. The provider invoice remains unknown.
The walkthrough did not read raw archives, send a model request, consume an
approval, compile/execute a candidate or infer attack resistance.

Screenshots: `/tmp/aegis-dashboard-nvidia-post-hoc.png` and
`/tmp/aegis-dashboard-nvidia-post-hoc-mobile.png`.
Latest suite artifacts: `/tmp/aegis-dashboard-browser-results-6473`.

Files changed for this extension (relative to `platform/dashboard/`):
`src/research.ts`, `src/ResearchView.tsx`, `src/research-schema.json`,
`tests/contracts.test.ts`, `tests/browser/workspace.spec.ts`, `README.md`,
`FRONTEND_HANDOFF.md`, `VALIDATION.md`. No other source paths were edited.
