# Operator release commands and final checklist

Prepared 30 October 2026. These commands are review material, not authorization
to commit, push, publish or spend credits. MIT adoption was separately authorized
by the operator for all four named contributors on 30 October 2026.
Development cutoff: **12:00 Toronto / 16:00 UTC**. Submission deadline:
**13:00 Toronto / 17:00 UTC**, 30 October 2026 (operator supplied).
The subsequent project-wide NVIDIA authorization permits necessary development
inference within a shared **$20 total including prior costs**, preserving all
single-use/disclosure safeguards. The operator centrally coordinates spending
and executes approved requests in their separate Fish terminal at the repo root,
where the key is already exported. No agent-accessible ledger is required.
Codex 4 owns the final genuine NVIDIA demonstration; do not duplicate requests.
[NEBIUS_SPEND_RECONCILIATION.md](NEBIUS_SPEND_RECONCILIATION.md) records known
estimates and the resolved handoff. No new paid call occurred here.

## Hold point: frozen demo evidence and final contents

The combined implementation is frozen and the full integration gate has passed.
Capture Codex 4’s final safe demonstration report before the definitive archive. Reconcile it against Git, include every
new implementation/test file, and rerun the relevant suites. Missing research
results stay pending; a deadline does not turn them into successful results.
If work is still incomplete at the cutoff, ask the operator which completed
snapshot to freeze and label the omitted work. Do not change implementation here.

The root LICENSE is now the approved standard MIT License, copyright 2026
Youssef Bossabah, Karim Lahyani, Nevan Vu, and Riche Anyadike. Package metadata
and release manifests record MIT/approved. Do not hand-edit an archive inventory.
License approval is complete; publication still requires approval of final contents.

## 1. Review and stage only the approved inventory

```sh
git status --short --untracked-files=all
git diff --check
git diff --stat
git diff --cached --stat
```

Review [STAGING_INVENTORY.md](STAGING_INVENTORY.md), including untracked files
that `git diff` does not show. `STAGING_PATHS.txt` contains literal Git pathspecs
for precisely that snapshot. `STAGING_SNAPSHOT.json` binds their bytes and status;
its own digest is intentionally absent to avoid a self-reference. Inventory
membership is **not** approval to publish, especially `LICENSE`.

Before staging, this read-only check refuses drift/new paths rather than
silently leaving the owners’ latest files out:

```sh
python3 - <<'PY'
import hashlib, json, pathlib, subprocess
s = json.loads(pathlib.Path('docs/release/STAGING_SNAPSHOT.json').read_text())
raw = subprocess.check_output(['git','status','--porcelain=v1','-z','-uall'])
now = {x[3:]: x[:2] for x in raw.decode().split('\0') if x}
expected = {x['path']: x['status'] for x in s['entries']}
if now != expected:
    raise SystemExit('STOP: status/membership changed; regenerate and review inventory')
for x in s['entries']:
    if x['sha256'] is not None:
        p = pathlib.Path(x['path'])
        if p.is_symlink() or hashlib.sha256(p.read_bytes()).hexdigest() != x['sha256']:
            raise SystemExit('STOP: reviewed bytes changed: ' + x['path'])
print('Snapshot matches; operator review and approval still required')
PY
```

If it refuses, regenerate the three staging files from current `git status
--porcelain=v1 -z -uall`, review every addition/deletion and hash actual bytes
again. Keep SHA-256 of the snapshot itself in a detached operator receipt.
Do not read credentials to generate an inventory; any credential/key/approval
path is an exclusion and publication blocker, never a staging candidate.
Do not use `git add .`, stash, reset, or stage ignored build/runtime directories.

**Only after explicit authorization and per-file/license review**, the operator
may run the following (not run by this task):

```sh
git add --pathspec-from-file=docs/release/STAGING_PATHS.txt
git diff --cached --name-status
git diff --cached --check
git diff --cached
```

The paths file uses `:(literal)` entries; do not add `--literal-pathspecs`, which
would make those prefixes part of filenames. Commit/push/PR still need
their own operator instruction. Never publish the old clean HEAD alone: release
functionality is in the uncommitted tree. Use the repository's task-branch/PR
workflow to `dev/integration`; do not rewrite shared history.

## 2. Final gate against the frozen implementation

Installed prerequisites are in [INSTALL.md](INSTALL.md). No installation or
browser download is implicit in these commands. Substitute your installed Ghidra
and Chromium-cache locations; use free loopback ports. Do not reuse team secrets
or workspace stores. Build regenerates the ignored dashboard bundle, so run it
only after the implementation freeze.

```sh
umask 077
RELEASE_WORK=$(mktemp -d /tmp/aegis-release-gate-XXXXXXXX)
GHIDRA_HEADLESS=/absolute/path/to/ghidra_12.1.4_PUBLIC/support/analyzeHeadless
BROWSER_CACHE=/absolute/path/to/installed/playwright-browsers
.venv/bin/python scripts/product.py build --workspace "$RELEASE_WORK"
.venv/bin/python scripts/product.py configure --workspace "$RELEASE_WORK"
AEGIS_GHIDRA_HEADLESS="$GHIDRA_HEADLESS" \
PLAYWRIGHT_BROWSERS_PATH="$BROWSER_CACHE" \
  .venv/bin/python scripts/product.py verify --workspace "$RELEASE_WORK" \
  --lab-profile integration --api-port 19900 --dashboard-port 19773 \
  > "$RELEASE_WORK/final-gate.log" 2>&1
git diff --check
```

Require exit 0, both genuine configure probes, zero skipped strict Lab cases,
all Python/native/frontend/browser suites and truthful warning counts. Offline
Lab is useful but insufficient for strict certification. Record toolchain, host,
date, command, source hashes and all pass/fail/skip counts. Freeze reviewed bytes
and compare them after the gate. Any implementation drift requires new checks.
Hosted CI is a separate result; do not label local tests as hosted CI.

New concurrent modules are outside `product.py verify`'s suite list. Once their
owners finish, also run their actual complete suites with real prerequisites;
these commands match the currently inspected option names:

```sh
.venv/bin/python -m pytest integrations/native_project/tests -q \
  --native-plugin "$RELEASE_WORK/shield-build/AegisShield.so"
.venv/bin/python -m pytest integrations/rust/tests -q \
  --rust-shield-plugin "$RELEASE_WORK/shield-build/AegisShield.so"
AEGIS_RECONSTRUCTION_PLUGIN="$RELEASE_WORK/shield-build/AegisShield.so" \
  .venv/bin/python -B -m unittest discover -s benchmarks/reconstruction/tests -v
AEGIS_ADAPTIVE_PLUGIN="$RELEASE_WORK/shield-build/AegisShield.so" \
AEGIS_GHIDRA_HEADLESS="$GHIDRA_HEADLESS" \
  .venv/bin/python -m pytest experiments/adaptive_mvp/tests -q
```

Rust additionally needs a compatible installed rustc/Cargo toolchain. Require
zero skips; missing prerequisites mean NOT RUN. Have the `scripts/live_evaluate.py`
owner provide its final tests and validated isolation evidence before claiming
that new wrapper or candidate scoring is certified. Do not execute a generated
candidate to fill a release checklist. Recheck command names after owner changes.
Check for unresolved experiment placeholders before treating any report as final.
The current final handoffs and limitations are linked in RELEASE_CONTENTS_READY.md.
Do not complete another agent’s experiment report on their behalf.

## 3. Package only the final reviewed bytes, then verify a fresh installation

After the report, license decision and inventory are final, package in a new
private output directory. The command captures tracked **and untracked** source
plus the built dashboard. Source staging alone does not determine its contents.

```sh
PACKAGE_OUT=$(mktemp -d /tmp/aegis-release-package-XXXXXXXX)
.venv/bin/python scripts/product.py package --workspace "$PACKAGE_OUT"
(cd "$PACKAGE_OUT" && sha256sum aegis-local-review.tar.gz > SHA256SUMS)
tar -tzf "$PACKAGE_OUT/aegis-local-review.tar.gz"
```

Review every member: one `aegis/` root, regular files, no traversal, links,
credentials, config/stores, approvals/reservations, raw inference artifacts,
reVC code/IR/binaries, `.git`, dependencies or native build scratch. Native test
fixtures and sanitized/synthetic JSON tests belong in the source package;
do not mistake them for actual research results. Review frontend notices after
any dependency/bundle change. Hashes establish integrity, not publisher identity.

After inspection, extract and check before installing dependencies:

```sh
FRESH_INSTALL=$(mktemp -d /tmp/aegis-release-install-XXXXXXXX)
tar --extract --gzip --file "$PACKAGE_OUT/aegis-local-review.tar.gz" \
  --directory "$FRESH_INSTALL" --no-same-owner --no-same-permissions
(cd "$FRESH_INSTALL/aegis" && python3 scripts/product.py check-package)
```

Follow [INSTALL.md](INSTALL.md) **inside that extraction**, creating its own
`.venv` and `node_modules`, native workspace and probes. Dependency installation
requires the operator's authorization and network access; do not substitute the
original checkout's installed packages. Run real HTTP `smoke` in a fresh local
server and independently rehash output downloads. Generate a new demo signing
identity outside Git/store following [FINAL_SIGNED_DEMO.md](FINAL_SIGNED_DEMO.md);
verification needs only the fresh public key. Existing team keys are unnecessary.
The signed-demo setup's `git rev-parse HEAD` must be replaced in a Git-free
extraction with `RELEASE-MANIFEST.json`'s recorded `git_head`; also retain the
manifest because that HEAD alone does not identify dirty-tree bytes.

Run [JUDGE_RUNTIME_INFERENCE.md](JUDGE_RUNTIME_INFERENCE.md)'s fresh-input and
draft/preflight steps without credentials. Any actual request requires separate
spending/disclosure approval; it is not part of the default installation gate.
Do not package its private workspace. Archive checksum, per-file inventory,
installation receipt and screenshots go in a **detached operator receipt**.
If documentation or any packaged file changes afterward, create a new archive
and digest. Do not reuse an old SHA-256 or attempt to embed an archive's own hash
inside that archive.

## 4. Security and reproducibility checklist

- [ ] Final safe NVIDIA handoff captured; actual outcomes, commands and limitations reviewed;
  source/tests/docs reconciled with the staging inventory and final source hashes.
- [ ] No private-key payload, token, `.env`, credential file, inference approval,
  reservation store, raw prompt/reasoning/candidate/response archive or local job
  store enters Git, archive, screenshot or video. A bounded scan is supplemented
  by human per-file review; ignored credential stores are not read for the audit.
- [ ] reVC and other non-redistributable artifacts excluded; third-party notices
  accompany bundled React/React DOM/Scheduler/Lucide. No external model is relicensed.
- [x] Operator confirmed all four contributors approved MIT; root/package notices
  and manifest metadata reflect the supplied 2026 names. Final contents/publication
  remain separately reviewable.
- [ ] Complete frozen-tree gate and fresh-extraction receipt pass; warnings, known
  failures, missing prerequisites and untested platforms recorded exactly.
- [ ] Both genuine adapters probed; real job downloads independently hash-check;
  signing verification and denial/tampering paths shown with a new demo identity.
- [ ] Sentinel described as cooperating enforcement; caller IDs asserted;
  host LLVM parsing and no in-flight job crash recovery disclosed.
- [ ] Paid request only with fresh independent disclosure/spend approval, account's
  own credential, exact NVIDIA ID, current catalogue checks and bounded limits;
  no automatic retries, no candidate execution, Core dual gates preserved.
- [ ] Historical invalid parser outcome retained separately from post-hoc text
  acceptance; no behavioral/security/latency/GPU/billing claims invented.
- [ ] Final package + detached checksum uploaded only after explicit publication
  authorization; anonymous download, extraction and clean install verified from
  the actual public URL. Do not call a source bundle a native binary installer.
- [ ] Approved source permalink/tag, downloadable test-build URL, checksum URL,
  150–175-second video URL and Devpost URL filled; private/loopback addresses
  never used as public demo links. Verify organizer rules separately.
- [ ] Operator approves final Devpost copy/video/license/assets and submits before
  13:00 Toronto; save submission confirmation. No agent publication assumed.
