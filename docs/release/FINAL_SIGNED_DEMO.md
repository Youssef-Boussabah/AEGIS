# Final signed demo verification — 30 October 2026

Owner: Agent 1, Core/API/CLI/Provenance/Sentinel. **Verdict: PASS for the
implemented signed LLVM IR demo scope.** Genuine Shield and Shield + Mirage
jobs, exact-byte downloads, trusted Ed25519 verification and cooperating Sentinel
decisions work through the current API and dashboard. No implementation repair
was needed; no backend, dashboard, launcher, Lab or other owner's release file
was edited. The API contract was clarified to describe the actual CLI key-loading
boundary and this verification.

This run used the shared, already-dirty `dev/integration` checkout at
`691ce2717934c22dd30883b5dd8a586ebf78bf20`, including the latest uncommitted
implementation. It does **not** certify the clean commit alone. The 206 relevant
source-file hashes are recorded privately in `evidence/source-sha256.json`.
Builds and checks ran approximately 10:10–10:25 UTC (06:10–06:25 Toronto).
Host: Linux 7.2.3-1-cachyos x86-64, Python 3.14.7, LLVM/Clang/opt/llvm-link
22.1.8, Node 26.8.1; existing repository `.venv`, node_modules and Chromium cache.
No packages were installed.

## Private workspace and identity

```sh
cd /home/youss/Projects/aegis
W=/tmp/aegis-agent1-signed-demo-20261030-13295zu0
```

`$W` is a newly created directory outside Git, mode **0700**. The fresh demo-only
Ed25519 identity lives in `$W/identity` (0700); its private key
`demo-private.pem`, verification key `demo-public.pem` and random `api-token`
are **0600**. The private key is unencrypted for this local demo and is protected
by filesystem permissions; it is not a release identity. No private key bytes
or bearer token were printed, returned in API responses, included in screenshots,
or placed in Git. The public signing key fingerprint is:

```text
c78ca7406b44d195bcf9c52c270024e307f5ffb91ada1ec685458b720fcaf050
```

The main config is `$W/aegis.toml`; the main job store is `$W/store`. Independent
negative configs and stores are under `$W/unsigned` and `$W/deny`.
`$W/untrusted/aegis.toml` reads only this run's signed store with an independent
untrusted public key. Builds are `$W/shield-build` and `$W/imagelab-build`.
No existing operator/agent workspace was reconfigured or reused.

Agent 4's published
[native backend contract](NATIVE_BACKEND_CONTRACT.md) was used unchanged;
the report chain was checked independently below. No Agent 4 session was visible
in the available collaboration tree, so direct coordination was unavailable.
`$W/AGENT4_HANDOFF.md` records scope, ports, results and this limitation. Agent 4's
documents were not edited; no claim of Agent 4 approval is made.

## Operate this verified demo

The main server was left running at **http://127.0.0.1:18473** (UI), with the API
at **http://127.0.0.1:18400**. Only loopback is used. If it has stopped, restart
it from the repository root with:

```sh
.venv/bin/python "$W/serve.py"
```

This wrapper reads the private token file into the server environment without
putting the token in argv or stdout, and invokes:

```text
scripts/product.py serve --workspace /tmp/aegis-agent1-signed-demo-20261030-13295zu0 --api-port 18400 --dashboard-port 18473
```

The wrapper/launcher is a foreground process: Ctrl-C stops its own API/UI.
Do not start a second copy on those ports. Logs from this verification's running
instance are in `$W/logs/serve.log`. `/healthz` is open; every `/v1/*` route
requires the token. In the UI, open **Capabilities**, enter the value from
`$W/identity/api-token` privately in **API bearer token**, then open
**Protection jobs** and load one of these verified browser jobs:

| Profile | Job id | Verified outputs |
| --- | --- | --- |
| Shield | `f6402c5e3b3d46bd9a2c8a126e003e3d` | 2 |
| Shield + Mirage | `ca789d888802409fbafb05fd211ca6ca` | 4 |

Click **Verify artifact**. Each output must say **Signature verified**; signing
configuration or a manifest's presence alone is insufficient. The UI displays
the signer, fingerprint, `cooperating_enforced` mode, disclaimer and limitations.
Evaluate `execute`, `modify` or `attack_evaluate`: **Denied**. Evaluate
`redistribute`: **Permitted**. Download `protected.ll`, its manifest and policy.
**Continue to Results** retains verification for the selected job. The token and
jobs are held in memory; reloading requires token entry and job loading again.

To create another genuine job in this workspace:

```sh
.venv/bin/python -m aegis_cli protect --config "$W/aegis.toml" --json \
  --backend llvm-shield --option 'seed="42"' --option max-sites=16 "$W/annotated.ll"
.venv/bin/python -m aegis_cli protect --config "$W/aegis.toml" --json \
  --backend llvm-shield-mirage --option 'seed="42"' --option max-sites=16 "$W/annotated.ll"
.venv/bin/python -m aegis_cli verify --config "$W/aegis.toml" --json \
  bf0d3d27dc8b4f2687b1379e8465450b
```

The last command verifies the already-created signed combined CLI job and exits
0. Supply a newly returned job id when checking a new job. Alternatively upload
`$W/annotated.ll` through **Protect LLVM IR**, choose either registered profile,
and submit seed `42`. Only the repository-owned annotated fixture was used.

## Reproduce the setup in a fresh workspace

Use installed prerequisites from this checkout. These commands create new
builds, probe both genuine backends, compile only the owned fixture to IR, and
generate a new identity. They do not copy this identity or modify another store.

```sh
cd /home/youss/Projects/aegis
umask 077
NEW=$(mktemp -d /tmp/aegis-signed-demo-repro-XXXXXXXX)
.venv/bin/python scripts/product.py build --workspace "$NEW"
.venv/bin/python scripts/product.py configure --workspace "$NEW"
mkdir -m 700 "$NEW/identity"
.venv/bin/python -m aegis_provenance.cli keygen \
  --private-key "$NEW/identity/demo-private.pem" \
  --public-key "$NEW/identity/demo-public.pem"
.venv/bin/python - "$NEW" <<'PY'
import json, os, pathlib, secrets, subprocess, sys
os.umask(0o077)
w = pathlib.Path(sys.argv[1]).resolve()
commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
with (w / 'aegis.toml').open('a') as out:
    out.write('\n[provenance]\nenabled = true\n')
    out.write('signing_key_path = ' + json.dumps(str(w / 'identity/demo-private.pem')) + '\n')
    out.write('trusted_public_keys = [' + json.dumps(str(w / 'identity/demo-public.pem')) + ']\n')
    out.write('signer_name = "AEGIS demo ONLY"\n')
    out.write('build_repository = "https://github.com/Youssef-Boussabah/AEGIS"\n')
    out.write('build_commit = ' + json.dumps(commit) + '\n')
    out.write('\n[sentinel]\nenabled = true\nissuer = "AEGIS demo ONLY"\n')
    out.write('enforcement_mode = "cooperating_enforced"\n')
    out.write('allowed_actions = ["analyze", "redistribute"]\n')
with (w / 'identity/api-token').open('x') as out:
    out.write(secrets.token_urlsafe(32))
PY
```

Both configure probes must pass; the config must register both backends.
Do not treat `/healthz` alone as proof that a plugin works: it only checks
storage and the adapter executable. Start the fresh workspace on other free
ports, without exposing its token:

```sh
.venv/bin/python - "$NEW" <<'PY'
import os, pathlib, subprocess, sys
w = pathlib.Path(sys.argv[1])
env = {**os.environ, 'AEGIS_API_TOKEN': (w / 'identity/api-token').read_text()}
raise SystemExit(subprocess.call([
    sys.executable, 'scripts/product.py', 'serve', '--workspace', str(w),
    '--api-port', '18420', '--dashboard-port', '18493'], env=env))
PY
```

In a separate terminal, use the CLI/UI steps above with the new path, ports,
token, job ids and public key. The `build_commit` field names HEAD; a dirty
checkout is not fully identified by that value. Record source hashes as well.

## Exact checks and results

The following commands were run from the repository root, with stdout/stderr
saved under `$W/logs`. No test was deleted, weakened or skipped to obtain green.
The Python tests that use `aegis_core.testing.fake_adapter` verify protocol and
attestation behavior only; the separate live jobs and browser tests used the
real registered adapters and freshly built plugin.

| Check | Result | Log/evidence under `$W` |
| --- | --- | --- |
| Fresh `product.py build` and `configure` | passed; both genuine backend probes passed | `logs/build.log`, `logs/configure.log` |
| Core/API/CLI/Provenance/Sentinel + real adapter Python suite | **735 passed**, 1 Starlette `httpx` TestClient deprecation warning; no skips | `logs/python-unrestricted.log` |
| Shield CTest | **1/1 passed** | `logs/shield-ctest.log` |
| ImageLab CTest, native/IR-baseline/Shield | **12/12 passed** | `logs/imagelab-ctest.log` |
| Frontend contract tests | **14/14 passed**, no skips | `logs/frontend-contracts.log` |
| Full dashboard Playwright suite | **22/22 passed**, no skips | `logs/browser-suite-final.log` |
| Independent live API probes | **108 checks passed** | `evidence/api-verification.json` |
| Independent Chromium, both signed profiles | **2/2 profile scenarios passed**, 6 output signatures verified | `evidence/browser-verification.json` |
| Real-browser denial, untrusted signer, unsigned state, and authorization errors | **3/3 scenarios passed** | `evidence/browser-negative-verification.json` |
| Unsafe-key startup, offline failures, final identity modes | **7 checks passed** | `evidence/startup-offline-verification.json` |

```sh
.venv/bin/python -m pytest core/tests platform/api/tests platform/cli/tests \
  provenance/tests sentinel/tests protectors/llvm/adapter/tests -q \
  --shield-plugin "$W/shield-build/AegisShield.so"
ctest --test-dir "$W/shield-build" --output-on-failure
ctest --test-dir "$W/imagelab-build" --output-on-failure
npm --prefix platform/dashboard test
env AEGIS_PRODUCT_WORKSPACE="$W/unsigned" AEGIS_API_PORT=18410 \
  AEGIS_DASHBOARD_PORT=18483 PLAYWRIGHT_BROWSERS_PATH=/tmp/aegis-product-browsers \
  npm --prefix platform/dashboard run test:e2e
.venv/bin/python "$W/verify-api.py"
env PLAYWRIGHT_BROWSERS_PATH=/tmp/aegis-product-browsers node "$W/verify-browser.mjs"
env PLAYWRIGHT_BROWSERS_PATH=/tmp/aegis-product-browsers node "$W/verify-browser-negative.mjs"
.venv/bin/python "$W/verify-startup-offline.py"
```

The private standalone scripts remain in `$W`; rerunning the API probe creates
new jobs, refreshes its evidence, and changes the job ids used by the negative
browser probe. Run them sequentially. Temporary APIs use 18401–18403 and shut
down after each script. The unsigned browser workspace has its own store and
fixture, and `unsigned/imagelab-build` links only to this run's own build.
Playwright traces/results use `/tmp/aegis-dashboard-browser-results-18483`;
independent screenshots and downloads are in `$W/evidence`.

The first Python attempt inside the socket-restricted sandbox failed/stalled
and was interrupted; its incomplete log is `logs/python.log`, **not a passing
suite**. The identical suite passed outside that restriction. The first browser
suite was **21 passed / 1 failed** because my unsigned workspace lacked the
ImageLab build path; after adding the path, the full suite passed 22/22.
The first independent browser script had an ambiguous selector after loading
two jobs; using a fresh page per profile resolved the harness issue.
The initial startup probe incorrectly expected read-only `inspect` to load
keys; the corrected probe checks `protect` and API startup. These were probe
and environment corrections; application code was unchanged. Browser launch
also emitted Node's `NO_COLOR`/`FORCE_COLOR` environment warning.

## Exact artifacts and negative behavior

| Genuine job | Job id | Outputs |
| --- | --- | --- |
| API Shield | `bf759adb9d4b4bbab8c1edde82fe0eda` | 2, all verified |
| API Shield + Mirage | `0636dff03ad849a08c7f9f3ed37fcab2` | 4, all verified |
| CLI Shield + Mirage | `bf0d3d27dc8b4f2687b1379e8465450b` | 4, CLI `verify` exit 0 |
| Unsigned Shield, separate store | `dbc38d014fad42b5a3e2dd55828c9c7d` | 2, explicitly unsigned |
| Signed Shield, redistribution denied, separate store | `4ea020593b0342d18138643cfc644ff0` | 2, signatures verified; download 403 |

For input `annotated.ll`, seed `"42"`, max-sites `16`, these Core digests were
also reproduced in the independently submitted browser jobs:

```text
Shield protected.ll / combined shield-stage.ll:
4a7da8c1e1eae14ac9a4820c2f684a872123b38b332e816b9582143949d68a9a
Shield + Mirage protected.ll:
0fc986a807ccd88cd7e1c6a6e504354b3bd5633f9d5515c20fac561460116b42
shield-report.json:
135c529d9daea13b9927b7dc0f3b356657c586e9e869649fe5b5b02740b4764a
mirage-report.json:
8ea58753a0550c73336335c79ce4739988ec8e24d78f15a77af95866234fe8aa
```

Every API output download was independently hashed and size-checked against
Core's job. Each downloaded manifest names the same job id and artifact digest,
and was verified offline with the fresh public key. The combined Mirage report's
`input_sha256` equals Core's `shield-stage.ll` hash, and `output_sha256` equals
Core's final `protected.ll` hash. The standalone Shield output equals the
combined Shield stage byte for byte. `inserted_count = 3` remains an **adapter
claim**, not protection evidence.

Example offline check, requiring no bearer token or signing key:

```sh
.venv/bin/python -m aegis_provenance.cli verify \
  "$W/evidence/llvm-shield-mirage/protected.ll" \
  --manifest "$W/evidence/llvm-shield-mirage/protected.ll.manifest.json" \
  --trusted-key "$W/identity/demo-public.pem"
```

| Case actually tested | Observed result |
| --- | --- |
| Trusted signed bytes | `signature.status = verified`; offline exit 0; UI says Signature verified |
| Modified stored artifact | `ARTIFACT_TAMPERED`; download 409 `ARTIFACT_INTEGRITY_ERROR`; Sentinel evaluation denied; UI shows error |
| Modified signed manifest metadata | `SIGNATURE_INVALID` |
| Missing manifest | `MANIFEST_MISSING`; never verified |
| Independent untrusted public key | `UNTRUSTED_KEY`; offline exit 1; real UI never says verified |
| Signing unconfigured | `not_configured` / `unsigned`; no manifest/policy (404); CLI verify exit 1; real UI explicit |
| `execute`, `modify`, `attack_evaluate` with demo policy | HTTP 200 decision `permitted: false`; real UI Denied; CLI execute decision exit 1 |
| `analyze`, `redistribute` with demo policy | HTTP 200 decision `permitted: true`; permitted downloads hash correctly |
| Valid signature but redistribution not allowed | 403 `POLICY_DENIED`; real UI shows Denied and blocks download |
| Changed or missing configured Sentinel policy | evaluation denied; download 403; signature validity is a separate result |
| Missing or incorrect bearer token on job, report, trust, attestation, download, manifest, policy, evaluate, and submit routes | 401 `UNAUTHORIZED`; real UI load error; health remains open |
| Unknown digest or input digest used as output | 404; no caller-supplied filesystem path is served |
| Unknown evaluate field | 422 `INVALID_REQUEST` |
| Native backend asked to run `attack_lab` | 400 `UNSUPPORTED_TASK`, before dispatch; neither gate was enabled |
| Demo key copied to an unsafe mode for startup check | API and CLI protect exit 3 `CONFIG_INVALID`; test copy restored to 0600 |
| Offline modified / missing artifact | exits 1, `ARTIFACT_TAMPERED` / `ARTIFACT_NOT_FOUND` |

Stored artifacts, manifests and policies changed by probes were restored in
`finally` blocks; final live signatures and policies were checked again.
The final independent read of the five signed API/CLI/browser jobs verified
all **16 output signatures** and valid policies (`evidence/final-check.json`).
A scan of 58 log/evidence/documentation files found neither private-key PEM
headers nor the actual demo bearer token. The source-hash inventory showed no
implementation drift during verification.
Deliberately tampered **offline copies** remain under private evidence and are
not demo outputs. The demo's attack-lab configuration gate remains false, and
no attack-lab authorization record was supplied or bypassed. Existing regression
tests for both gates ran in the Python suite.

## Limits and handoff

- Signatures attest exact bytes and operator-supplied metadata by a trusted key
  holder. They establish no ownership, originality, security or attack resistance.
  Shield and Mirage have no established security property.
- Sentinel governs cooperating tools. Only AEGIS's artifact download route
  enforces redistribution here; caller/environment ids are assertions, not
  authenticated identities. Policies are integrity-checked locally, not signed.
- Download authorization is separate from signature verification: valid Core
  bytes and allowed redistribution can be downloaded even if a signature is
  absent/untrusted/invalid. Always use the live attestation result to claim
  verification. Local records, trusted-key configuration and `attestation.json`
  rely on local filesystem trust, not an external transparency service.
- The local demo key is unencrypted and temporary. Keep the entire workspace
  private; do not package or publish it. `/tmp` is ephemeral and not a backup.
- Automatic launcher configuration of signing/Sentinel is not implemented;
  operators add the two TOML sections. Read-only CLI `inspect`/`report` do not
  load signing keys; healthy backend status is not a verified signature.
- API background jobs have no restart recovery. A changed trusted-key set can
  change verification on the next request. Each UI verification is a snapshot;
  refresh recomputes it.
- No live inference, generated candidate execution, external targets or attack
  resistance measurements ran. Lab/Ghidra suites, native retention suites,
  extended benchmarks and external platform/browser matrices were **not run in
  this task**; they are outside this signed-demo scope. No sudo, installs,
  commits, pushes, resets or destructive cleanup were performed.
- Agent 4 should review the published backend contract against these job hashes
  and use this document as the signed-path supplement to the historical
  integration audit. Direct Agent 4 confirmation remains outstanding because
  that session was unavailable; no other release document was edited.

Repository files changed by this task, exhaustively:
`docs/release/FINAL_API_CONTRACT.md` and `docs/release/FINAL_SIGNED_DEMO.md`.
Builds, private keys/configs, standalone verification scripts, logs and evidence
are outside Git; the frontend's ignored `dist/` was regenerated by the existing
build command. No application source or repository tests were changed.
