# AEGIS Adversarial Lab

Role **B** · branch `feat/lab-mirage` · [issue #10](https://github.com/Youssef-Boussabah/AEGIS/issues/10)

## What this first increment does

`aegis_lab.manifest` defines the **local, versioned experiment record** (`aegis.lab.trial.v2`) for an authorized, paired baseline/protected reconstruction trial. It records the final-artifact identity, shared build conditions, the one permitted protection step, attack tool/workflow/model identity bound by digests, attacker access, equal budgets, scorer identity and an authorization reference. It rejects incomparable declarations *before an attacker is run*. `TrialManifest.sha256()` produces a stable record fingerprint, not a signature.

A manifest is a **declaration**. Its digests are the author's claims, and matching manifest fields do not prove that a comparison is scientifically fair. Three kinds of record are kept separate: declared configuration (the manifest), checked evidence (not implemented) and attack outcomes (not implemented).

**The manifest does not run an attack.** It does not integrate REA, Nebius, generated-code execution, AEGIS Core, or any security scoring. Any claims of attack resistance require a later independent scoring implementation. The authorization field here is *audit metadata*, not permission: actual execution must still satisfy **both** Core gates (`[attack_lab] enabled` and `AttackLabAuthorization`). Nothing in the present Core adapter runner is a sandbox for generated programs.

## Install and test (from repository root)

```sh
uv pip install --python .venv/bin/python -e './attack_lab[dev]'
.venv/bin/python -m pytest attack_lab/tests -q
```

Use `python -m aegis_lab validate-pair BASELINE.json PROTECTED.json` to validate two locally saved manifests. It never runs an attacker. On success it prints pair and manifest digests, `final_artifacts_identical`, observations, a `not_established` list and `"authorizes_execution": false`, and exits 0. Invalid input exits 2, and an unexpected internal failure exits 3. The example test fixtures in `tests/test_manifest.py` are illustrative, not benchmark evidence.

Python 3.11+, Pydantic 2 and pytest are sufficient. No attack tools, external models or network access are required to test the manifest contract. Existing Core/API/CLI suites are separate:

```sh
.venv/bin/python -m pytest core/tests platform/api/tests platform/cli/tests -q
```

## Contract, v2

`aegis.lab.trial.v1` is **retired**. A v1 manifest is rejected with `retired_schema_version` and must be re-issued as v2. v1 could not express shared build conditions or tool configuration digests, accepted blank identities, and fingerprinted `-0.0` and `0.0` differently. No v1 fingerprint remains valid.

- `TrialManifest`: `schema_version="aegis.lab.trial.v2"`, a unique 32-hex `trial_id` and a shared 32-hex `pair_id`.
- `ToolIdentity`: `name`, `version`, `executable_sha256` and `configuration_sha256`, all required. Used for attack tools, the compiler, the protection backend and the scorer.
- `BuildTarget`: final linked/bundled artifact SHA-256 (*not* intermediate LLVM IR), name, function, source revision, platform and format. It also holds `build` and, on protected trials only, `protection`.
  - `build` (`BuildConditions`) must be identical across a pair: `pipeline`, `compiler`, `shared_recipe_sha256` (the recipe without the protection step), `symbols` (`stripped`/`present`) and `debug_info`. It replaces v1's free-text `matched_build_profile` and the per-variant `build_recipe_sha256`.
  - `protection` (`ProtectionStep`) is the only declared build difference: backend identity, optional seed and `transformation_report_sha256`. The report is the backend's claim about what it changed. It is **not** evidence that the protection survived into the final artifact.
- `AttackConfig`: `ghidra_model`, `rea` or `custom`, plus `workflow_configuration_sha256`, `tools`, provider, `model_id`, `prompt_sha256`, `sampling_configuration_sha256` (every request parameter except model, temperature and seed), optional `sampling_seed` (0 to 2^63−1), `temperature`, and `session_isolation="fresh_session_and_workspace"`.
  - `tools` is a **set**: order carries no meaning. It must be listed in ascending case-folded name order, with names unique ignoring case, so one tool set has one representation.
  - `ghidra_model` must list a Ghidra tool and `rea` must list an REA tool. REA is an alternative workflow, not mandatory for Ghidra trials.
- `AccessPolicy`: `workspace_policy_sha256` identifies the rules for which files, besides the trial's artifact, enter the attacker workspace. It also holds symbol-file, original-source, retrieval and network permissions. An enabled runtime oracle requires `oracle_query_limit ≥ 1` and `oracle_configuration_sha256`. A disabled oracle requires both to be unset.
- `AttackBudget`: bounded wall-clock seconds, tokens, tool calls, attempts.
- `ScoringPlan`: `hidden_test_suite_sha256` (compute it over the whole test-suite archive, because a digest of a small or guessable answer can be brute-forced), `scorer` identity, interface and the all-tests-pass rule. Test contents never appear in a manifest.
- `AuthorizationReference`: traceable reference and scope, **not approval to execute**.
- `TrialManifest.attacker_view()`: the allowlisted projection that may enter an attacker workspace. It contains the task (function, interface, platform, format), the artifact digest, access and budget. Variant, ids, target name, source revision, build/protection details, the attack workflow, scorer and hidden-test identities, and authorization are excluded.
- `validate_pair(a, b)` returns a `PairValidation`. It requires exactly one baseline and one protected trial with distinct `trial_id`s, and every other field equal except `target.final_artifact_sha256` and `target.protection`. Differences are reported as field paths such as `target.build.compiler.version`.
  - **Identical final artifacts are accepted** and reported as `final_artifacts_identical: true`. Such a pair is a valid no-op experiment (for example, the optimizer removed the transformation). It is never evidence of protection, and any outcome difference cannot be attributed to protection.

### Identity text rules

Every identity and audit-reference string (target fields, build pipeline, tool names and versions, provider, model, interface, authorization reference and scope) is **rejected, never rewritten**, if it:

- is blank, including Unicode whitespace only;
- has leading or trailing whitespace;
- contains a control (Cc), format (Cf, including bidi overrides and zero-width characters), surrogate, private-use or unassigned code point, or a line/paragraph separator;
- is not already Unicode NFC.

Accepted values are stored exactly as given (no stripping, case folding or normalization). Interior spaces and NFC non-ASCII text are allowed. Characters assigned in a newer Unicode version than the running Python's are rejected as unassigned.

### Fingerprints

`TrialManifest.sha256()` is SHA-256 over `aegis.lab.canonical-json.v1` (`aegis_lab.canonical`): UTF-8, sorted keys, no whitespace, finite numbers only, `-0.0` written as `0.0`, shortest round-trip floats, and defaults included whether written or omitted. Records that compare equal therefore have equal bytes. Fixed vectors are in `tests/test_canonical.py` and `tests/test_manifest.py`. A fingerprint identifies a record; it does not authenticate it.

### Untrusted input handling

- **Files** (`aegis_lab.safe_io`): regular files only. A symlink in the final path component is rejected; parent directories are resolved normally. FIFOs, sockets, devices and directories are rejected after a non-blocking open, before any read. At most limit + 1 bytes are read (1 MiB for manifests). A change in size, inode or timestamps during the read is rejected. Parsing and hashing use the bytes that were read.
- **JSON**: strict UTF-8 without BOM. Duplicate keys at any depth, `NaN`/`Infinity` and overflowing numbers are rejected rather than resolved by "last key wins".
- **Errors** (`aegis_lab.diagnostics`): the CLI prints `<role>: <field path>: <category>` lines only, at most 20 per file. Rejected values, Pydantic messages, validator contexts, file paths and OS messages are never printed. Unknown keys appear as `<unknown>`, because a key name can itself be a secret.

### Deferred to the trial runner and scorer

The manifest cannot establish the following; later stages must:

- verify the declared digests against the actual tools, recipes, workspace and hidden tests;
- rebuild or check both artifacts from the shared recipe;
- inspect the final protected artifact for **retention**;
- record the provider-reported model identity and actual token/tool/time consumption;
- create fresh sessions, randomize trial order and record its seed;
- keep the manifest itself out of the attacker workspace (only `attacker_view()` may enter it);
- score outside the workspace without leaking hidden answers into retries;
- record failed, error and inconclusive trials.

Linking the manifest's authorization reference to Core's `AttackLabAuthorization` (including permitted artifacts) needs agreement with role A.

## Subsequent increments

1. Add a **trial runner contract** and outcome classifier, with no false success on errors or incomplete comparisons.
2. Integrate **Ghidra** analysis under bounded trusted subprocess execution, with pinned versions and saved structured evidence. *Standalone export implemented in Phase 2 (below); not yet connected to a trial runner or Core adapter.*
3. Integrate a **Nebius model provider** with pinned identity, explicit token budgets and sanitized traces.
4. Implement **isolated compilation and scoring** of agent-generated candidate implementations, with hidden tests outside the attacker environment.
5. Implement a separate **REA workflow adapter** using the same record, scoring and budget contract, noting which internal tools REA invokes.
6. Expose a real `aegis.adapter.v1` `attack_lab` backend only after dual authorization and isolation are tested. Coordinate any Core changes with role A.
7. Build **Mirage** decoys with no-decoy controls and measure functional equivalence, retention, overhead and reconstruction outcomes.

This module remains independent of ImageLab, PhotoCraft, reVC and Mattermost; no target-name logic is allowed in the generic code. Hold out unseen software during effectiveness evaluation.

## Phase 2: bounded local Ghidra evidence export

`aegis_lab.ghidra` is a **standalone local analysis command**. It runs a
trusted Ghidra `analyzeHeadless` installation on an *authorized local binary*
and publishes one versioned JSON record, `ghidra-analysis.json`
(`schema_version="aegis.lab.ghidra.v1"`). The bundled post-script
`scripts/AegisExportFunctions.java` exports Ghidra's own SHA-256 of the imported
program and, for each selected function, its name, namespace-qualified name,
entry point, thunk flag, database signature, decompiler signature, bounded
decompiled C, decompilation status and bounded decompiler message. The default
exporter path assumes a source checkout or editable install.

```sh
.venv/bin/python -m aegis_lab.ghidra \
  --binary /tmp/aegis-ghidra-smoke/sample \
  --headless "$HOME/Applications/ghidra_12.1.4_PUBLIC/support/analyzeHeadless" \
  --expected-ghidra-version 12.1.4 \
  --expected-sha256 <64-hex digest of the authorized input> \
  --function add \
  --output-dir /tmp/aegis-ghidra-run-1
```

Options: `--function` (exact name, namespace-qualified name, or `*` for all
functions up to `--max-functions`, 1–512, default 64), `--max-c-chars` (100–20000,
default 12000), `--decompile-timeout` (per function, 1–120 s, default 30),
`--analysis-timeout` (Ghidra auto-analysis, 1–600 s, default 120) and
`--wall-timeout` (whole run, 1–3600 s, default 300). The command exits 0 and
prints the report path only on success. A rejected run exits 1 and prints
`AEGIS Ghidra analysis failed [<category>]: <reason>`, an unexpected internal
failure exits 3, and invalid arguments exit 2 (see *Error output* below).

### What the worker guarantees

- **Input identity.** The input must be a non-empty regular file (no symlinks,
  at most 64 MiB). It is copied into a private 0700 temporary directory while
  being hashed. Ghidra analyzes only that copy, which is re-hashed afterwards.
  `--expected-sha256` is checked before Ghidra starts. The exporter script is
  likewise copied and hashed before use. The launcher and the installation's
  `Ghidra/application.properties` are hashed too. Ghidra's own digest of the
  imported program (`analysis.executable_sha256`) must equal the worker's.
- **File loading.** The input, exporter, launcher, `application.properties` and
  Ghidra's raw export are all read under the `safe_io` policy: the final path
  component must not be a symlink (parent directories are resolved normally);
  files are opened non-blocking, so a FIFO, socket or device is rejected instead
  of waited on; reads are bounded (input 64 MiB, launcher and exporter 1 MiB,
  `application.properties` 64 KiB, raw export 4 MiB) and an oversized file is
  rejected from `fstat` before any byte is read; a file that changes while it is
  read is rejected. Filesystem errors become fixed categories, never OS messages.
- **Strict raw JSON.** The raw export is parsed with the same strict parser as
  manifests: duplicate keys (for example two contradictory `analysis_timed_out`
  values), `NaN`/`Infinity`, overflowing numbers, invalid UTF-8 and malformed
  JSON are rejected before schema validation.
- **Tool identity.** The exporter reports the running Ghidra version, release,
  build date and Java version. The worker rejects a run whose runtime version
  differs from the installation's `application.properties`. `--expected-ghidra-version`
  pins the version before Ghidra starts. A launcher outside a Ghidra installation
  layout is rejected.
- **Process control.** Ghidra runs from an argument array (no shell) in its own
  process group, with a minimal environment (`PATH`, `JAVA_HOME`, `LANG`,
  `LC_ALL` only; no provider tokens). `HOME`, the settings and cache
  directories, and Java's temporary directory all point inside the private
  directory. The whole group is killed after the run, on wall timeout, and on
  interruption. The private directory, including the Ghidra project, is
  always removed. Selectors starting with `-` or containing control characters
  are rejected because Ghidra would treat them as options.
- **No false success.** Ghidra 12.1.x exits 0 and still runs post-scripts when
  auto-analysis times out or a script throws. The worker therefore rejects
  any of the following: a non-zero exit, Ghidra's `REPORT: Analysis timed out` or
  `REPORT SCRIPT ERROR` log markers (detected over the full output stream), the
  exporter's `analysis_timed_out` flag, a missing, oversized (> 4 MiB) or
  schema-invalid export, and a changed input. The remaining rules are the
  **report invariants** below.
- **Report invariants.** `aegis_lab.ghidra.analysis_violations` and
  `report_violations` are the single definition, applied by the worker before
  publication and by every `AnalysisReport` when it is constructed or parsed.
  A report is invalid if analysis timed out;
  the program name or Ghidra's executable digest differs from `binary`; a
  function does not match an exact selector; there are more functions than
  `max_functions` or fewer than the exporter's own count implies; decompiled C
  exceeds `max_c_chars` (measured in UTF-16 units, as Java counts) or a
  truncation flag is inconsistent with the length; two functions share an entry
  point; no function matched; an exact selector matched more than one function
  (an **ambiguity error**, for example two `static` functions with one name);
  the exactly selected function failed to decompile; no function decompiled; or
  versions, runtime fields, counts or `log_truncated` are inconsistent.
  Violations are reported as `<field path>: <reason>` codes. With `*`,
  per-function failures are recorded and counted (`decompiled_ok_count`,
  `decompile_failed_count`) as long as one function succeeded.
- **Decompiler outcomes.** Each function has `decompile_status`: `completed`,
  `completed_with_warnings` (success whose `DecompileResults.getErrorMessage()`
  was not empty), `timed_out`, `cancelled`, `failed_to_start` or `failed`.
  `decompiler_message` keeps that message independently of success (at most 2000
  UTF-16 units, `decompiler_message_truncated`); `error` is set only for failures.
  Warnings and truncation are reported in the per-function fields and in
  `limitations`; they are not failures. Auto-analysis timeout is the
  program-level `analysis_timed_out` and is always a failure. In local checks
  with Ghidra 12.1.4 on x86-64 Linux ELF (463 successful functions across two
  AEGIS fixtures and a copy of a system binary, 2026-10-28), `getErrorMessage()`
  was empty for every successful function, and Ghidra wrote warnings as
  `/* WARNING: ... */` comments inside `decompiled_c`. Those inline comments are
  **not** classified as warnings, and `completed_with_warnings` is covered by
  offline tests only.
- **Bounded, shareable output.** Output is drained through a pipe. Only the last
  128 KiB of the log are kept (`log_bytes_total`, `log_truncated`). The
  scratch path, Ghidra installation path, home directory and account name are
  replaced with `<scratch>`, `<ghidra>`, `~` and `<user>` on a best-effort basis.
  The report is re-parsed with the strict report parser, written to a temporary
  file and hard-linked into place, so it appears complete or not at all and never
  replaces an existing report. The output directory is opened once before Ghidra
  starts and all publication is relative to that descriptor; if the path was
  replaced or removed in the meantime (for example by a symlink), nothing is
  published.

### Error output

Messages are built from fixed text, integers, the caller's own validated
selector and pattern-checked version strings only. They never contain rejected
JSON values, unknown field names, local paths, operating-system messages, Ghidra
log lines or exporter-controlled strings (function names, decompiler errors);
schema errors are shown as `<field path>: <category>` as for manifests.
Everything printed is additionally escaped for non-printable characters and
bounded. Argument errors name the option but never repeat its value. For
programmatic callers, `WorkerError` carries `category`, `violations` (codes) and
`log_tail` (the redacted, bounded Ghidra output, which is not printed).

### Compatibility and limitations

- Validated only with **Ghidra 12.1.4 PUBLIC** (Java 21.0.12) on x86-64 Linux ELF
  inputs. The exporter extends `HeadlessScript`, so it runs only under
  `analyzeHeadless`. Other versions run but receive a stated limitation in
  the report.
- This command is **not** an `aegis.adapter.v1` attack backend and must not be
  presented as one. It does not implement or bypass Core's two authorization
  gates. Analyze only owned or explicitly authorized files.
- Ghidra parses untrusted formats. This runner is bounded execution, **not** a
  sandbox for hostile binaries. No input or agent-generated code is executed.
- Decompilation output is analysis evidence, not a verified behavioral
  reconstruction, attack result, or security score. Reports reveal function
  names and code: treat them as build artifacts.
- Ghidra's launcher starts a short-lived helper JVM (`LaunchSupport`) that
  does not receive the worker's JVM options. It may briefly create a perf file
  under `/tmp/hsperfdata_<user>`; no input-derived data was observed there.
- A `*` export that exceeds the 4 MiB limit fails rather than being partially
  published; lower `--max-functions` or `--max-c-chars`.
- The launcher is hashed and then executed by path; a substitution between the
  two is not detected. The launcher and installation are trusted local tools.
- Reports are not signed. The worker cannot show which process produced a
  report file.
- On failure the CLI no longer prints Ghidra's log tail; use `WorkerError.log_tail`
  from Python to debug a failing Ghidra run.

### Tests

`tests/test_ghidra.py` contains 107 offline worker tests. They mock Ghidra's
command line and **cannot** prove that the Java exporter works. They cover the
report invariants, strict raw JSON, decompiler outcomes, FIFO/symlink/oversized
file substitution, output-directory replacement and CLI output with synthetic
secrets. `tests/test_ghidra_real.py` runs the real exporter: it compiles fresh
AEGIS-owned fixtures (never executed). It checks a distinctive decompiled
function against the ELF symbol table, that ambiguous and missing selectors
fail, that a 1 s auto-analysis timeout fails closed, and that a wall timeout
leaves no process running in the worker's scratch directory. Those 5 tests
are skipped (not run) unless enabled:

```sh
AEGIS_GHIDRA_HEADLESS="$HOME/Applications/ghidra_12.1.4_PUBLIC/support/analyzeHeadless" \
  .venv/bin/python -m pytest attack_lab/tests -q
```

Future AEGIS adapter integration requires both existing authorization gates
and a separate architecture review.
