# AEGIS Adversarial Lab

Role **B** · working branch `feat/lab-behavior-scoring` · [issue #10](https://github.com/Youssef-Boussabah/AEGIS/issues/10)

## Current delivery (29 October 2026)

The existing manifest, Ghidra, one-shot reconstruction, paired trials and Phase 4
scoring paths are preserved. New `aegis_lab.experiment` adds an explicitly labeled
**REA-style controlled iterative reconstruction workflow**: bounded target-evidence
inspection, private candidate revisions, exact provider-body provenance, per-step
budgets, and paired orchestration through existing pair validation. This is not a
direct REA integration. Generated candidates are **behaviorally unscored** while
Core execution remains unavailable; no candidate executes in the demonstration.

The real Nebius transport uses the documented Token Factory API and now also
requires explicit transport opt-in. Live inference is still refused by the public
Lab reconstruction/workflow entry points. No credits were spent. FakeOffline always
identifies itself as scripted offline inference. Missing usage is unknown and
conservatively reserved, never represented as zero model use. Offline cost is zero.

[Reproduction commands and integration handoff](docs/role-b-delivery.md) cover
strict/offline test profiles, the actual baseline/Shield/Mirage demonstration,
private evidence, source isolation, remaining approval gates and all changed files.
Mirage is implemented in [its owned module](../protectors/mirage/README.md).
The older sections below describe each established phase separately.

## What this first increment does

`aegis_lab.manifest` defines the **local, versioned experiment record** (`aegis.lab.trial.v2`) for an authorized, paired baseline/protected reconstruction trial. It records the final-artifact identity, shared build conditions, the one permitted protection step, attack tool/workflow/model identity bound by digests, attacker access, equal budgets, scorer identity and an authorization reference. It rejects incomparable declarations *before an attacker is run*. `TrialManifest.sha256()` produces a stable record fingerprint, not a signature.

A manifest is a **declaration**. Its digests are the author's claims, and matching manifest fields do not prove that a comparison is scientifically fair. Three kinds of record are kept separate: declared configuration (the manifest), checked evidence (`aegis_lab.evidence`, below) and attack outcomes (not implemented).

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

1. Add a **trial runner contract** and outcome classifier, with no false success on errors or incomplete comparisons. *Offline paired-trial runner implemented in Phase 3B (below); outcome classification beyond workflow completion needs Phase 4 scoring.*
2. Integrate **Ghidra** analysis under bounded trusted subprocess execution, with pinned versions and saved structured evidence. *Standalone export implemented in Phase 2 (below); not yet connected to a trial runner or Core adapter.*
3. Integrate a **Nebius model provider** with pinned identity, explicit token budgets and sanitized traces. *Offline reconstruction pipeline implemented in Phase 3A (below); live inference is disabled pending Core execution-authorization integration with role A. Generated-code execution and reconstruction scoring are not implemented.*
4. Implement **isolated compilation and scoring** of agent-generated candidate implementations, with hidden tests outside the attacker environment. *Phase 4 scoring contracts, coordinator, Core-grant integration and paired comparison implemented (below), tested only with Core's non-executing scripted runtime; Core refuses real execution until ADR 0004 is accepted and its isolation runtime exists.*
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
  publication, by every `AnalysisReport` when it is constructed or parsed, and
  therefore by the evidence binder. A report is invalid if analysis timed out;
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
  The report is re-parsed with the binder's own parser, written to a temporary
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
- Reports are not signed. Neither the worker nor the binder can show which
  process produced a report file.
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
leaves no process running in the worker's scratch directory. Those 5 tests,
and 15 real-Ghidra tests in `tests/test_evidence.py`, are skipped (not run)
unless enabled:

```sh
AEGIS_GHIDRA_HEADLESS="$HOME/Applications/ghidra_12.1.4_PUBLIC/support/analyzeHeadless" \
  .venv/bin/python -m pytest attack_lab/tests -q
```

Future AEGIS adapter integration requires both existing authorization gates
and a separate architecture review.

## Binding Ghidra evidence to manifests

`aegis_lab.evidence` connects a Phase 2 `ghidra-analysis.json` report to the
manifest of the trial it belongs to. It does not run Ghidra or any attack.

1. **Before the run**, declare the Ghidra tool in the manifest's
   `attack.tools`. The command below hashes the launcher, the installation's
   `application.properties` and the exporter, and prints the `ToolIdentity`.
   Use the same selector and limits for the worker run.

   ```sh
   .venv/bin/python -m aegis_lab.evidence ghidra-tool \
     --headless "$HOME/Applications/ghidra_12.1.4_PUBLIC/support/analyzeHeadless" --function add
   ```

   `configuration_sha256` is SHA-256 over the canonical JSON of
   `{"schema": "aegis.lab.ghidra-configuration.v1"}` plus these report
   `export` fields:
   - `ghidra_application_properties_sha256`, `ghidra_revision`;
   - `exporter_name`, `exporter_script_sha256`;
   - `selected_function`, `max_functions`, `max_c_chars`;
   - the three timeouts.

   The version and launcher digest are bound through `version` and
   `executable_sha256`.

2. **After both runs**, check each report against its own manifest:

   ```sh
   .venv/bin/python -m aegis_lab.evidence bind-pair \
     BASELINE.json PROTECTED.json baseline/ghidra-analysis.json protected/ghidra-analysis.json
   ```

   The command first requires a comparable manifest pair. It then requires each
   report's `binary.sha256` to equal its *own* manifest's
   `final_artifact_sha256`, so swapped reports fail. Each report's Ghidra
   version, launcher digest and configuration digest must equal the declared
   tool, and each report must satisfy the worker's report invariants (see
   *Report invariants*; a violation prints `<role>: <field path>: <reason>`).
   Both reports must also have observed the same Ghidra release, build date and
   Java version. When two bindings are combined (`compare_pair_evidence`), each
   binding's recorded `trial_id`, `manifest_sha256` and `artifact_sha256` must
   equal the current manifest's, so evidence bound to an earlier revision of a
   manifest (same trial id, different content) or to the other variant is
   rejected as `stale_or_swapped`. Byte-identical baseline and protected
   artifacts remain valid.

   The output (`aegis.lab.evidence-binding.v1`) records, separately for each
   variant: `trial_id`, `manifest_sha256`, `artifact_sha256`, and the
   `evidence_sha256` of the exact report bytes that were parsed, plus observed
   counts (exported, decompiled, failed, with warnings, truncated). It includes no
   decompiled code or logs. Reports are loaded with the same bounded
   file/JSON rules as manifests (limit 8 MiB).

A binding is a **consistency check of unsigned report files**. It does not show:

- that the AEGIS worker produced the report (signing is role D's planned work);
- that the artifact presently on disk has the declared hash;
- that protection was retained;
- any attack outcome.

It never authorizes execution.

## Phase 3A: AI-assisted reconstruction pipeline (offline)

Phase 3A turns **checked Ghidra evidence** about one artifact into a bounded,
policy-checked reconstruction request, runs it against an **offline** provider,
and publishes a strictly validated record of every attempt and the outcome.

- `aegis_lab.provider`: typed provider interface, canonical endpoint identity,
  strict response parsing and a `NebiusProvider` transport.
- `aegis_lab.disclosure`: the model-facing field allowlist, the evidence
  scanner and the `ExternalDisclosureApproval` record.
- `aegis_lab.reconstruction`: preparation, configuration binding, budgets, the
  attempt loop, the `aegis.lab.reconstruction.v2` record and the CLI.
- `aegis_lab.fake_provider`: an offline `FakeProvider` (no network, no token).
  Its replies go through the same strict parser as network responses.
- `aegis_lab.safe_io.publish_new_file`: exclusive, atomic publication.

**Status.** Offline reconstruction is available. **Live inference is disabled.**
The candidate is an untrusted proposal: it is never compiled, executed or
scored. Nothing here proves that reconstruction succeeded or that any
protection resisted anything.

### Live inference is disabled

`run_reconstruction` and `run-live` refuse every provider that would disclose
evidence externally. They first check the opt-in and the disclosure approval
(so an approval can be validated), then always stop with
`live_inference_disabled`, blocked by:

- `core_execution_authorization_unavailable`: Core's two attack-lab gates
  (`[attack_lab] enabled` and `AttackLabAuthorization`) are not connected to
  this pipeline. That interface needs role A.
- `token_bound_unverified`: no verified tokenizer bound exists for a live
  model, so a strict token budget cannot be enforced.
- `transport_deadline_not_enforced`: the transport has only logical deadline
  checks and socket inactivity timeouts (below). Guaranteed wall-clock
  interruption must be solved before live inference is enabled.

`run-live` never reads `NEBIUS_API_KEY` and never opens a connection.

**Disclosure approval and execution authorization are different things.** An
`ExternalDisclosureApproval` records a review decision to send *exactly this
material* to *exactly this endpoint*. It is an unauthenticated local file: it
does not prove who approved it, it is not a Core authorization, and it never
satisfies either Core gate. Execution authorization (may this attack run at
all?) belongs to Core.

### Disclosure approval (`aegis.lab.external-disclosure-approval.v1`)

An approval binds all of the following, and any mismatch fails closed before
any network activity:

- the `artifact_sha256`, `evidence_sha256` (report bytes) and
  `rendered_prompt_sha256` of the exact messages that were reviewed;
- the `provider` name and the canonical `endpoint` (scheme, host, effective
  port and base path);
- an optional `model_id` pin;
- `acknowledged_findings`, which must cover every finding category present;
- the disclosure policy version;
- `created_at <= valid_from < expires_at`, as timezone-aware times compared in
  UTC, with at most a 7-day window.

Endpoints are canonicalized to `https://host:port/path`. URLs with userinfo,
a query, a fragment, a non-HTTPS scheme, an IP literal, percent escapes or
`.`/`..` segments are rejected with a fixed code that never repeats the URL.
Redirects are never followed.

### Information isolation (`aegis.lab.disclosure-policy.v1`)

The prompt is rendered from an **allowlist**, not filtered from a larger
document. The fixed system message carries no data. The single user message
is a JSON document holding exactly these fields:

- the task: function label, expected interface, platform, artifact format,
  language (only `c`) and whether symbol names are withheld;
- the decompiler's output for the selected function;
- the symbol-table signature, only when symbols are revealed.

Every other manifest, report, authorization and run field is structurally
excluded.

Encoding the evidence as JSON string values keeps embedded delimiters,
quotes and newlines inside the data. It does **not** make prompt injection
impossible: the model still reads the text.

Hard failures (fail closed in every mode):

- an invalid language or task field;
- an interface that names a withheld symbol;
- a withheld symbol (including case variants and substrings of 6+ characters)
  still present after blinding;
- a pre-existing `target_function` placeholder;
- a privileged trial value in a pipeline-supplied task field.

**Findings** are category counts from a heuristic scan of the evidence:
paths, file names, URLs, e-mail addresses, comments, string literals,
instruction-like text, high-entropy tokens, other function names, artifact
names, protection hints, privileged trial values and control characters. They
are recorded in `prepare` output and in the record. Evidence is never silently
rewritten. The only transformation is the declared, counted renaming of the
target symbol to `target_function` when the run is blinded.

**Limitations.** Arbitrary binaries can contain arbitrary strings. The
scanner is not secret detection or semantic declassification. Absence of
findings is not proof that nothing sensitive is present. Blinding withholds
the target name only; other identifiers in the binary remain and are reported
as findings. For any external disclosure, a reviewer must inspect the exact
prompt (`prepare --show-prompt`) and approve its digest.

### Configuration binding

A run is refused before any call unless the effective configuration matches
the manifest:

- `attack.workflow` is `ghidra_model`;
- `attack.prompt_sha256` equals the prompt *template* digest;
- `attack.sampling_configuration_sha256` equals the digest of
  `aegis.lab.sampling-configuration.v1` (max output tokens, top_p, n, stop,
  stream);
- `attack.workflow_configuration_sha256` equals the digest of
  `aegis.lab.reconstruction-workflow.v1` (template, disclosure policy,
  candidate envelope, language, effective blinding, token-bound method, retry
  policy and hard limits);
- CLI overrides of temperature, seed, top_p and max output tokens equal the
  declared values;
- the running provider's name equals `attack.provider`, and the model equals
  `attack.model_id`.

`python -m aegis_lab.reconstruction plan --max-model-tokens N [--blinded]`
prints the three digests to declare.

Known limitations:

- Manifests written with Phase 1 placeholder digests cannot be verified, and
  are rejected rather than accepted.
- Manifest v2 cannot declare an endpoint, so the endpoint is not covered by
  these digests. For live runs it is bound only by the disclosure approval.
- The offline provider always identifies as `FakeOffline` at `offline:fake`.
  It refuses any other provider name, and no network provider may use that
  name. An offline run therefore requires a manifest declaring
  `provider: "FakeOffline"`; a manifest that declares Nebius fails offline with
  `provider_mismatch`.
- A prepared request retains its manifest and the exact Ghidra report bytes.
  Immediately before execution, `verify_prepared` re-runs the complete
  `prepare_reconstruction` on those two inputs and requires an identical
  result. This reapplies the unchanged Phase 2 evidence binding (artifact,
  Ghidra tool identity and configuration digest, report invariants), function
  selection, disclosure policy, configuration digests, prompt rendering, token
  bound and budgets. A replaced request or field, evidence rebound to another
  manifest (even with that manifest's correct fingerprint), or swapped evidence
  is refused (`evidence_binding_mismatch` or `prepared_request_inconsistent`)
  before any provider call. Stored fingerprints are never trusted as proof.
  The record stores the manifest temperature and seed next to the executed ones.

### Budgets, retries and interruption

- `budget.max_model_tokens` is the **aggregate** budget for the trial. Each
  attempt reserves `prompt_token_bound + max_output_tokens` before submission.
  It is then charged its reported total, or its full reservation when usage is
  unknown. A definitely unsubmitted attempt is charged zero.
- The default `max_output_tokens` is `min(16384, max_model_tokens // 2)`. It
  depends only on the budget, so both trials of a pair declare the same value.
- **The prompt bound is a heuristic** (UTF-8 bytes plus a template allowance).
  It is not a verified tokenizer bound, so budget enforcement is not strict.
  If reported usage exceeds the reservation, the record flags it.
- The wall budget is a monotonic **logical** deadline, not a guaranteed
  wall-clock interruption. It is checked before each attempt and retry wait,
  between transport operations and body chunks, and after the response. Each
  socket timeout is at most the time left, but a socket timeout is an
  *inactivity* timeout for one blocking operation. A server that trickles bytes,
  the buffered reads inside `http.client`, and name resolution can all run past
  the deadline; the call then reports `deadline_exceeded` after the fact.
  Strict transport deadline enforcement is unresolved and blocks live inference.
- A response over budget, over `max_output_tokens`, or after the deadline is
  never `completed`.
- Each attempt records its submission state: `not_submitted`, `rejected`,
  `uncertain`, `completed` or `interrupted`.
- **Retries:** only failures that definitely never reached the provider
  (`not_submitted`) are retried, with a fixed backoff (1, 2, 4 … s, at most
  30 s) that must fit the deadline. **No HTTP response is ever retried**,
  including 429, 503 and 529: there is no established guarantee that they mean
  the request was not processed, and no idempotency mechanism. Such attempts
  are charged their full reservation (usage unknown, never zero). An uncertain
  submission stops the run with `submission_uncertain`.
- **`Retry-After`:** delta-seconds or an HTTP-date (GMT) is parsed and recorded
  as valid or invalid. It never triggers a retry.
- A provider that raises anything other than `ProviderError`, or returns
  anything other than a valid `InferenceResponse` (`None`, another type, an
  unvalidated `model_construct` object, invalid nested usage), is recorded as
  an uncertain `provider_contract_violation` attempt charged its reservation.
  The return value is re-validated field by field inside the protected call.
- Responses over 8 MiB are rejected by the shared parser, before decoding, as a
  typed `oversized_response`; the body is not retained.
- **Interruption:** `KeyboardInterrupt` during a call or a wait raises
  `ReconstructionInterrupted` carrying the partial record. The CLI publishes
  it and exits 130. No other cancellation mechanism exists.

### Response and candidate validation

Responses are parsed strictly. Any of the following is rejected or explicitly
classified, never coerced:

- duplicate JSON keys, non-finite numbers or invalid UTF-8;
- more than one choice, a non-assistant role, or an `error` body;
- refusals, tool calls or unknown message fields;
- unknown or absent finish reasons;
- a reply containing a lone surrogate or NUL;
- usage that is absent, non-integer, negative or does not sum (absent stays
  absent);
- a response body over 8 MiB.

A candidate must be one `aegis.lab.candidate.v1` JSON object with exactly the
keys `schema`, `language`, `interface` (equal to the task interface) and
`source`. Markdown fences, prose and malformed envelopes are
`invalid_candidate`; nothing is "extracted" from them.

### Record (`aegis.lab.reconstruction.v2`)

The record holds these sections:

- task, inputs, provider (canonical endpoint), disclosure (policy, findings,
  approval reference and digest);
- configuration (verified digests), declared request and budget;
- the bounded attempt history;
- the outcome and candidate, or the rejected output.

`completed` means only that an acceptable candidate envelope arrived on time,
within budget, with `finish_reason` `stop`, from the requested model identity
with reported usage. It does **not** mean the candidate works. The other
statuses are:

`truncated`, `content_filtered`, `refused`, `unsupported_response`,
`unknown_finish_reason`, `empty_candidate`, `invalid_candidate`,
`model_identity_unverified`, `model_identity_mismatch`, `usage_unreported`,
`usage_invalid`, `budget_exceeded`, `deadline_exceeded`,
`submission_uncertain`, `provider_error`, `interrupted`.

A candidate is present exactly when the status is `completed`. Every classified
response that is not `completed` keeps a `rejected_output` (reason, digest,
size, and text up to 1 MiB; or why the text is withheld) and is never
promoted. For an HTTP error body, only its digest and size are kept; an
oversized body is not kept at all.

`parse_reconstruction_record` enforces the same invariants as creation:

- candidate digest and sizes (the unverifiable reply digest was removed);
- the status, **replayed** from the recorded observations: lateness, budget
  overrun, usage status, reported model, refusal, tool calls, unsupported
  fields, finish reason and content status. A retained invalid reply is
  re-parsed and must yield the recorded `candidate_error`;
- each attempt's HTTP status against its submission state and error category,
  using the transport's own status mapping (a completed response is HTTP 200;
  a 503 is a rejection and is never retryable);
- `retryable` exactly for definitely unsubmitted transport failures;
- retry waits that follow the backoff schedule, and attempts that start only
  after the previous attempt and its wait ended;
- strict, non-negative, summing usage and the charging rules;
- `prompt_token_bound` recomputed from `prompt_bytes` and the token-bound method;
- the executed temperature and seed against the manifest's;
- each stop reason against its preconditions, in the run loop's order: budget
  and deadline stops only after a retryable failure and below the attempt
  limit; `token_budget_exhausted` only when the next reservation does not fit;
  `deadline_reached` only after a wait and once the wall budget has elapsed;
  `retry_wait_exceeds_deadline` only when the backoff does not fit; an
  interruption only during a call or a wait;
- the attempt count against the budget, disclosure fields, and recomputed
  configuration digests.

**Records are unsigned.** These checks establish internal consistency, not
provenance: anyone who can write a record can change identity fields that no
other field depends on (`trial_id`, `pair_id`, `variant`,
`inputs.manifest_sha256`), or change two dependent fields together (for
example, both the executed and the manifest temperature). Detecting that
needs the original manifest or a signature (role D).

Records produced by earlier uncommitted drafts of v2 (with `reply_sha256` or
without the new outcome fields) do not parse and must be regenerated.

`aegis.lab.reconstruction.v1` records are rejected as `retired_schema_version`.

### Commands and exit codes

```sh
.venv/bin/python -m aegis_lab.reconstruction plan --max-model-tokens 4000
.venv/bin/python -m aegis_lab.reconstruction prepare MANIFEST.json REPORT.json [--show-prompt]
.venv/bin/python -m aegis_lab.reconstruction run-offline MANIFEST.json REPORT.json \
  [--candidate SOURCE.c | --reply REPLY.txt] [--output RECORD.json]
.venv/bin/python -m aegis_lab.reconstruction run-live MANIFEST.json REPORT.json \
  --approval APPROVAL.json [--i-accept-external-disclosure] [--endpoint URL]   # always refused
```

`--output` publishes with `publish_new_file`:

- the parent directory is opened once without following a final symlink;
- the record is written to a private (0600) temporary file, fsynced and
  hard-linked to the final name;
- the directory is fsynced.

An existing file, symlink, FIFO or directory at the destination is never
followed or replaced; this includes the manifest and report. A replaced
output directory, a write failure, or a filesystem without hard links is
reported and fails closed. Output is ASCII-escaped JSON.

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | completed |
| 1 | record produced, but the run did not complete |
| 2 | invalid input, configuration, policy or budget (no record) |
| 3 | internal error |
| 4 | live inference refused |
| 5 | publication failed |
| 130 | interrupted (partial record published if possible) |

### Reproducibility limits

The record stores the template version and digest, the rendered-prompt digest,
the settings digests and the provider-reported identity. Provider generation
is nondeterministic. A forwarded seed does not guarantee reproducible
sampling. Uncertain submissions and unknown usage limit cost accounting. Ghidra
evidence is an unsigned report and is not proof of origin.

### Tests

These test files cover Phase 3A:

- `tests/test_provider.py`;
- `tests/test_reconstruction.py`;
- `tests/test_reconstruction_cli.py`.

They are offline only. No network call, real model or real token is used, and
candidates are never compiled or executed.

**Not yet written:** dedicated unit tests for the disclosure module
(`test_disclosure.py`) and for `publish_new_file` (`test_publication.py`). Those
behaviours are currently exercised only through the reconstruction and CLI
tests.

## Phase 3B: controlled paired trial runner (offline)

`aegis_lab.paired_trial` runs one **baseline/protected pair** through the
existing stages and publishes a versioned paired record,
`aegis.lab.paired-trial.v2`. It composes Phase 1, 2 and 3A; it does not
reimplement them, and it does not run Ghidra (it consumes existing
`ghidra-analysis.json` reports).

**Status.** Only the local offline `FakeOffline` workflow is available.
Its replies and token usage are **scripted by the fake provider**: they
are not model output. Live inference stays disabled, and Core's two
attack-lab gates are not connected. The manifests' authorization reference
is recorded as audit metadata with `is_execution_permission: false`.
Candidates are never compiled, executed or scored.

### What the runner does, in order

1. **Roles.** Manifests and reports are taken by role (`--baseline-*`,
   `--protected-*`). A protected manifest given as the baseline is rejected
   (`baseline-manifest: variant: not_baseline`), never silently re-ordered.
2. **Phase 1.** `validate_pair` must accept the two manifests.
3. **Phase 2.** Each report is bound to its own manifest
   (`bind_ghidra_evidence`). Swapped, stale or wrong-artifact evidence fails
   with `binding: binary.sha256: mismatch`. `compare_pair_evidence` must
   accept the pair (same Ghidra release, build date and Java version).
4. **Phase 3A preparation, for both trials, before either runs.** Both use
   `prepare_reconstruction` with the same options. Each trial also gets a
   target-analysis observation from its bound report (see *Target-analysis
   failures* below). A target that failed to decompile in a valid wildcard
   report yields no request, and its declared settings are verified
   separately. When both requests exist, the runner requires identical
   prepared settings: task, blinding, declared provider/model,
   configuration digests and budgets. It also requires identical request
   parameters (model, temperature, top_p, seed, max output tokens, stop, n),
   the same fixed system message and the same model-facing `task` object.
   Only the artifact-derived evidence may differ.
5. **Run preconditions.** It checks the execution mode (only `offline`) and
   the order seed. It re-prepares the pair from the retained manifests and exact
   report bytes, rejecting changed observations, bindings or request membership
   before creating any provider. It creates one provider instance per trial *that has a
   request* (none for an analysis-failure trial). Two instances must be distinct
   objects of the exact built-in `FakeProvider` type, `FakeOffline` at
   `offline:fake`, and each must pass
   `verify_prepared` and `verify_effective_configuration`. It then creates
   the output directory, which must not exist (mode 0700; an existing entry,
   including a symlink, is refused). Every failure up to this point happens
   **before any inference**, and no output is left behind.
   A factory cannot substitute a transport by claiming the offline identity:
   duck-typed providers, subclasses and instance overrides of inference methods
   are refused. Python factories and fake-provider callbacks are trusted local
   test code, not a sandbox for arbitrary Python.
6. **Seeded order.** `execution_order(seed, ...)` takes the low bit of the
   first byte of SHA-256 over canonical JSON of
   `{schema: "aegis.lab.trial-order.v1", seed, pair_id, baseline_trial_id,
   protected_trial_id}`. The seed is the operator's `--order-seed` or, if
   omitted, comes from `secrets`. The seed, its source and the sequence are
   recorded. The order does not depend on Python's `random` module, and
   parsing re-derives it.
7. **Trials.** Each trial with a prepared request calls `run_reconstruction` with its own provider
   instance and fresh attempt state. Each trial's record is published as
   `<variant>-reconstruction.json` (via `publish_new_file`) as soon as that
   trial ends.
8. **Paired record.** `paired-trial.json` is published last. It references
   every produced reconstruction record by file digest and canonical digest.

### Information isolation between trials

- Available prompts are rendered before either trial runs, and each is
  re-verified (`verify_prepared`) immediately before it runs. No candidate,
  record or outcome of one trial can reach the other trial's request.
- Each provider instance receives exactly one trial's requests.
- When both prompts exist, their model-facing tasks are identical. A task never contains
  the variant, trial or pair ids, protection details, hidden-test or scorer
  identity, or authorization data (the Phase 3A allowlist). For each trial,
  the runner also counts the *other* trial's privileged values that appear
  in this trial's prompt (`cross_trial_value_findings`). Such a value can
  only come from artifact-derived evidence. Like Phase 3A's own findings,
  it is recorded and noted in `limitations`, not rejected.

### Failure handling

| Situation | Behaviour |
| --- | --- |
| A trial's reconstruction does not complete (invalid candidate, provider error, uncertain submission, deadline, budget) | Its record and status are kept. The other trial still runs. `pair_status: trial_failures`. Exit 1. |
| Both trials fail | Both records kept. `pair_status: trial_failures`. Exit 1. |
| Interrupted (Ctrl-C) during a call, a wait, a publication or between trials | The partial record is published if one exists. The remaining trial is `not_started`. `run_status: interrupted`. Exit 130. |
| Execution refused after preparation (`ConfigurationError`, `BudgetError`, `AuthorizationError`) | `state: execution_refused` with codes. The run stops. Exit 1. |
| Unexpected exception inside a trial | `state: internal_error` (exception type only). The other trial's record is preserved. Exit 3. |
| A trial record cannot be published | `publication: failed` with its category. The run stops. Exit 5. |
| The output directory is replaced during the run | `directory_replaced`. Nothing is written into the substituted directory. Exit 5. |
| The paired record cannot be published | The trial records remain. The CLI prints only the terminal-safe summary; the full record remains available to Python callers in `PairedTrialResult.record`. Exit 5. |
| Existing output directory | Refused before inference. Exit 5. |
| A target did not decompile in a valid wildcard report (one or both trials) | `state: analysis_failure_recorded`: no request, no provider, zero attempts and tokens. The other trial runs normally. `pair_status: target_analysis_failure_observed`, `interpretation: not_evaluated`. Exit 1. |
| A target failure under an exact selector, an auto-analysis timeout, or no function decompiled | Invalid input: Phase 2 refuses to publish or bind such a report. Exit 2. |
| The target is missing from, or ambiguous in, a wildcard report | Invalid input (`function_not_found`, `ambiguous_function`). Exit 2. |

No trial or inference request is retried by the runner. Phase 3A retries
only failures that are definitely not submitted.

### Record (`aegis.lab.paired-trial.v2`)

v2 replaced v1 to represent target-analysis observations. A v1 record is
rejected as `retired_schema_version`; it is never reinterpreted as v2.

- `experiment_id` (random), `pair_id`, `execution_mode: "offline"`, and
  `started_at` / `finished_at` (UTC).
- `provider`: `FakeOffline`, `offline:fake`, `external_disclosure: false`,
  `independent_instance_per_trial: true`.
- `authorization`: the manifests' reference and scope,
  `is_execution_permission: false`, `core_attack_lab_gates:
  "not_integrated"`, `live_inference: "disabled"`.
- `order`: derivation, seed, `seed_source` (`operator` / `generated`) and
  sequence.
- `preparation`: the options needed to re-prepare the pair.
- `comparability`: the controls that were checked, the observed Ghidra
  runtime and `final_artifacts_identical`. It distinguishes shared settings
  from generated requests:
  - `declared_settings: "verified_for_both_trials"`: budgets, access, workflow
    and configuration digests were checked for both trials, whatever their
    analysis observed.
  - `effective_request_settings` and `model_facing_task`: `identical` only
    when both requests exist, otherwise `not_compared`.
- `trials` (baseline, then protected), each with:
  - `trial_id`, `manifest_sha256`, `artifact_sha256`, and the evidence
    digest and size;
  - `analysis`: the selector kind (`exact` / `wildcard`), `status`
    (`decompiled` / `decompilation_failed`), Ghidra's `decompile_status`, and
    the report's function, decompiled and failed counts. For a failure it
    also holds `failure`: the status, the exporter's error and decompiler
    message, each with SHA-256 and length, and the text kept verbatim when it
    is valid text (otherwise `withheld: "invalid_text"`), plus the truncation
    flag. The text is never printed to the terminal.
  - `prepared` (prompt digest, prompt token bound, reservation, findings),
    or `null` exactly when the target failed to decompile;
  - `execution_position` and `state` (`record_produced`, `interrupted`,
    `execution_refused`, `internal_error`, `not_started`,
    `analysis_failure_recorded`);
  - `outcome`, derived from the state and record: `candidate_received`,
    `reconstruction_not_completed`, `reconstruction_interrupted`,
    `execution_error`, `not_attempted_target_analysis_failed` or
    `not_attempted_run_stopped`;
  - `runner_wall_seconds`;
  - a `reconstruction` reference (file, `file_sha256`, `record_sha256`,
    status, stop reason, candidate digest, publication result);
  - `resources` (attempts, submitted attempts, charged and reported tokens,
    usage completeness, reservation overrun, elapsed time). These are all
    zero for an analysis-failure trial;
  - `error`.
- `totals`, `errors`, `outcome`, `not_established`, `limitations` and
  `record_signed: false`.

`outcome` describes **workflow completion only**:

- `run_status`: `finished`, `interrupted`, `execution_refused`,
  `internal_error` or `publication_failed`.
- `workflow_complete`, `trials_with_record`, `trials_completed` and
  `trials_not_attempted_analysis_failed`.
- `pair_status`, in this order of precedence:
  - `incomplete`;
  - `target_analysis_failure_observed`;
  - `candidates_received_for_both_trials`;
  - `trial_failures`.
- `interpretation: "not_evaluated"`.
- `candidate_origin: "offline_fake_provider"`.
- These fields are fixed: `scoring: "not_performed"`,
  `reconstruction_success_established: false` and
  `protection_effect_established: false`.

"Candidates received" is **not** successful reconstruction. No `resisted` or
`bypassed` outcome exists. The two `*_established: false` fields mean that those
properties have **not been evaluated or established**, not that reconstruction
failed or protection was ineffective. No `ready_for_independent_scoring` claim
is emitted; scripted offline candidates provide no model-reconstruction evidence.

`parse_paired_trial_record` uses strict JSON (no duplicate keys or NaN) and
a strict schema. It also re-derives these values from the trial facts:

- the execution order, from the seed;
- the execution positions;
- each trial's state rules;
- its derived `outcome`;
- the consistency of its analysis observation;
- an exact selector reporting exactly one successfully decompiled function;
- `prepared` being present exactly when the target decompiled;
- zero resources without a request;
- the run status;
- `workflow_complete`, the trial counts and `pair_status`;
- whether generated requests are marked compared;
- the totals and the error list;
- `final_artifacts_identical`.

A stored summary therefore cannot contradict the stored trials.

`verify_experiment` (CLI `verify`) reloads the directory. It checks each
published trial record's file digest and canonical digest, parses it
strictly with Phase 3A rules, and compares every field the paired record
repeats: identities, inputs, prompt digest, prompt bound, status, stop
reason, candidate digest, resources and provider. This detects an edit such
as a changed `trial_id` with recomputed digests, which Phase 3A alone cannot
detect. When both manifests and both reports are given, it re-runs
`prepare_pair` and compares the manifest, artifact, evidence and prompt
digests, evidence size, prepared bounds and findings, authorization audit
reference/scope and observed Ghidra runtime. It also compares the complete
target-analysis observation and the presence or absence of a prepared request.
An analysis-failure trial has no reconstruction record to reload, so its
observation can be revalidated **only** against the inputs. An internally
consistent but replaced observation passes `verify` without inputs.

**Records are unsigned.** Verification establishes consistency between the
files, not who wrote them.

### Commands

```sh
.venv/bin/python -m aegis_lab.paired_trial run \
  --baseline-manifest BASELINE.json --protected-manifest PROTECTED.json \
  --baseline-evidence baseline/ghidra-analysis.json \
  --protected-evidence protected/ghidra-analysis.json \
  --output-dir /tmp/aegis-paired-1 --mode offline [--order-seed N] \
  [--blinded] [--max-output-tokens N] [--top-p X]

.venv/bin/python -m aegis_lab.paired_trial verify /tmp/aegis-paired-1 \
  [--baseline-manifest ... --protected-manifest ... \
   --baseline-evidence ... --protected-evidence ...]
```

Preparing the inputs uses the existing commands:

1. `python -m aegis_lab.evidence ghidra-tool --headless ... --function F`
   prints the Ghidra tool to declare in both manifests.
2. `python -m aegis_lab.reconstruction plan --max-model-tokens N [--blinded]`
   prints the three attack digests. `attack.provider` must be
   `FakeOffline`.
3. `python -m aegis_lab.ghidra --function F ...` produces one report per
   artifact.

`run` prints a terminal-safe JSON summary (no paths, evidence or candidate
text). `verify` prints the same summary plus a `verification` line.

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | both trials received a candidate (unscored) |
| 1 | records published, but at least one trial did not receive a candidate (including a recorded target-analysis failure), or execution was refused |
| 2 | invalid input or incomparable pair; `verify` found an inconsistency (no inference) |
| 3 | internal error |
| 5 | publication failed (the output directory exists or was replaced, or a record could not be written) |
| 130 | interrupted (records published where possible) |

Errors print `<role>: <field path>: <code>` only. Roles are
`baseline-manifest`, `protected-evidence`, `pair`, `pair-evidence`,
`<variant>-preparation`, `<variant>-provider`, `output-dir`,
`<variant>-reconstruction`, `paired-record` and `inputs`. Rejected values
and paths are never printed.

### Limitations

- Offline `FakeOffline` only. Its token figures and candidates are
  scripted, so the recorded "resources" describe the fake run, not model
  consumption.
- `max_tool_calls` is neither consumed nor enforced. The model gets no
  tools, and the Ghidra analysis ran before the trial and is not counted.
- Each trial's prompt token bound depends on its own evidence. Reservations,
  and the number of attempts a token budget allows, can therefore differ
  between the trials. Both values are recorded.
- The order seed is recorded, not committed in advance. An operator-chosen
  seed could have been picked after the fact.
- Only wildcard target failures are recorded as observations. Exact-selector
  failures, auto-analysis timeouts and reports with no successful
  decompilation are still invalid input. They exit 2 and produce no paired
  record (see below).
- The output directory's identity is checked before each publication, and
  `publish_new_file` re-checks it around the link. A substitution between
  those checks is not fully excluded. `verify` detects mismatched content
  by digest.
- An interrupt during the final paired-record publication (including the first
  interrupt of the run) can prevent
  `paired-trial.json` from being written. Trial records already published
  remain, and `verify` reports `paired-record: not_found` if it was not linked.
  If already linked, the complete record remains. There is no resume/recovery
  command; preserve the partial directory and use a new directory for another run.
- `runner_wall_seconds` is not revalidated on reload.

### Target-analysis failures

**Supported: a failed target in a valid wildcard report.** When Ghidra runs
with `--function '*'`, a report can show that the target function failed to
decompile (`timed_out`, `cancelled`, `failed_to_start` or `failed`) while at
least one other function decompiled. Phase 2 validates and binds such a
report normally (artifact, tool and configuration). Phase 3A refuses the
target with `selected_function_failed`. Phase 3B then records the
observation instead of discarding the experiment. This happens only when
all of the following hold:

- the report bound to this trial's own manifest;
- exactly one exported function matches the target;
- that function failed;
- the selector was `*`;
- Phase 3A's refusal code was exactly `selected_function_failed`;
- the trial's declared settings pass the same checks as a prepared trial
  (language, output-token bounds, prompt template, sampling and workflow
  digests, and the provider name).

Otherwise the input stays invalid.

The trial has no request and no provider, and records zero attempts and
tokens. The other trial runs normally, and both, one or neither trial may
fail this way. The failure is **not evaluated**. It does not establish
protection, reverse-engineering resistance, a failed behavioral
reconstruction or any hidden-test result. It is an observation about this
Ghidra configuration on this artifact. A decompiler timeout, for example,
depends on host speed.

**Unsupported (still invalid input, exit 2):**

- a failed target under an exact selector;
- an auto-analysis timeout;
- a report in which no function decompiled;
- a missing or ambiguous target.

For the first three, the worker publishes no report, and the binder rejects
an edited report that claims them. Accepting those reports would weaken
Phase 2.

**Interface a future Phase 2 task would need for those cases.** A new,
versioned record would be required. It is not implemented, and its name is
only a proposal, for example `aegis.lab.ghidra-failure.v1`. The worker would
publish it, through the same exclusive publication, when analysis fails. It
would need to carry:

- the artifact SHA-256 the worker computed, plus Ghidra's own digest when it
  was available;
- the launcher, `application.properties` and exporter digests, and the full
  `ghidra-configuration.v1` field set, so `configuration_sha256` binds it to
  the declared tool exactly as reports are bound today;
- the selector;
- a fixed failure category (`analysis_timeout`, `selected_function_failed`,
  `no_function_decompiled`, `exporter_error`) and the bounded, redacted
  diagnostics;
- the observed runtime (release, build date, Java), and the log byte count
  and truncation flag.

`aegis_lab.evidence` would then need a `bind_ghidra_failure(manifest,
bytes)` that applies the same artifact and tool checks. Phase 3B would accept
either a bound report or a bound failure record per trial. The record would
also need an explicit worker exit classification, so that a crash or kill is
not mistaken for an analysis outcome. That is a separate, scoped change to
Phase 2.

### Tests

`tests/test_paired_trial.py` contains 130 offline tests and 1 opt-in
real-Ghidra test for the paired workflow. They cover:

- role, comparability, evidence and preparation failures before inference;
- provider independence and the live-provider refusal;
- seed reproducibility, including a fixed derivation vector;
- trial identity under both orders, and cross-trial isolation;
- one or both trials failing, deadline and budget failures, and
  interruptions during a provider call, during record publication and
  between trials;
- refused and crashed executions, and partial and paired-record publication
  failures;
- directory replacement;
- 29 kinds of record tampering;
- verification of rewritten, swapped, missing and identity-forged files;
- the CLI, and a check that no candidate is executed (process creation is
  patched to fail).

`tests/test_paired_trial_analysis.py` contains 64 offline tests and 1 opt-in
real-Ghidra test for target-analysis failures. They cover:

- a wildcard pair whose targets both decompile;
- only the baseline target failing, only the protected target failing, and
  both, under both execution orders;
- that no provider is created or called and no reconstruction runs for a
  failed target;
- zero resources and correct totals;
- retained diagnostics (kept and withheld text);
- interruption and partial publication alongside an observation;
- invalid inputs that stay invalid: an exact-selector failure, nothing
  decompiled, a missing or ambiguous target, swapped evidence, a wrong
  artifact hash, a corrupted report, unverifiable digests, an unenforceable
  budget, an invalid language, and a live-provider manifest;
- 21 kinds of contradictory observation and the retired v1 schema;
- replaced observation facts, which are detected against the inputs;
- changed prepared-pair facts rejected before provider creation, exact-selector
  observation counts, and diagnostic secrecy when paired publication fails;
- the CLI.

The opt-in real-Ghidra tests compile AEGIS-owned fixtures, which are never
executed:

- `test_paired_trial.py` runs a full pair. Its "protected" fixture is a
  hand-rewritten stand-in, **not** a Shield output, and says nothing about
  protection.
- `test_paired_trial_analysis.py` compiles a large target. A real Ghidra
  12.1.4 wildcard run with a 1 s decompile timeout reports it as `timed_out`
  while `main` decompiles. Neither report is edited. If a faster host
  decompiles the target within 1 s, the test is **skipped**, not passed.

```sh
AEGIS_GHIDRA_HEADLESS="$HOME/Applications/ghidra_12.1.4_PUBLIC/support/analyzeHeadless" \
  .venv/bin/python -m pytest attack_lab/tests/test_paired_trial.py attack_lab/tests/test_paired_trial_analysis.py -q
```

## Phase 4: independent behavioral scoring (execution disabled)

**Status.** The scoring contracts, the trusted coordinator, the Core
integration, the paired comparison, reload verification and the CLI are all
implemented. **No candidate is compiled or executed.**

- **Authorization belongs to Core.** Core's `CandidateExecutionGrant` and its
  three gates are checked when a session opens and again before every stage.
  The Lab keeps no execution permission of its own.
- **Core refuses real execution in the tested configuration.** Its Firecracker
  runtime answers `SANDBOX_UNAVAILABLE` (`isolation_adr_not_accepted`,
  `containment_unverified`). gVisor has separate missing-runtime prerequisites.
- **Tests inject Core's `ScriptedIsolationRuntime`.** It never runs anything,
  and every record it produces is labeled `test_double`.

Integration details and the open interface question for Role A are in
[docs/phase4-isolation-proposal.md](docs/phase4-isolation-proposal.md). Core's
contract is `core/docs/lab-execution-contract.md`, and the design is ADR 0004
(proposed). Both are owned by Role A.

**Dependency.** `aegis_lab.core_execution`, `behavior_score` and `scoring`
import `aegis_core.lab_authorization` and `aegis_core.lab_execution`. Those
modules come from Role A's `feat/core-lab-execution` branch, which is not yet
merged. Until it is, run the Phase 4 Core tests with that Core on `PYTHONPATH`.
Without it, they are **skipped**, which means not run.

Modules:

- `aegis_lab.c_abi`: the C ABI `aegis.lab.c-abi.scalar-u32.v1` and the generated
  harness.
- `aegis_lab.hidden_suite`: the hidden suite, `aegis.lab.hidden-suite.v1`.
- `aegis_lab.scoring_policy`: the sandbox policy (`aegis.lab.sandbox-policy.v1`)
  and the scorer identity.
- `aegis_lab.core_execution`: the grant-binding checks, Core's decision and
  session, and `CoreSessionWorker`.
- `aegis_lab.scoring_worker`: the Lab-side worker protocol models.
- `aegis_lab.behavior_score`: the per-trial record, `aegis.lab.behavior-score.v1`.
- `aegis_lab.scoring`: the paired comparison (`aegis.lab.behavior-comparison.v1`),
  verification and the CLI.

### Interface (`aegis.lab.c-abi.scalar-u32.v1`)

- `label(uint32_t, ...)->uint32_t` in the existing interface notation, with 0 to
  16 parameters, ASCII only and matched exactly. Other types, pointers, `void`,
  variadics and more than 16 parameters are `unsupported_*`. Anything else is
  `interface_invalid`.
- The C function called is the reconstruction task's `function_label`
  (`target_function` when blinded). No target name is special-cased. ImageLab's
  three-, four- and seven-argument kernels fit, and so does any other function of
  this shape.
- Core receives three files:
  - the candidate as `candidate.c`;
  - `aegis_harness.c`;
  - `aegis_candidate_unit.c`, which declares the prototype and includes the
    candidate, so a definition with the wrong types fails to compile.

  The harness depends only on the arity and the symbol, so it contains no test
  data. Only `aegis_harness.c` and `aegis_candidate_unit.c` are passed as
  `translation_units`; `candidate.c` is staged and included, never compiled on its
  own.
- The observed result is exactly one `AEGIS-RESULT <decimal>\n` line.

### Hidden suite (`aegis.lab.hidden-suite.v1`)

A suite is a scorer-side file that must never enter an attacker workspace,
prompt, runtime or retry.

- `scoring.hidden_test_suite_sha256` is SHA-256 over the **exact file bytes**.
- Cases are `c0001`, `c0002`, ... in order (opaque), each with frozen reference
  expectations.
- Strict types.
- Equal arguments with different expectations are rejected as
  `contradictory_expectations`.
- `audit_suite` re-checks expectations against a trusted reference callable.

### Policy, scorer identity and the Core grant

- `aegis.lab.sandbox-policy.v1` pins what the Lab expects Core to attest:
  - the runtime name (`firecracker`, `gvisor-runsc` or `aegis-test-double`) and
    version;
  - the runtime and **rootfs** digests, plus the **guest kernel**, **guest
    agent** and **containment-verification** digests for Firecracker;
  - the compiler identity;
  - the allowlisted compiler flags;
  - the compile and execution limits, with the same fields and ranges as Core's
    `CompileLimits` and `SandboxLimits`.
- `python -m aegis_lab.scoring plan --policy P` prints the `scoring.scorer`
  identity to declare in the manifests.
- **Core's grant** must describe the Lab's inputs exactly. The Lab checks this
  before contacting Core (`ExecutionRefused` with a `grant_*` code):
  - the authorization reference is the manifest's;
  - `lab_bindings` equal the pair id, the suite digest, `policy.sha256()` and
    the scorer-configuration digest;
  - each trial is listed as `candidate_id = trial_id`, with the exact candidate
    SHA-256 and its own manifest target;
  - the stages include compile and execute, and the flags and limits equal the
    policy;
  - the budgets cover the whole suite.

  Core then applies its gates, window and ceilings (`core_refused`) and its
  runtime preflight (`sandbox_unavailable`).
- **Budgets are grant-wide.** Core keeps a persistent ledger, and the Lab reads it
  before opening any session:
  - a grant whose remaining budget cannot cover the trials is refused upfront
    (`grant_budget_insufficient`);
  - a reused grant id with other contents is refused
    (`core_refused (grant_ledger_conflict)`);
  - budget consumed elsewhere mid-run stops as `incomplete` / `core_refused`.

  Interrupted runs keep their reservations.

### What the coordinator checks, in order

1. **Inputs** (`prepare_scoring`; nothing runs):
   - Ghidra evidence bound to the manifest;
   - the strict reconstruction record, with the candidate digest recomputed;
   - every identity: trial, pair, variant, manifest, artifact, evidence, target
     and interface;
   - the suite digest and interface;
   - the scorer identity;
   - `max_cases`.
2. **Interface and candidate:** an unsupported interface (`unsupported_interface`)
   or a missing candidate (`not_evaluated`) never contacts Core.
3. **Permission:** the grant binding, then Core's decision, then Core's session.
   A caller-injected runtime must attest `test_double`.
4. **Stages through Core:**
   - preflight: the attestation must match the policy's runtime, rootfs and
     compiler;
   - one compilation;
   - one execution per case, carrying only that case's decimal arguments;
   - session close.

   Each Core record is cross-checked against the request.

### Classifications

- **Per case:**
  - `match` and `mismatch`;
  - `runtime_crash`, `timeout`, `resource_limit_exceeded` and
    `malformed_output`;
  - `infrastructure_failure`, which stops the run;
  - `not_evaluated`.
- **Per trial:**
  - `behavioral_match`, `behavioral_mismatch`, `compilation_failed`;
  - `unsupported_interface`, `infrastructure_failure`;
  - `incomplete`: deadline, Core refusal in mid-run (`core_refused` with
    `refusal_reason`), interruption, not started;
  - `not_evaluated`.
- `all_hidden_tests_pass` holds **only** for `behavioral_match`.
- Infrastructure is never a candidate result. These are all
  `infrastructure_failure`:
  - Core `SANDBOX_FAILED`;
  - a contract violation;
  - a Core record that does not match its request (`core_record_mismatch`);
  - a failed close.

### Records

- **`aegis.lab.behavior-score.v1`** has a deterministic `result` section
  (`result_sha256`):
  - it records the grant id, digest and reference
    (`core_gates: checked_by_core_before_every_stage`, `grant_signed: false`);
  - it marks the worker as a Core session (`core_contract`);
  - it holds no case arguments, expected values or observed return values.

  The `run` section holds the coordinator's timings, the Core session id, and
  each Core record's id and canonical digest.
- **Requested, enforced and measured limits are recorded separately and never
  equated:**
  - `worker.granted_*_limits` are the requested limits from the grant;
  - `worker.enforced_*_limits` are the isolating runtime's `host_enforcement`
    values (cgroup read-back and microVM configuration), validated per stage and
    required to be identical across a stage;
  - `run.host_accounting` holds the host measurements: CPU, memory peak and OOM
    kills.

  A test double has neither enforced values nor accounting. Full canonical Core
  records are retained separately in private archives, including case arguments
  and observed bytes. Expected answers and evaluator state are never copied there.
  Linux cgroup `memory.peak` may exceed `memory.max`; this is valid accounting,
  including during OOM, and does not invalidate the enforced limit record.
- **`counts_as_behavioral_evidence`** is false for a test-double runtime, a
  FakeOffline candidate, no candidate, an outcome that cannot be attributed to
  the candidate, or guest results without independently verified guest integrity.
  A guest-held HMAC key does not establish guest integrity.
  `behaviorally_successful_reconstruction` is never established in this revision.
- **`aegis.lab.behavior-comparison.v1`** references the paired experiment and
  both scores, and requires identical controls. It keeps four things apart: a
  valid candidate, a suite pass or behavioral success, a completed comparison,
  and a protection effect. The protection effect is fixed to `false` in v1.

### Paired scoring

`score_paired_experiment` works in this order:

1. It re-verifies the experiment (`verify_experiment`) and prepares both trials.
2. It checks the grant binding, Core's decision, and opens one Core session per
   scored trial. Each session gets its own runtime: `runtime_factory()` in
   tests, Core's configured runtime otherwise.
3. Only after that does it create the new output directory (0700). A refusal
   leaves nothing behind.
4. It scores baseline, then protected, and publishes
   `baseline-behavior-score.json` and `protected-behavior-score.json` as each
   completes, then `behavior-comparison.json`.

The experiment directory is never modified; its paired record keeps
`scoring: "not_performed"`. `verify_behavior_scores` reloads and cross-checks
all three records.

```sh
.venv/bin/python -m aegis_lab.scoring plan --policy POLICY.json
.venv/bin/python -m aegis_lab.scoring suite-digest SUITE.json     # digest and count only
.venv/bin/python -m aegis_lab.scoring score-pair EXPERIMENT_DIR \
  --baseline-manifest B.json --protected-manifest P.json \
  --baseline-evidence B-ghidra.json --protected-evidence P-ghidra.json \
  --suite SUITE.json --policy POLICY.json --config aegis.toml --grant GRANT.json --output-dir DIR
.venv/bin/python -m aegis_lab.scoring verify SCORE_DIR EXPERIMENT_DIR [inputs] [--suite S] [--policy P]
```

`score-pair` uses Core's configured runtime only, and in this revision Core
refuses (exit 4) before anything is created.

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | records published |
| 2 | invalid input or inconsistency (paths and rejected values are never printed) |
| 3 | internal error |
| 4 | execution refused by the grant binding or by Core |
| 5 | publication failed |
| 130 | interrupted |

### Limitations

- Nothing is compiled or executed. Every score produced today uses Core's
  scripted runtime and FakeOffline candidates, and is labeled as such. It is not
  evidence.
- Core's Firecracker implementation remains owner-controlled and unavailable for
  candidate execution pending containment verification and ADR/operator approvals.
  This delivery neither boots a VM nor approves ADR 0004.
- Grants and Lab records are unsigned.

### Tests

These test files need Role A's Core and are skipped without it in the **offline**
profile. `--lab-profile integration` fails on missing Core/Ghidra prerequisites
or any skipped test:

- `tests/test_behavior_score.py`;
- `tests/test_scoring.py`.

These test files have no Core dependency:

- `tests/test_c_abi.py`;
- `tests/test_hidden_suite.py`;
- `tests/test_scoring_policy.py`.

Shared fixtures are in `tests/scoring_fixtures.py`.

```sh
PYTHONPATH=/path/to/feat-core-lab-execution/core/src \
  .venv/bin/python -m pytest attack_lab/tests -q
```
