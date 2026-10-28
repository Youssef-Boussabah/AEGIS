# AEGIS Adversarial Lab

Role **B** · branch `feat/lab-mirage` · [issue #10](https://github.com/Youssef-Boussabah/AEGIS/issues/10)

## What this first increment does

`aegis_lab.manifest` defines the **local, versioned experiment record** (`aegis.lab.trial.v2`) for an authorized, paired baseline/protected reconstruction trial. It records the final-artifact identity, shared build conditions, the one permitted protection step, attack tool/workflow/model identity bound by digests, attacker access, equal budgets, scorer identity and an authorization reference. It rejects incomparable declarations *before an attacker is run*. `TrialManifest.sha256()` produces a stable record fingerprint, not a signature.

A manifest is a **declaration**. Its digests are the author's claims, and matching manifest fields do not prove that a comparison is scientifically fair. Three kinds of record are kept separate: declared configuration (the manifest), checked evidence (not implemented) and attack outcomes (not implemented).

**The manifest does not run an attack.** It does not integrate REA, Ghidra, Nebius, generated-code execution, AEGIS Core, or any security scoring. Any claims of attack resistance require a later independent scoring implementation. The authorization field here is *audit metadata*, not permission: actual execution must still satisfy **both** Core gates (`[attack_lab] enabled` and `AttackLabAuthorization`). Nothing in the present Core adapter runner is a sandbox for generated programs.

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
2. Integrate **Ghidra** analysis under bounded trusted subprocess execution, with pinned versions and saved structured evidence.
3. Integrate a **Nebius model provider** with pinned identity, explicit token budgets and sanitized traces.
4. Implement **isolated compilation and scoring** of agent-generated candidate implementations, with hidden tests outside the attacker environment.
5. Implement a separate **REA workflow adapter** using the same record, scoring and budget contract, noting which internal tools REA invokes.
6. Expose a real `aegis.adapter.v1` `attack_lab` backend only after dual authorization and isolation are tested. Coordinate any Core changes with role A.
7. Build **Mirage** decoys with no-decoy controls and measure functional equivalence, retention, overhead and reconstruction outcomes.

This module remains independent of ImageLab, PhotoCraft, reVC and Mattermost; no target-name logic is allowed in the generic code. Hold out unseen software during effectiveness evaluation.
