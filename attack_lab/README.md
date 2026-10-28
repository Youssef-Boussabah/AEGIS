# AEGIS Adversarial Lab

Role **B** · branch `feat/lab-mirage` · [issue #10](https://github.com/Youssef-Boussabah/AEGIS/issues/10)

## What this first increment does

`aegis_lab.manifest` defines the **local, versioned experiment record** for an authorized, paired baseline/protected reconstruction trial. It validates the final-artifact identity, attack tool/model identity, attacker access, equal budgets, scoring version and authorization reference. It rejects incomparable trials *before an attacker is run*. `TrialManifest.sha256()` produces a stable record fingerprint, not a signature.

**This increment does not run an attack.** It does not integrate REA, Ghidra, Nebius, generated-code execution, AEGIS Core, or any security scoring. Any claims of attack resistance require a later independent scoring implementation. The authorization field here is *audit metadata*, not permission: actual execution must still satisfy **both** Core gates (`[attack_lab] enabled` and `AttackLabAuthorization`). Nothing in the present Core adapter runner is a sandbox for generated programs.

## Install and test (from repository root)

```sh
uv pip install --python .venv/bin/python -e './attack_lab[dev]'
.venv/bin/python -m pytest attack_lab/tests -q
```

Use `python -m aegis_lab validate-pair BASELINE.json PROTECTED.json` to validate two locally saved manifests; it outputs only pair and manifest digests and never runs an attacker. The example test fixtures in `tests/test_manifest.py` are illustrative, not benchmark evidence.

Python 3.11+, Pydantic 2 and pytest are sufficient. No attack tools, external models or network access are required to test the manifest contract. Existing Core/API/CLI suites are separate:

```sh
.venv/bin/python -m pytest core/tests platform/api/tests platform/cli/tests -q
```

## Contract, v1

- `TrialManifest`: versioned with `schema_version="aegis.lab.trial.v1"` and a unique 32-hex `trial_id` and shared 32-hex `pair_id`.
- `BuildTarget`: final linked/bundled artifact SHA-256, revision, symbol/entry point, platform and reproducible build identity. This is *not* the hash of intermediate LLVM IR.
- `AttackConfig`: `ghidra_model`, `rea` or `custom`, named tool versions, model/provider and prompt SHA-256. Tool binaries can have their own SHA-256. REA is an alternative workflow, not mandatory for Ghidra trials.
- `AccessPolicy`: concrete symbol, original-source, runtime oracle, network and retrieval permissions.
- `AttackBudget`: bounded wall-clock seconds, tokens, tool calls, attempts.
- `ScoringPlan`: hash of hidden test suite, declared interface, currently an all-tests-pass rule. Do not expose hidden tests to the attacker.
- `AuthorizationReference`: traceable authorizer reference and scope, **not approval to execute**.
- `validate_pair(a,b)`: verifies exactly one baseline and one protected trial, distinct trial/artifact IDs, and identical source target, tooling, budgets, access, scoring and authorization. Protection build recipes are allowed to differ but share a matched build profile.

## Next increments

1. Add a **trial runner contract** and outcome classifier, with no false success on errors or incomplete comparisons.
2. Integrate **Ghidra** analysis under bounded trusted subprocess execution, with pinned versions and saved structured evidence.
3. Integrate a **Nebius model provider** with pinned identity, explicit token budgets and sanitized traces.
4. Implement **isolated compilation and scoring** of agent-generated candidate implementations, with hidden tests outside the attacker environment.
5. Implement a separate **REA workflow adapter** using the same record, scoring and budget contract, noting which internal tools REA invokes.
6. Expose a real `aegis.adapter.v1` `attack_lab` backend only after dual authorization and isolation are tested. Coordinate any Core changes with role A.
7. Build **Mirage** decoys with no-decoy controls and measure functional equivalence, retention, overhead and reconstruction outcomes.

This module remains independent of ImageLab, PhotoCraft, reVC and Mattermost; no target-name logic is allowed in the generic code. Hold out unseen software during effectiveness evaluation.
