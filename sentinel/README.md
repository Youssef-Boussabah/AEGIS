# AEGIS Sentinel: Rights & Usage Policy Records

**Module:** `sentinel/`  
**Role:** D — Signature, Sentinel & Verification  
**Branch:** `feat/signature-sentinel`  
**Tracking:** Issue [#12](https://github.com/Youssef-Boussabah/AEGIS/issues/12)  
**Status:** Implemented and tested.

---

## 1. Overview

`aegis-sentinel` provides versioned, machine-readable rights and usage policy records linked to protected artifacts and cryptographic provenance manifests.

Cooperating tools in the AEGIS ecosystem query Sentinel policies to determine whether runtime execution, analysis, redistribution, or modification is permitted under declared constraints.

### Boundary & Enforcement Notice
- **Notice vs Enforcement:** Sentinel policies explicitly declare whether they are an `advisory_notice` or `cooperating_enforced`.
- **Third-Party Boundary:** Merely publishing a JSON policy document does **not** compel non-cooperating third-party tools to comply. Enforcement requires a cooperating runtime, loader, or orchestrator gate.

---

## 2. Policy Schema

A Sentinel policy covers:
- `schema_version`: Literal string `"1"`.
- `policy_id`: 32-character hex identifier.
- `issuer`: Name of issuing authority.
- `issued_at`: ISO-8601 UTC timestamp.
- `enforcement_mode`: `advisory_notice` or `cooperating_enforced`.
- `target_artifact`: Linked artifact name, SHA-256 digest, and optional provenance manifest reference.
- `permissions`: List of specific actions (`execute`, `analyze`, `redistribute`, `modify`, `attack_evaluate`) with boolean allow/deny flags, scopes, and notes. Ambiguous duplicate entries for an action are rejected.
- `constraints`: Optional temporal window (`not_before`, `expires_at`), permitted environments, authorized caller IDs, and watermark requirements (`watermark_required`).
- `disclaimer`: Standard notice stating that publishing metadata alone does not compel third-party compliance.

---

## 3. CLI Usage

The package exposes the `aegis-sentinel` CLI tool (also runnable via `python -m aegis_sentinel.cli`).

### Create a Policy Record
```bash
aegis-sentinel create build/output/protected.ll \
  --issuer "AEGIS Release Authority" \
  --mode cooperating_enforced \
  --allow-analyze \
  -o build/output/sentinel_policy.json
```

### Validate a Policy
```bash
aegis-sentinel validate build/output/sentinel_policy.json
```

### Inspect a Policy
```bash
aegis-sentinel inspect build/output/sentinel_policy.json
```

### Evaluate an Action
```bash
aegis-sentinel evaluate build/output/sentinel_policy.json \
  --action execute \
  --artifact build/output/protected.ll
```

Exit codes:
- `0`: Permitted / Valid
- `1`: Denied / Invalid policy
- `2`: Missing file or argument error

---

## 4. Use in AEGIS jobs and fail-closed evaluation

- With `[sentinel]` configured, every output of a succeeded AEGIS job gets a
  policy (listed `allowed_actions` allowed, all other actions explicitly
  denied), created by `aegis_provenance.jobs` and checked with this package's
  validator. AEGIS's artifact download is the cooperating enforcement point
  (`redistribute`); see ARCHITECTURE.md §8a.
- `evaluate_action` now **fails closed** when a policy restricts
  `allowed_caller_ids` or `environments` and the caller supplies none
  (previously the restriction was skipped).
- Note: `aegis-sentinel create` still allows `execute` unless `--deny-execute`
  is passed; AEGIS-created job policies do not use that default.
- Caller ids and environments are asserted by the caller, not authenticated.
  Sentinel's `attack_evaluate` permission never opens AEGIS attack-lab gates.
