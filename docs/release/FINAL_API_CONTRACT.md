# AEGIS final API contract: jobs, signatures and Sentinel policies

Owner: Agent 1 (Core/API/CLI/Provenance/Sentinel). Status: **implemented** in the
working tree (see "Implementation status" at the end for exact test results).
Consumers: Agent 3 (dashboard). Any change to this file needs Agent 1 review.

All existing contracts are **unchanged**. Everything below marked NEW is additive.

## 0. Rules the UI must follow

1. Show **"Signature verified"** only when `artifacts[i].signature.status === "verified"`.
   Nothing else means verified: not `signing.state === "signed"`, not the presence
   of a manifest, not a 200 response.
2. `signing.state === "not_configured"` must be shown as **"Not signed (signing not
   configured)"**, never as a warning-free success and never as verified.
3. `signature.status === "failed"` must show its `error_code` (for example
   `ARTIFACT_TAMPERED`, `UNTRUSTED_KEY`, `SIGNATURE_INVALID`) as a failure.
4. Sentinel policies are **cooperating** rights metadata. Show the `disclaimer` and
   the `enforcement_mode`. Never describe them as DRM, access control on third-party
   tools, or protection. Only AEGIS's own download route enforces them.
5. A valid signature proves that the holder of a trusted key attested to these
   bytes and metadata. It is **not** evidence of protection, originality or
   attack resistance. Show `limitations` verbatim.
6. Never send, store or display private key material. The API never returns it.

## 1. Unchanged routes

| Route | Contract |
| --- | --- |
| `GET /healthz` | unchanged `HealthReport` (200 ok / 503 degraded); open |
| `POST /v1/jobs` | unchanged request `{policy, input:{name, content_base64}}` → 202 `ProtectionJob` |
| `GET /v1/jobs/{job_id}` | unchanged `ProtectionJob` |
| `GET /v1/jobs/{job_id}/report` | unchanged `ProtectionReport` |

Signing and policy creation happen **inside the job run, before the job becomes
terminal**: once `GET /v1/jobs/{id}` says `succeeded`, the attestation below is final.

All `/v1/*` routes use the existing bearer-token gate. Errors use the existing
envelope `{"error": {"code", "message", "details"}}`.

## 2. NEW error codes

| Code | HTTP | CLI exit | Meaning |
| --- | --- | --- | --- |
| `ARTIFACT_NOT_FOUND` | 404 | 6 | sha256 is not a registered **output** of a succeeded job, or the manifest/policy does not exist. `details.kind` ∈ `artifact`, `manifest`, `policy` |
| `POLICY_DENIED` | 403 | 5 | a `cooperating_enforced` Sentinel policy denies the action, or the policy is missing/invalid/modified while Sentinel is configured (fail closed) |
| `ARTIFACT_INTEGRITY_ERROR` (existing) | 409 | 1 | stored bytes no longer match Core's recorded SHA-256; nothing is streamed |

## 3. NEW `GET /v1/attestation` — trust configuration (no secrets, no paths)

```json
{
  "schema": "aegis.attestation-config.v1",
  "signing": {
    "state": "configured" | "not_configured",
    "key_id": "<64 hex>" | null,
    "signer_name": "string" | null,
    "signer_trusted": true | false
  },
  "verification": { "trusted_key_ids": ["<64 hex>", "..."] },
  "sentinel": {
    "state": "configured" | "not_configured",
    "issuer": "string" | null,
    "enforcement_mode": "cooperating_enforced" | "advisory_notice" | null,
    "allowed_actions": ["analyze", "redistribute", "..."]
  }
}
```

`signer_trusted: false` means the signing key is not among the trusted keys, so its
signatures will verify as `failed` / `UNTRUSTED_KEY`.

## 4. NEW `GET /v1/jobs/{job_id}/attestation` — live verification status

Works for every existing job. Verification is recomputed on every request against
the bytes on disk and the operator's trusted keys.

```json
{
  "schema": "aegis.job-attestation.v1",
  "job_id": "<32 hex>",
  "job_status": "pending" | "running" | "succeeded" | "failed",
  "checked_at": "ISO-8601 UTC",
  "signing": {
    "state": "signed" | "not_configured" | "signing_failed" | "not_applicable" | "pending",
    "key_id": "<64 hex>" | null,
    "signer_name": "string" | null,
    "message": "string"
  },
  "sentinel": {
    "state": "created" | "not_configured" | "creation_failed" | "not_applicable" | "pending",
    "enforcement_mode": "cooperating_enforced" | "advisory_notice" | null,
    "message": "string"
  },
  "artifacts": [
    {
      "artifact_id": "<32 hex>",
      "name": "protected.ll",
      "sha256": "<64 hex>",
      "size_bytes": 1234,
      "signature": {
        "status": "verified" | "failed" | "unsigned",
        "error_code": null | "ARTIFACT_TAMPERED" | "SIGNATURE_INVALID" | "UNTRUSTED_KEY"
                    | "KEY_ID_MISMATCH" | "MANIFEST_MALFORMED" | "UNSUPPORTED_VERSION"
                    | "ABSENT_TRUSTED_KEYS" | "ARTIFACT_NOT_FOUND"
                    | "MANIFEST_MISSING" | "RECORD_MISMATCH",
        "message": "string",
        "key_id": "<64 hex>" | null,
        "signer_name": "string" | null,
        "manifest_sha256": "<64 hex>" | null
      },
      "policy": {
        "status": "valid" | "invalid" | "absent",
        "policy_id": "<32 hex>" | null,
        "policy_sha256": "<64 hex>" | null,
        "enforcement_mode": "cooperating_enforced" | "advisory_notice" | null,
        "permissions": [{ "action": "execute", "allowed": false }],
        "not_before": "ISO-8601" | null,
        "expires_at": "ISO-8601" | null,
        "disclaimer": "string" | null,
        "errors": ["string"]
      }
    }
  ],
  "limitations": ["string", "..."]
}
```

- `artifacts` is empty unless `job_status === "succeeded"`.
- `signing.state` / `sentinel.state` are `pending` while the job is not terminal,
  and `not_applicable` for failed jobs.
- `signature.status`:
  - `verified`: Ed25519 signature valid, signing key in the operator's trusted set,
    the bytes on disk hash to Core's recorded SHA-256, and the manifest names the
    same digest, artifact name and job id.
  - `failed`: verification ran and failed; `error_code` says why. `MANIFEST_MISSING`
    = signing was recorded but the manifest file is gone. `RECORD_MISMATCH` = a
    validly signed manifest for a different artifact/job.
  - `unsigned`: no signature exists (signing not configured, or signing failed).
- `policy.status`: `valid` (passes Sentinel validation and matches the digest
  recorded at creation), `invalid` (fails either; `errors` explains), `absent`.

## 5. NEW `GET /v1/jobs/{job_id}/artifacts/{sha256}` — download an output

Returns the exact bytes (`application/octet-stream`,
`Content-Disposition: attachment; filename="<registered name>"`). Only registered
output artifacts of a succeeded job; no caller-supplied path. Bytes are read once,
hashed and compared with Core's record **before** anything is sent.

Response headers: `X-AEGIS-Artifact-SHA256`, `X-AEGIS-Sentinel-Decision` ∈
`permitted` (cooperating policy allows `redistribute`), `advisory` (advisory-only
policy; not enforced), `not_configured` (no Sentinel policy for this job).

Errors: 404 `JOB_NOT_FOUND`, 404 `ARTIFACT_NOT_FOUND`, 409
`ARTIFACT_INTEGRITY_ERROR`, 403 `POLICY_DENIED` (with `details.reason`).

## 6. NEW signed manifest and policy documents

- `GET /v1/jobs/{job_id}/artifacts/{sha256}/manifest` → the stored Ed25519
  `ManifestEnvelope` JSON (as written by `aegis_provenance`). 404
  `ARTIFACT_NOT_FOUND` with `details.kind = "manifest"` when unsigned.
- `GET /v1/jobs/{job_id}/artifacts/{sha256}/policy` → the stored `SentinelPolicy`
  JSON. 404 with `details.kind = "policy"` when absent.

These let anyone verify offline:
`aegis-provenance verify protected.ll --manifest m.json --trusted-key pub.pem`.

## 7. NEW `POST /v1/jobs/{job_id}/artifacts/{sha256}/evaluate` — Sentinel decision

Request (strict, unknown fields rejected):

```json
{ "action": "execute" | "analyze" | "redistribute" | "modify" | "attack_evaluate",
  "caller_id": "string ≤128" | null,
  "environment": "string ≤128" | null }
```

Response 200 (a denial is a decision, not an HTTP error):

```json
{
  "schema": "aegis.sentinel-decision.v1",
  "job_id": "<32 hex>",
  "artifact_sha256": "<64 hex>",
  "action": "execute",
  "permitted": false,
  "enforcement_mode": "cooperating_enforced" | "advisory_notice",
  "reason": "string",
  "policy_id": "<32 hex>" | null,
  "caller_id_verified": false,
  "evaluated_at": "ISO-8601 UTC"
}
```

`caller_id` and `environment` are **asserted by the caller and not authenticated**
(`caller_id_verified` is always `false`). A missing, invalid or modified policy
yields `permitted: false`. 404 `ARTIFACT_NOT_FOUND` (`kind: "policy"`) when no
policy exists for the artifact. Sentinel `attack_evaluate` never opens Core's
attack-lab gates; those remain the config gate plus `AttackLabAuthorization`.

## 8. Operator configuration (`aegis.toml`, additive, off by default)

```toml
[provenance]
enabled = true
# Absolute; outside any Git work tree and outside the store; mode 0600; never generated by AEGIS.
signing_key_path = "/home/operator/.config/aegis/signing-key.pem"
# signing_key_password_env = "AEGIS_SIGNING_KEY_PASSWORD"   # optional, env var NAME only
trusted_public_keys = ["/home/operator/.config/aegis/signing-key.pub.pem"]
signer_name = "AEGIS demo operator"
build_repository = "https://github.com/Youssef-Boussabah/AEGIS"
build_commit = "691ce2717934c22dd30883b5dd8a586ebf78bf20"

[sentinel]
enabled = true
issuer = "AEGIS demo operator"
enforcement_mode = "cooperating_enforced"
allowed_actions = ["analyze", "redistribute"]   # every other action is written as denied
# valid_days = 30
# allowed_caller_ids = ["aegis-api", "aegis-cli"]
```

A broken signing configuration (missing/unreadable key, key inside Git, group- or
world-readable key, wrong password, non-Ed25519 key) **stops API startup and CLI
`protect`, `verify` and `evaluate`** with `CONFIG_INVALID` (exit 3); AEGIS never
falls back to unsigned silently and never generates a key during job execution.
Read-only CLI `inspect` and `report` do not load signing keys. In particular,
`inspect`/`GET /healthz` describe storage and adapter availability, not per-artifact
signature validity; use the attestation routes or `aegis verify` for that.

## 9. Implementation status (30 October 2026, this host)

Implemented exactly as specified above; no field changed from the first
published draft. Code: `aegis_provenance/jobs.py` (lifecycle), Core config /
hook / verified reads, API routes, CLI `verify` and `evaluate`.

| Suite | Result |
| --- | --- |
| Complete Python + real LLVM adapter (fresh `AegisShield.so`, LLVM 22.1.8) | 735 passed, 1 Starlette deprecation warning |
| Default `.venv/bin/pytest` | 596 passed, 1 warning |
| Per package: core / api / cli / provenance / sentinel | 485 / 29 / 21 / 49 / 12 passed |
| Shield CTest (fresh build) | 1/1 passed |

Real end-to-end (real Shield adapter, `annotated.c` fixture, seed 42, operator
key from `aegis-provenance keygen`): CLI and API jobs → both outputs `verified`;
`protected.ll` `4a7da8c1…68a9a` downloaded via API with
`X-AEGIS-Sentinel-Decision: permitted` and re-verified offline with
`aegis-provenance verify` (exit 0); modified copy → `ARTIFACT_TAMPERED` (exit 1);
untrusted key → `UNTRUSTED_KEY` (exit 1); `execute`/`modify` → denied; key mode
0644 → API exits 3 `CONFIG_INVALID`.

Final independent verification at approximately 10:17–10:22 UTC on 30 October:
the current API and dashboard work with genuine signed `llvm-shield` and
`llvm-shield-mirage` jobs. The complete affected Python suite passed **735 tests**
(one Starlette deprecation warning); frontend contracts **14/14**, browser suite
**22/22**, Shield CTest **1/1**, ImageLab CTest **12/12**. Independent live API
checks passed **108 checks**; separate real-browser checks exercised both signed
profiles, tampering, downloads, unsigned states, untrusted signatures, policy
denial and authorization errors. Exact commands, job ids, digests, private demo
workspace, evidence and limitations: [FINAL_SIGNED_DEMO.md](FINAL_SIGNED_DEMO.md).
The earlier audit's standalone-only claims are historical.

Remaining limitations: `scripts/product.py configure` does not write
`[provenance]`/`[sentinel]` (the operator adds them); policy documents are
integrity-checked against `attestation.json` but are not themselves signed;
no Sentinel check on attack-lab submissions. Artifact downloads enforce Core
integrity and Sentinel redistribution permission; they do not require a verified
signature. Thus a missing or invalid manifest does not itself block a download
whose bytes and redistribution policy pass those gates. Consumers must inspect
`signature.status` to claim verification.
