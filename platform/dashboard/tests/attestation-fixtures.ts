// Synthetic protocol fixtures only; never evidence of signing or protection.
import type { Attestation } from "../src/attestation.ts";
export const digest = "a".repeat(64);
export const jobId = "1".repeat(32);
export const output = { artifact_id: "2".repeat(32), name: "protected.ll", sha256: digest, size_bytes: 12, role: "output" };
export const fixtureJob = { job_id: jobId, status: "succeeded", input_artifact: { ...output, role: "input", name: "fixture.ll" }, output_artifacts: [output], error: null };
export const trust = {
  schema: "aegis.attestation-config.v1",
  signing: { state: "configured", key_id: "b".repeat(64), signer_name: "Synthetic test signer", signer_trusted: true },
  verification: { trusted_key_ids: ["b".repeat(64)] },
  sentinel: { state: "configured", issuer: "Synthetic test issuer", enforcement_mode: "cooperating_enforced", allowed_actions: ["analyze"] },
};
export function fixtureAttestation(status: "verified" | "failed" | "unsigned" = "verified"): Attestation {
  return {
    schema: "aegis.job-attestation.v1", job_id: jobId, job_status: "succeeded", checked_at: "2026-10-30T04:00:00Z",
    signing: { state: "signed", key_id: "b".repeat(64), signer_name: "Synthetic test signer", message: "Test signing record only" },
    sentinel: { state: "created", enforcement_mode: "cooperating_enforced", message: "Test policy record only" },
    artifacts: [{ ...output, signature: { status, error_code: status === "failed" ? "UNTRUSTED_KEY" : null, message: "Synthetic signature response", key_id: "b".repeat(64), signer_name: "Synthetic test signer", manifest_sha256: "c".repeat(64) },
      policy: { status: "valid", policy_id: "3".repeat(32), policy_sha256: "d".repeat(64), enforcement_mode: "cooperating_enforced", permissions: [{ action: "redistribute", allowed: false }], not_before: null, expires_at: null, disclaimer: "Synthetic policy: cooperating tools only.", errors: [] } }],
    limitations: ["Synthetic fixture only. A signature does not establish attack resistance."],
  };
}
export const denied = { schema: "aegis.sentinel-decision.v1", job_id: jobId, artifact_sha256: digest, action: "redistribute", permitted: false, enforcement_mode: "cooperating_enforced", reason: "Synthetic policy denies redistribution", policy_id: "3".repeat(32), caller_id_verified: false, evaluated_at: "2026-10-30T04:00:00Z" };
