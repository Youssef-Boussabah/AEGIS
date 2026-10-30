import { shaPattern, terminal } from "./contracts.ts";
import type { Artifact, Job, Status } from "./contracts.ts";

export type Enforcement = "cooperating_enforced" | "advisory_notice";
export const policyActions = ["execute", "analyze", "redistribute", "modify", "attack_evaluate"] as const;
export type PolicyAction = typeof policyActions[number];
export type AttestedArtifact = Omit<Artifact, "role"> & {
  artifact_id: string;
  signature: { status: "verified" | "failed" | "unsigned"; error_code: string | null; message: string; key_id: string | null; signer_name: string | null; manifest_sha256: string | null };
  policy: { status: "valid" | "invalid" | "absent"; policy_id: string | null; policy_sha256: string | null; enforcement_mode: Enforcement | null; permissions: { action: PolicyAction; allowed: boolean }[]; not_before: string | null; expires_at: string | null; disclaimer: string | null; errors: string[] };
};
export type Attestation = {
  schema: "aegis.job-attestation.v1"; job_id: string; job_status: Status; checked_at: string;
  signing: { state: "signed" | "not_configured" | "signing_failed" | "not_applicable" | "pending"; key_id: string | null; signer_name: string | null; message: string };
  sentinel: { state: "created" | "not_configured" | "creation_failed" | "not_applicable" | "pending"; enforcement_mode: Enforcement | null; message: string };
  artifacts: AttestedArtifact[]; limitations: string[];
};
export type TrustConfig = {
  schema: "aegis.attestation-config.v1";
  signing: { state: "configured" | "not_configured"; key_id: string | null; signer_name: string | null; signer_trusted: boolean };
  verification: { trusted_key_ids: string[] };
  sentinel: { state: "configured" | "not_configured"; issuer: string | null; enforcement_mode: Enforcement | null; allowed_actions: PolicyAction[] };
};
export type Decision = { schema: "aegis.sentinel-decision.v1"; job_id: string; artifact_sha256: string; action: PolicyAction; permitted: boolean; enforcement_mode: Enforcement; reason: string; policy_id: string | null; caller_id_verified: false; evaluated_at: string };
const obj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown): v is string => typeof v === "string";
const nullable = (v: unknown) => v === null || str(v);
const digest = (v: unknown) => str(v) && shaPattern.test(v);
const optionalDigest = (v: unknown) => v === null || digest(v);
const id = (v: unknown) => str(v) && /^[0-9a-f]{32}$/.test(v);
const optionalId = (v: unknown) => v === null || id(v);
const strings = (v: unknown): v is string[] => Array.isArray(v) && v.every(str);
const date = (v: unknown) => str(v) && Number.isFinite(Date.parse(v));
const mode = (v: unknown) => v === "cooperating_enforced" || v === "advisory_notice";
const optionalMode = (v: unknown) => v === null || mode(v);
const action = (v: unknown) => policyActions.includes(v as PolicyAction);

export function parseTrustConfig(v: unknown): TrustConfig {
  if (!obj(v) || v.schema !== "aegis.attestation-config.v1" || !obj(v.signing) || !["configured", "not_configured"].includes(String(v.signing.state)) ||
    !optionalDigest(v.signing.key_id) || !nullable(v.signing.signer_name) || typeof v.signing.signer_trusted !== "boolean" ||
    !obj(v.verification) || !Array.isArray(v.verification.trusted_key_ids) || !v.verification.trusted_key_ids.every(digest) ||
    !obj(v.sentinel) || !["configured", "not_configured"].includes(String(v.sentinel.state)) || !nullable(v.sentinel.issuer) ||
    !optionalMode(v.sentinel.enforcement_mode) || !Array.isArray(v.sentinel.allowed_actions) || !v.sentinel.allowed_actions.every(action)) throw new Error("Invalid attestation configuration response");
  return v as TrustConfig;
}

/** Bind verification results to the loaded job and its Core-recorded output bytes. */
export function parseAttestation(v: unknown, job: Job): Attestation {
  if (!obj(v) || v.schema !== "aegis.job-attestation.v1" || v.job_id !== job.job_id || v.job_status !== job.status || !date(v.checked_at) ||
    !obj(v.signing) || !["signed", "not_configured", "signing_failed", "not_applicable", "pending"].includes(String(v.signing.state)) || !optionalDigest(v.signing.key_id) || !nullable(v.signing.signer_name) || !str(v.signing.message) ||
    !obj(v.sentinel) || !["created", "not_configured", "creation_failed", "not_applicable", "pending"].includes(String(v.sentinel.state)) || !optionalMode(v.sentinel.enforcement_mode) || !str(v.sentinel.message) ||
    !strings(v.limitations) || !Array.isArray(v.artifacts) || (job.status !== "succeeded" && v.artifacts.length !== 0) ||
    (job.status === "succeeded" && v.artifacts.length !== job.output_artifacts.length)) throw new Error("Invalid or mismatched attestation response");
  const seen = new Set<string>();
  for (const a of v.artifacts) {
    if (!obj(a) || !id(a.artifact_id) || !digest(a.sha256) || !str(a.name) || !Number.isSafeInteger(a.size_bytes) ||
      !job.output_artifacts.some(o => o.sha256 === a.sha256 && o.name === a.name && o.size_bytes === a.size_bytes) || seen.has(String(a.artifact_id)) ||
      !obj(a.signature) || !["verified", "failed", "unsigned"].includes(String(a.signature.status)) || !nullable(a.signature.error_code) || !str(a.signature.message) ||
      !optionalDigest(a.signature.key_id) || !nullable(a.signature.signer_name) || !optionalDigest(a.signature.manifest_sha256) ||
      (a.signature.status === "failed" ? !str(a.signature.error_code) : a.signature.error_code !== null) ||
      (a.signature.status === "verified" && (!digest(a.signature.key_id) || !digest(a.signature.manifest_sha256) || v.signing.state !== "signed")) ||
      !obj(a.policy) || !["valid", "invalid", "absent"].includes(String(a.policy.status)) || !optionalId(a.policy.policy_id) || !optionalDigest(a.policy.policy_sha256) ||
      !optionalMode(a.policy.enforcement_mode) || !nullable(a.policy.disclaimer) || !strings(a.policy.errors) ||
      !(a.policy.not_before === null || date(a.policy.not_before)) || !(a.policy.expires_at === null || date(a.policy.expires_at)) ||
      !Array.isArray(a.policy.permissions) || !a.policy.permissions.every(p => obj(p) && action(p.action) && typeof p.allowed === "boolean")) throw new Error("Invalid artifact signature or policy response");
    seen.add(a.artifact_id as string);
  }
  if ((!terminal(job.status) && (v.signing.state !== "pending" || v.sentinel.state !== "pending")) ||
    (job.status === "failed" && (v.signing.state !== "not_applicable" || v.sentinel.state !== "not_applicable"))) throw new Error("Inconsistent attestation lifecycle");
  return v as Attestation;
}

export function parseDecision(v: unknown, jobId: string, sha: string, requestedAction: PolicyAction): Decision {
  if (!obj(v) || v.schema !== "aegis.sentinel-decision.v1" || v.job_id !== jobId || v.artifact_sha256 !== sha || v.action !== requestedAction ||
    typeof v.permitted !== "boolean" || !mode(v.enforcement_mode) || !str(v.reason) || !optionalId(v.policy_id) || v.caller_id_verified !== false || !date(v.evaluated_at)) throw new Error("Invalid or mismatched Sentinel decision");
  return v as Decision;
}

export function saveBlob(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a"); a.href = url; a.download = name; a.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export async function downloadArtifact(jobId: string, artifact: Artifact, token: string): Promise<string> {
  const response = await fetch(`/v1/jobs/${jobId}/artifacts/${artifact.sha256}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {}, signal: AbortSignal.timeout(60000),
  });
  if (!response.ok) {
    let data: unknown;
    try { data = await response.json(); } catch { throw new Error(`Artifact download failed: HTTP ${response.status}`); }
    throw new Error(obj(data) && obj(data.error) && str(data.error.code) && str(data.error.message) ? `${data.error.code}: ${data.error.message}` : `Artifact download failed: HTTP ${response.status}`);
  }
  const decision = response.headers.get("X-AEGIS-Sentinel-Decision");
  if (response.headers.get("X-AEGIS-Artifact-SHA256") !== artifact.sha256 || !["permitted", "advisory", "not_configured"].includes(decision ?? "")) throw new Error("Artifact download headers do not match the recorded artifact");
  const bytes = await response.arrayBuffer();
  const sha = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))).map(b => b.toString(16).padStart(2, "0")).join("");
  if (bytes.byteLength !== artifact.size_bytes || sha !== artifact.sha256) throw new Error("Artifact SHA-256 or size mismatch; download refused");
  saveBlob(new Blob([bytes], { type: "application/octet-stream" }), artifact.name);
  return `Downloaded ${artifact.name}; SHA-256 matches Core. Sentinel: ${decision}.`;
}
