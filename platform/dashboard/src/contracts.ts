export type Status = "pending" | "running" | "succeeded" | "failed";
export type Artifact = { name: string; sha256: string; size_bytes: number; role: string };
export type Failure = { code: string; message: string; details: Record<string, unknown> };
export type Job = { job_id: string; status: Status; input_artifact: Artifact; output_artifacts: Artifact[]; error: Failure | null };
export type Report = Job & { summary: string; limitations: string[]; evidence: { source: string; kind: string; summary: string; data: Record<string, unknown> }[]; attack_evaluations: unknown[] };
export type Health = { status: string; version: string; backends: { name: string; available: boolean; tasks: string[] }[]; attack_lab_enabled: boolean; problems: string[] };
export type LegacyEvidence = { schema: "aegis.product.evidence.v1"; kind: "reconstruction" | "mirage" | "benchmark"; source_sha256: string; verification: string; summary: Record<string, unknown> };
export type LocalEvidence = LegacyEvidence | ResearchEvidence;
export const shaPattern = /^[0-9a-f]{64}$/;
export const terminal = (status: Status) => status === "succeeded" || status === "failed";
const object = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const strings = (value: unknown): value is string[] => Array.isArray(value) && value.every(x => typeof x === "string");
const artifact = (value: unknown): value is Artifact => object(value) && typeof value.name === "string" && typeof value.sha256 === "string" && shaPattern.test(value.sha256) && Number.isSafeInteger(value.size_bytes) && Number(value.size_bytes) >= 0;

export function parseJob(value: unknown): Job {
  if (!object(value) || typeof value.job_id !== "string" || !/^[0-9a-f]{32}$/.test(value.job_id) ||
    !["pending", "running", "succeeded", "failed"].includes(String(value.status)) || !artifact(value.input_artifact) ||
    !Array.isArray(value.output_artifacts) || !value.output_artifacts.every(artifact) ||
    (value.status !== "succeeded" && value.output_artifacts.length > 0) ||
    (value.status === "failed" ? !object(value.error) || typeof value.error.code !== "string" || typeof value.error.message !== "string" : value.error !== null)) {
    throw new Error("Invalid job response from API");
  }
  return value as Job;
}

export function parseReport(value: unknown, id: string): Report {
  const job = parseJob(value);
  if (!object(value) || job.job_id !== id || !terminal(job.status) || typeof value.summary !== "string" ||
    !strings(value.limitations) || !Array.isArray(value.attack_evaluations) || !Array.isArray(value.evidence) ||
    !value.evidence.every(e => object(e) && ["adapter", "orchestrator"].includes(String(e.source)) && typeof e.summary === "string" && object(e.data))) {
    throw new Error("Invalid or mismatched terminal report from API");
  }
  return value as Report;
}

const summaryKeys = {
  reconstruction: ["trial_id", "pair_id", "artifact_sha256", "candidate_sha256", "generation_status", "behavioral_scoring", "provider", "requested_model", "steps", "charged_tokens", "reported_tokens", "cost_microusd", "execution_performed", "attack_effectiveness"],
  mirage: ["input_sha256", "output_sha256", "inserted_count", "security_property", "final_artifact_retention"],
  benchmark: ["baseline", "outputs_match", "conditions", "settings", "measurements", "security_property"],
};

export async function loadEvidence(text: string, expectedDigest: string): Promise<LocalEvidence> {
  if (text.length > 1024 * 1024) throw new Error("Summary exceeds the 1 MiB limit");
  if (!shaPattern.test(expectedDigest)) throw new Error("Enter the SHA-256 printed by the local exporter");
  const bytes = new TextEncoder().encode(text);
  const digest = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))).map(b => b.toString(16).padStart(2, "0")).join("");
  if (digest !== expectedDigest) throw new Error("Summary SHA-256 mismatch; nothing was loaded");
  let value: unknown;
  try { value = JSON.parse(text); } catch { throw new Error("Invalid summary JSON; no content was loaded"); }
  if (object(value) && value.schema === "aegis.product.evidence.v2") return parseResearch(value);
  if (!object(value) || value.schema !== "aegis.product.evidence.v1" || !["reconstruction", "mirage", "benchmark"].includes(String(value.kind)) ||
    value.verification !== "offline_hash_bindings_checked" || typeof value.source_sha256 !== "string" || !shaPattern.test(value.source_sha256) || !object(value.summary) ||
    Object.keys(value).some(k => !["schema", "kind", "source_sha256", "verification", "summary"].includes(k))) throw new Error("Unsupported summary; use the local evidence exporter");
  const kind = value.kind as LegacyEvidence["kind"];
  const keys = summaryKeys[kind];
  if (Object.keys(value.summary).some(k => !keys.includes(k)) || keys.some(k => !(k in (value.summary as object)))) throw new Error("Unexpected or missing summary fields");
  if (kind === "reconstruction" && (value.summary.execution_performed !== false || value.summary.attack_effectiveness !== "not_established" || value.summary.provider !== "FakeOffline" || value.summary.behavioral_scoring !== "pending_authorized_core_runtime")) throw new Error("Unsupported reconstruction claims");
  if (kind === "mirage" && value.summary.security_property !== "not_established") throw new Error("Unsupported Mirage claims");
  if (kind === "benchmark" && value.summary.security_property !== "not_measured") throw new Error("Unsupported benchmark claims");
  // Fixed nested allowlists prevent a local report from displaying hidden cases or request bodies.
  if (kind === "benchmark") {
    const allowed = {
      conditions: ["utc", "platform", "cpu_model", "cpu0_governor", "compiler", "build_type", "ir_backend_flags"],
      settings: ["quick", "rounds", "width", "height", "samples", "warmup", "repeat", "seed"],
    };
    for (const key of ["conditions", "settings"] as const) {
      const nested = value.summary[key];
      if (!object(nested) || Object.keys(nested).some(k => !allowed[key].includes(k)) || Object.values(nested).some(v => v !== null && !["string", "number", "boolean"].includes(typeof v))) throw new Error("Invalid benchmark conditions");
    }
    if (!Array.isArray(value.summary.measurements) || value.summary.measurements.length > 30 || !value.summary.measurements.every(row => object(row) && Object.keys(row).sort().join() === "max_ns,median_ns,min_ns,operation,samples,variant" && typeof row.variant === "string" && typeof row.operation === "string" && [row.samples, row.median_ns, row.min_ns, row.max_ns].every(n => typeof n === "number" && Number.isFinite(n) && n >= 0))) throw new Error("Invalid benchmark measurements");
  }
  for (const [key, item] of Object.entries(value.summary)) {
    if (["conditions", "settings", "measurements"].includes(key)) continue;
    if (item !== null && !["string", "number", "boolean"].includes(typeof item)) throw new Error("Invalid summary field");
    if (typeof item === "string" && item.length > 256) throw new Error("Summary field too long");
  }
  return value as LocalEvidence;
}

export function parseHealth(value: unknown, httpStatus: number): Health {
  if (!object(value) || !["ok", "degraded"].includes(String(value.status)) || typeof value.version !== "string" ||
    typeof value.attack_lab_enabled !== "boolean" || !strings(value.problems) || !Array.isArray(value.backends) ||
    !value.backends.every(b => object(b) && typeof b.name === "string" && typeof b.available === "boolean" && strings(b.tasks))) {
    throw new Error("Invalid health response");
  }
  // Core answers 200 for ok and 503 for degraded; anything else is inconsistent.
  if ((value.status === "ok") !== (httpStatus === 200) || (value.status === "degraded") !== (httpStatus === 503) ||
    (value.status === "degraded") !== (value.problems.length > 0)) throw new Error("Inconsistent health response");
  return value as Health;
}

/** Health is public; a degraded API answers HTTP 503 with a valid report that must stay visible. */
export async function fetchHealth(): Promise<Health> {
  const response = await fetch("/healthz", { signal: AbortSignal.timeout(15000) });
  let data;
  try { data = await response.json(); } catch { throw new Error(`API returned HTTP ${response.status} without valid JSON`); }
  if (response.status !== 200 && response.status !== 503) throw new Error(`API returned HTTP ${response.status}`);
  return parseHealth(data, response.status);
}

export async function api(path: string, token: string, body?: unknown): Promise<unknown> {
  const response = await fetch(path, { method: body === undefined ? "GET" : "POST", signal: AbortSignal.timeout(15000),
    headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body) });
  let data;
  try { data = await response.json(); } catch { throw new Error(`API returned HTTP ${response.status} without valid JSON`); }
  if (!response.ok) throw new Error(object(data) && object(data.error) ? `${data.error.code}: ${data.error.message}` : `API returned HTTP ${response.status}`);
  return data;
}
import { parseResearch } from "./research.ts";
import type { ResearchEvidence } from "./research.ts";
