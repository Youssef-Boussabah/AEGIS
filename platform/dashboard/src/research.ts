import schema from "./research-schema.json" with { type: "json" };

export type CompletionParser = "aegis.lab.completion-parser.v1" | "aegis.lab.nebius-reasoning-text.v2";
export type PostHocReview = {
  analysis_kind: "post_hoc_parser_compatibility_review";
  report_sha256: string; historical_experiment_sha256: string; response_sha256: string;
  historical_generation_status: "invalid_output";
  historical_completion_parser: "aegis.lab.completion-parser.v1";
  revalidation_completion_parser: "aegis.lab.nebius-reasoning-text.v2";
  post_hoc_status: "candidate_text_revalidated_but_behaviorally_unscored" | "rejected";
  candidate_envelope_valid: boolean; candidate_sha256: string | null;
};
export type Reconstruction = {
  evidence_label: "offline_scripted" | "external_provider_record" | "synthetic_fixture";
  trial_id: string; pair_id: string; artifact_sha256: string; candidate_sha256: string | null;
  generation_status: string; behavioral_scoring: "pending_authorized_core_runtime";
  provider: "FakeOffline" | "Nebius"; requested_model: string; reported_model: string | null;
  reported_model_status: "matched" | "missing" | "mismatch" | "mixed"; reported_identity_sha256: string | null;
  steps: number; charged_tokens: number; known_reported_tokens: number; reported_tokens: number | null;
  prompt_tokens: number | null; completion_tokens: number | null; usage_status: "complete" | "partial" | "unknown" | "no_requests";
  cost_microusd: number | null; cost_basis: string; reserved_spend_microusd: number; estimated_reported_cost_microusd: number | null;
  execution_performed: false; attack_effectiveness: "not_established"; limitations: string[];
  completion_parser?: CompletionParser | null; post_hoc_review?: PostHocReview | null;
};
export type Comparison = {
  evidence_label: "external_provider_record" | "synthetic_fixture";
  order: ("baseline" | "shield" | "mirage")[]; order_seed: number;
  experiments: { variant: "baseline" | "shield" | "mirage"; source_sha256: string | null; generation_status: string; summary: Reconstruction | null }[];
  reported_identity_comparable: boolean; behavioral_scoring: "pending_authorized_core_runtime";
  execution_performed: false; protection_effect: "not_established"; limitations: string[];
};
export type ResearchEvidence = { schema: "aegis.product.evidence.v2"; source_sha256: string; verification: "offline_hash_bindings_checked" } &
  ({ kind: "reconstruction"; summary: Reconstruction } | { kind: "reconstruction_comparison"; summary: Comparison });

type Shape = { $ref?: string; $defs?: Record<string, Shape>; const?: unknown; enum?: unknown[]; anyOf?: Shape[]; type?: string; properties?: Record<string, Shape>; required?: string[]; additionalProperties?: boolean; items?: Shape; minItems?: number; maxItems?: number; minLength?: number; maxLength?: number; pattern?: string; minimum?: number; maximum?: number };
const obj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
/** Only the JSON Schema keywords used by Agent 2's pinned public projection. */
function conforms(v: unknown, s: Shape, root: Shape): boolean {
  if (s.$ref) { const key = s.$ref.slice(s.$ref.lastIndexOf("/") + 1); return !!root.$defs?.[key] && conforms(v, root.$defs[key], root); }
  if (s.anyOf) return s.anyOf.some(a => conforms(v, a, root));
  if ("const" in s && v !== s.const) return false;
  if (s.enum && !s.enum.includes(v)) return false;
  if (s.type === "null") return v === null;
  if (s.type === "boolean") return typeof v === "boolean";
  if (s.type === "integer" || s.type === "number") return typeof v === "number" && Number.isFinite(v) && (s.type !== "integer" || Number.isSafeInteger(v)) && (s.minimum === undefined || v >= s.minimum) && (s.maximum === undefined || v <= s.maximum);
  if (s.type === "string") return typeof v === "string" && (s.minLength === undefined || v.length >= s.minLength) && (s.maxLength === undefined || v.length <= s.maxLength) && (!s.pattern || new RegExp(s.pattern).test(v));
  if (s.type === "array") return Array.isArray(v) && (s.minItems === undefined || v.length >= s.minItems) && (s.maxItems === undefined || v.length <= s.maxItems) && (!s.items || v.every(i => conforms(i, s.items!, root)));
  if (s.type === "object") return obj(v) && (!s.required || s.required.every(k => Object.prototype.hasOwnProperty.call(v, k))) && Object.entries(v).every(([k, val]) => s.properties && Object.prototype.hasOwnProperty.call(s.properties, k) ? conforms(val, s.properties[k], root) : s.additionalProperties !== false);
  return true;
}
const requiredLimitations = ["unsigned_local_evidence_not_provider_attestation", "candidate_text_is_not_reconstruction_success", "no_candidate_compilation_execution_or_behavioral_score", "no_established_protection_effect"];
function consistent(s: Reconstruction, sourceDigest: string) {
  const totals = [s.reported_tokens, s.prompt_tokens, s.completion_tokens];
  const review = s.post_hoc_review;
  const reviewed = review?.post_hoc_status === "candidate_text_revalidated_but_behaviorally_unscored";
  const reviewConsistent = !review || (
    s.provider === "Nebius" && s.completion_parser === "aegis.lab.completion-parser.v1" &&
    s.generation_status === "invalid_output" && s.candidate_sha256 === null &&
    review.historical_experiment_sha256 === sourceDigest &&
    reviewed === (review.candidate_sha256 !== null) && (!reviewed || review.candidate_envelope_valid)
  );
  return reviewConsistent && requiredLimitations.every(l => s.limitations.includes(l)) &&
    ((s.provider === "Nebius") === (s.cost_basis === "provider_invoice_unknown")) &&
    (s.provider !== "Nebius" || (s.cost_microusd === null && s.requested_model.startsWith("nvidia/"))) &&
    (s.provider !== "FakeOffline" || (s.cost_microusd === 0 && s.reserved_spend_microusd === 0)) &&
    (s.evidence_label !== "offline_scripted" || s.provider === "FakeOffline") &&
    (s.evidence_label !== "external_provider_record" || s.provider === "Nebius") &&
    (s.evidence_label !== "synthetic_fixture" || s.limitations.includes("synthetic_fixture_not_live_evidence")) &&
    (s.reported_model_status === "matched" ? s.reported_model === s.requested_model : s.reported_model === null) &&
    (s.usage_status === "complete" ? s.steps > 0 && totals.every(n => n !== null) && s.prompt_tokens! + s.completion_tokens! === s.reported_tokens && s.known_reported_tokens === s.reported_tokens : totals.every(n => n === null)) &&
    ((s.steps === 0) === (s.usage_status === "no_requests")) &&
    (s.generation_status !== "generated_but_behaviorally_unscored" || s.candidate_sha256 !== null);
}

export function parseResearch(value: unknown): ResearchEvidence {
  const kind = obj(value) ? value.kind : undefined;
  const shape = kind === "reconstruction" ? schema.reconstruction : kind === "reconstruction_comparison" ? schema.reconstruction_comparison : null;
  if (!shape || !conforms(value, shape as Shape, shape as Shape)) throw new Error("Unsupported research summary or private fields; use the Lab public exporter");
  const record = value as ResearchEvidence;
  if (record.kind === "reconstruction") {
    if (!consistent(record.summary, record.source_sha256)) throw new Error("Inconsistent reconstruction identity, usage, post-hoc review or limitations");
  } else {
    const s = record.summary;
    const identities = new Set(s.experiments.map(r => r.summary?.reported_identity_sha256 ?? null));
    const comparable = s.experiments.every(r => r.summary !== null) && identities.size === 1 && !identities.has(null);
    if (new Set(s.order).size !== 3 || new Set(s.experiments.map(r => r.variant)).size !== 3 ||
      s.reported_identity_comparable !== comparable || !requiredLimitations.every(l => s.limitations.includes(l)) ||
      (s.evidence_label === "synthetic_fixture" && !s.limitations.includes("synthetic_fixture_not_live_evidence")) ||
      s.experiments.some(r => (r.summary === null) !== (r.source_sha256 === null) || (r.summary && (
        !consistent(r.summary, r.source_sha256!) || r.summary.generation_status !== r.generation_status ||
        r.summary.provider !== "Nebius" || r.summary.evidence_label !== s.evidence_label)))) throw new Error("Inconsistent reconstruction comparison");
  }
  return record;
}
