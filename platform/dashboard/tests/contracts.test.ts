import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { loadEvidence, parseHealth, parseJob, parseReport } from "../src/contracts.ts";
import { parseAttestation, parseDecision, parseTrustConfig, downloadArtifact } from "../src/attestation.ts";
import { fixtureJob, fixtureAttestation, trust, denied } from "./attestation-fixtures.ts";

const artifact = { name: "test.ll", sha256: "a".repeat(64), size_bytes: 12, role: "input" };
const job = { job_id: "a".repeat(32), status: "succeeded", input_artifact: artifact, output_artifacts: [], error: null };
test("job responses preserve real status and reject contradictory failure/success", () => {
  assert.equal(parseJob(job).status, "succeeded");
  for (const bad of [{ ...job, status: "failed" }, { ...job, error: { code: "FAIL" } }, { ...job, status: "protected" }, { ...job, input_artifact: { ...artifact, sha256: "not-a-digest" } }, { ...job, status: "pending", output_artifacts: [artifact] }]) assert.throws(() => parseJob(bad));
});
test("reports require a matching terminal job and evidence source", () => {
  const report = { ...job, summary: "test fixture only", limitations: ["Not protection evidence"], evidence: [], attack_evaluations: [] };
  assert.equal(parseReport(report, job.job_id).summary, "test fixture only");
  assert.throws(() => parseReport(report, "b".repeat(32)));
  assert.throws(() => parseReport({ ...report, status: "pending" }, job.job_id));
  assert.throws(() => parseReport({ ...report, evidence: [{ source: "verified_model", data: {}, summary: "bad" }] }, job.job_id));
});

const fixture = { schema: "aegis.product.evidence.v1", kind: "mirage", source_sha256: "a".repeat(64), verification: "offline_hash_bindings_checked", summary: { input_sha256: "b".repeat(64), output_sha256: "c".repeat(64), inserted_count: 3, security_property: "not_established", final_artifact_retention: "requires_independent_check" } };
async function load(value: unknown) {
  const text = JSON.stringify(value);
  return loadEvidence(text, createHash("sha256").update(text).digest("hex"));
}
test("local report requires a trusted expected digest", async () => {
  assert.equal((await load(fixture)).kind, "mirage");
  await assert.rejects(loadEvidence(JSON.stringify(fixture), "0".repeat(64)), /mismatch/);
  await assert.rejects(loadEvidence(JSON.stringify(fixture), ""), /SHA-256/);
  await assert.rejects(loadEvidence("x".repeat(1024 * 1024 + 1), "0".repeat(64)), /limit/);
});
test("raw archives, private extra fields and security claims fail closed", async () => {
  await assert.rejects(load({ schema_version: "aegis.lab.controlled-experiment.v1", private_evidence: "DO_NOT_RENDER" }));
  await assert.rejects(load({ ...fixture, summary: { ...fixture.summary, model_request: "DO_NOT_RENDER" } }));
  await assert.rejects(load({ ...fixture, private_evidence: "DO_NOT_RENDER" }));
  await assert.rejects(load({ ...fixture, summary: { ...fixture.summary, security_property: "secure" } }));
  const malformed = '{"request":"PRIVATE_MARKER"';
  await assert.rejects(loadEvidence(malformed, createHash("sha256").update(malformed).digest("hex")), error => {
    assert.ok(error instanceof Error);
    assert.equal(error.message, "Invalid summary JSON; no content was loaded");
    return true;
  });
});
test("benchmark nested fields cannot smuggle request or hidden-suite data", async () => {
  const summary = { baseline: "ir-baseline", outputs_match: true, conditions: { compiler: "test" }, settings: { samples: 1 }, measurements: [{ variant: "shield", operation: "tone", samples: 1, median_ns: 10, min_ns: 10, max_ns: 10 }], security_property: "not_measured" };
  const benchmark = { ...fixture, kind: "benchmark", summary };
  assert.equal((await load(benchmark)).kind, "benchmark");
  await assert.rejects(load({ ...benchmark, summary: { ...summary, conditions: { request: "DO_NOT_RENDER" } } }));
  await assert.rejects(load({ ...benchmark, summary: { ...summary, measurements: [{ ...summary.measurements[0], hidden_case: "DO_NOT_RENDER" }] } }));
});

test("degraded health stays a visible report; inconsistent health is rejected", () => {
  const ok = { status: "ok", version: "0.1.0", storage_writable: true, storage_root: null, attack_lab_enabled: false, backends: [{ name: "llvm-shield", tasks: ["protect"], available: true }], problems: [] };
  const degraded = { ...ok, status: "degraded", backends: [{ name: "llvm-shield", tasks: ["protect"], available: false }], problems: ["adapter executable for backend 'llvm-shield' is not available"] };
  assert.equal(parseHealth(ok, 200).status, "ok");
  assert.deepEqual(parseHealth(degraded, 503).problems, degraded.problems);
  for (const [bad, status] of [[ok, 503], [degraded, 200], [{ ...degraded, problems: [] }, 503], [{ ...ok, status: "healthy" }, 200], [{ ...ok, backends: [{ name: 1 }] }, 200], [{ error: { code: "INTERNAL_ERROR" } }, 500]] as const) assert.throws(() => parseHealth(bad, status));
});

test("attestation distinguishes signatures from signing and binds exact job artifacts", () => {
  const j = parseJob(fixtureJob);
  const value = fixtureAttestation();
  assert.equal(parseAttestation(value, j).artifacts[0].signature.status, "verified");
  assert.equal(parseAttestation(fixtureAttestation("failed"), j).artifacts[0].signature.error_code, "UNTRUSTED_KEY");
  assert.throws(() => parseAttestation({ ...value, job_id: "0".repeat(32) }, j));
  assert.throws(() => parseAttestation({ ...value, signing: { ...value.signing, state: "not_configured" } }, j));
  assert.throws(() => parseAttestation({ ...value, artifacts: [{ ...value.artifacts[0], sha256: "0".repeat(64) }] }, j));
  assert.throws(() => parseAttestation({ ...value, artifacts: [] }, j));
  assert.throws(() => parseAttestation(fixtureAttestation("unsigned").artifacts, j));
  assert.equal(parseTrustConfig(trust).signing.state, "configured");
  assert.throws(() => parseTrustConfig({ ...trust, signing: { state: "signed" } }));
});

test("Sentinel HTTP success can be denial; mismatched decisions fail closed", () => {
  assert.equal(parseDecision(denied, fixtureJob.job_id, artifact.sha256, "redistribute").permitted, false);
  assert.throws(() => parseDecision({ ...denied, permitted: "true" }, fixtureJob.job_id, artifact.sha256, "redistribute"));
  assert.throws(() => parseDecision(denied, fixtureJob.job_id, artifact.sha256, "execute"));
  assert.throws(() => parseDecision({ ...denied, caller_id_verified: true }, fixtureJob.job_id, artifact.sha256, "redistribute"));
});

const labFixture = (name: string) => JSON.parse(readFileSync(new URL(`../../../attack_lab/tests/fixtures/public-summary/${name}.json`, import.meta.url), "utf8"));
test("Lab schema snapshot matches Agent 2's published public interface", () => {
  const local = JSON.parse(readFileSync(new URL("../src/research-schema.json", import.meta.url), "utf8"));
  assert.deepEqual(local, labFixture("schema"));
});

test("public Lab records distinguish offline and synthetic inference usage and preserve unknown billing", async () => {
  for (const name of ["offline-scripted", "synthetic-nebius", "synthetic-comparison"]) assert.equal((await load(labFixture(name))).schema, "aegis.product.evidence.v2");
  const live = labFixture("synthetic-nebius");
  await assert.rejects(load({ ...live, summary: { ...live.summary, cost_microusd: 23 } }), /Inconsistent/);
  await assert.rejects(load({ ...live, summary: { ...live.summary, prompt_tokens: 0 } }), /Inconsistent/);
  await assert.rejects(load({ ...live, summary: { ...live.summary, reported_model: "nvidia/other-model" } }), /Inconsistent/);
  await assert.rejects(load({ ...live, summary: { ...live.summary, execution_performed: true } }));
  await assert.rejects(load({ ...live, summary: { ...live.summary, limitations: [] } }));
  await assert.rejects(load({ ...live, summary: { ...live.summary, generation_status: "success" } }));
});

test("public Lab nested data rejects raw prompts, candidate source and private records", async () => {
  const live = labFixture("synthetic-nebius");
  for (const key of ["prompt", "candidate_source", "private_record", "system_fingerprint", "constructor", "__proto__"]) {
    await assert.rejects(load({ ...live, summary: { ...live.summary, [key]: "PRIVATE_TEST_MARKER" } }));
  }
  const comparison = labFixture("synthetic-comparison");
  const extra = structuredClone(comparison); extra.summary.experiments[0].summary.private_record = "PRIVATE_TEST_MARKER";
  await assert.rejects(load(extra));
  await assert.rejects(load({ ...comparison, summary: { ...comparison.summary, reported_identity_comparable: false } }));
});

test("artifact downloads refuse changed bytes, invalid hash headers and policy denial", async () => {
  const original = globalThis.fetch;
  try {
    globalThis.fetch = async () => new Response("changed data", { headers: { "X-AEGIS-Artifact-SHA256": artifact.sha256, "X-AEGIS-Sentinel-Decision": "permitted" } });
    await assert.rejects(downloadArtifact(fixtureJob.job_id, artifact, ""), /mismatch/);
    globalThis.fetch = async () => new Response("test", { headers: { "X-AEGIS-Artifact-SHA256": "0".repeat(64), "X-AEGIS-Sentinel-Decision": "permitted" } });
    await assert.rejects(downloadArtifact(fixtureJob.job_id, artifact, ""), /headers/);
    globalThis.fetch = async () => new Response(JSON.stringify({ error: { code: "POLICY_DENIED", message: "test denial", details: {} } }), { status: 403 });
    await assert.rejects(downloadArtifact(fixtureJob.job_id, artifact, ""), /POLICY_DENIED/);
  } finally { globalThis.fetch = original; }
});

test("post-hoc reviews preserve original failure, bind its source and retain optional-field compatibility", async () => {
  const value = labFixture("synthetic-post-hoc");
  const record = await load(value);
  assert.equal(record.summary.generation_status, "invalid_output");
  assert.equal(record.summary.candidate_sha256, null);
  assert.equal((record.summary.post_hoc_review as { post_hoc_status: string }).post_hoc_status, "candidate_text_revalidated_but_behaviorally_unscored");
  for (const [key, invalid] of [["generation_status", "generated_but_behaviorally_unscored"], ["candidate_sha256", "a".repeat(64)], ["completion_parser", "aegis.lab.nebius-reasoning-text.v2"], ["provider", "FakeOffline"]]) {
    await assert.rejects(load({ ...value, summary: { ...value.summary, [key]: invalid } }));
  }
  for (const mutation of [
    { historical_experiment_sha256: "0".repeat(64) }, { candidate_envelope_valid: false }, { candidate_envelope_valid: 1 },
    { candidate_sha256: null }, { post_hoc_status: "rejected" }, { revalidation_completion_parser: "unpublished-parser" },
  ]) await assert.rejects(load({ ...value, summary: { ...value.summary, post_hoc_review: { ...value.summary.post_hoc_review, ...mutation } } }));
  const rejected = { ...value.summary.post_hoc_review, candidate_sha256: null, candidate_envelope_valid: false, post_hoc_status: "rejected" };
  assert.equal((await load({ ...value, summary: { ...value.summary, post_hoc_review: rejected } })).kind, "reconstruction");
  const previous = labFixture("synthetic-nebius");
  assert.equal((await load(previous)).kind, "reconstruction");
  assert.equal((await load({ ...previous, summary: { ...previous.summary, completion_parser: null, post_hoc_review: null } })).kind, "reconstruction");
});

test("post-hoc nested data cannot import private response text or replace comparison history", async () => {
  const value = labFixture("synthetic-post-hoc");
  for (const key of ["prompt", "candidate_source", "private_record", "reasoning_content", "response_body", "constructor", "__proto__"]) {
    await assert.rejects(load({ ...value, summary: { ...value.summary, post_hoc_review: { ...value.summary.post_hoc_review, [key]: "PRIVATE_TEST_MARKER" } } }));
  }
  const comparison = labFixture("synthetic-comparison");
  const row = comparison.summary.experiments[0];
  row.generation_status = "invalid_output";
  row.summary = { ...value.summary, post_hoc_review: { ...value.summary.post_hoc_review, historical_experiment_sha256: row.source_sha256 } };
  assert.equal((await load(comparison)).kind, "reconstruction_comparison");
  row.summary.post_hoc_review.historical_experiment_sha256 = "0".repeat(64);
  await assert.rejects(load(comparison));
  const mismatchedLabel = labFixture("synthetic-comparison");
  mismatchedLabel.summary.experiments[0].summary.evidence_label = "external_provider_record";
  await assert.rejects(load(mismatchedLabel));
});
