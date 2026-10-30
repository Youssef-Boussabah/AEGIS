import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { loadEvidence, parseJob, parseReport } from "../src/contracts.ts";

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
