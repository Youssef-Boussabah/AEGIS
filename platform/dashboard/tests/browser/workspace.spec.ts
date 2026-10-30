import { test, expect } from "@playwright/test";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fixtureJob, fixtureAttestation, trust, denied, jobId, digest } from "../attestation-fixtures";

// These tests exercise documented failure states with synthetic HTTP responses.
// The existing product.spec suite separately exercises the real LLVM adapter.
async function loadFixture(page: import("@playwright/test").Page, status: "verified" | "failed" | "unsigned" = "verified") {
  await page.route(`**/v1/jobs/${jobId}`, route => route.fulfill({ json: fixtureJob }));
  await page.route(`**/v1/jobs/${jobId}/report`, route => route.fulfill({ json: { ...fixtureJob, summary: "Synthetic report fixture only", limitations: ["No protection evidence"], evidence: [], attack_evaluations: [] } }));
  await page.route("**/v1/attestation", route => route.fulfill({ json: trust }));
  await page.route(`**/v1/jobs/${jobId}/attestation`, route => route.fulfill({ json: fixtureAttestation(status) }));
  await page.goto("/");
  await page.getByRole("button", { name: "Protection jobs", exact: true }).click();
  await page.getByLabel("Job ID", { exact: true }).fill(jobId);
  await page.getByRole("button", { name: "Load job", exact: true }).click();
  await expect(page.getByTestId("job-status")).toHaveText("succeeded");
  await page.getByRole("button", { name: "Verify artifact", exact: true }).click();
}

test("synthetic verified signature, denied Sentinel decision and denied download remain distinct", async ({ page }) => {
  await page.route(`**/v1/jobs/${jobId}/artifacts/${digest}/evaluate`, route => route.fulfill({ json: denied }));
  await page.route(`**/v1/jobs/${jobId}/artifacts/${digest}`, route => route.fulfill({ status: 403, json: { error: { code: "POLICY_DENIED", message: "Synthetic download denial", details: {} } } }));
  await loadFixture(page);
  await expect(page.getByText("Signature verified", { exact: true })).toBeVisible();
  await expect(page.getByText("Synthetic policy: cooperating tools only.")).toBeVisible();
  await page.getByRole("button", { name: "Evaluate Sentinel policy for protected.ll", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("Denied");
  await expect(page.getByRole("status")).toContainText("Synthetic policy denies redistribution");
  await page.getByRole("button", { name: "Download protected.ll", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("POLICY_DENIED");
  await page.getByRole("button", { name: "Continue to Results", exact: true }).click();
  await expect(page.getByText("Signature verified", { exact: true })).toBeVisible();
  await expect(page.getByText("Last verification:", { exact: false })).toBeVisible();
});

test("synthetic untrusted signature and malformed verification never show verified", async ({ page }) => {
  await loadFixture(page, "failed");
  await expect(page.getByText("Signature failed", { exact: true })).toBeVisible();
  await expect(page.getByText("UNTRUSTED_KEY", { exact: true })).toBeVisible();
  await expect(page.getByText("Signature verified", { exact: true })).toHaveCount(0);
  await page.route(`**/v1/jobs/${jobId}/attestation`, route => route.fulfill({ json: { ...fixtureAttestation(), job_id: "0".repeat(32) } }));
  await page.getByRole("button", { name: "Refresh verification", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("mismatched attestation");
  await expect(page.getByText("Signature verified", { exact: true })).toHaveCount(0);
  await page.route(`**/v1/jobs/${jobId}/attestation`, route => route.abort());
  await page.getByRole("button", { name: "Refresh verification", exact: true }).click();
  await expect(page.getByRole("alert")).toBeVisible();
});

test("synthetic unsigned outputs are never verified just because signing is recorded", async ({ page }) => {
  await loadFixture(page, "unsigned");
  await expect(page.getByText("Unsigned", { exact: true })).toBeVisible();
  await expect(page.getByText("Signature verified", { exact: true })).toHaveCount(0);
});

test("synthetic changed artifact bytes are refused before the browser saves a file", async ({ page }) => {
  await page.route(`**/v1/jobs/${jobId}/artifacts/${digest}`, route => route.fulfill({ status: 200, body: "changed data", headers: { "X-AEGIS-Artifact-SHA256": digest, "X-AEGIS-Sentinel-Decision": "permitted" } }));
  let downloads = 0; page.on("download", () => downloads++);
  await loadFixture(page);
  await page.getByRole("button", { name: "Download protected.ll", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("mismatch; download refused");
  expect(downloads).toBe(0);
});

test("synthetic model usage and comparison imports are labelled and never uploaded", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Research evidence", exact: true }).click();
  const fixtureRoot = path.resolve(import.meta.dirname, "../../../../attack_lab/tests/fixtures/public-summary");
  let posts = 0; page.on("request", req => { if (req.method() === "POST") posts++; });
  for (const name of ["synthetic-nebius", "synthetic-comparison"]) {
    const bytes = await readFile(path.join(fixtureRoot, `${name}.json`));
    await page.getByLabel("Evidence JSON").setInputFiles({ name: `${name}.json`, mimeType: "application/json", buffer: bytes });
    await page.getByLabel("Expected summary SHA-256").fill(createHash("sha256").update(bytes).digest("hex"));
    await page.getByRole("button", { name: "Verify and load summary", exact: true }).click();
  }
  await expect(page.getByRole("heading", { name: "Baseline / Shield / Shield + Mirage comparison", exact: true })).toBeVisible();
  await expect(page.getByText("Synthetic fixture · not live inference evidence.", { exact: false }).first()).toBeVisible();
  await expect(page.getByText("nvidia/synthetic-fixture-model", { exact: false }).first()).toBeVisible();
  await expect(page.getByText("Provider billing is unknown. Budget reservations are not an invoice.").last()).toBeVisible();
  await expect(page.getByText("Shield + Mirage (operator declared)", { exact: true })).toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.getByRole("button", { name: "Results", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Baseline / Shield / Shield + Mirage comparison", exact: true })).toBeVisible();
  expect(posts).toBe(0);
});

test("synthetic partial usage preserves unknown totals and private nested records fail import", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Research evidence", exact: true }).click();
  const source = JSON.parse(await readFile(path.resolve(import.meta.dirname, "../../../../attack_lab/tests/fixtures/public-summary/synthetic-nebius.json"), "utf8"));
  source.summary.usage_status = "partial"; source.summary.prompt_tokens = null; source.summary.completion_tokens = null; source.summary.reported_tokens = null;
  async function importValue(value: unknown) {
    const text = JSON.stringify(value);
    await page.getByLabel("Evidence JSON").setInputFiles({ name: "synthetic.json", mimeType: "application/json", buffer: Buffer.from(text) });
    await page.getByLabel("Expected summary SHA-256").fill(createHash("sha256").update(text).digest("hex"));
    await page.getByRole("button", { name: "Verify and load summary", exact: true }).click();
  }
  await importValue(source);
  await expect(page.getByText("Unknown", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("partial", { exact: true })).toBeVisible();
  source.summary.private_record = "PRIVATE_TEST_MARKER";
  await importValue(source);
  await expect(page.getByRole("alert")).toContainText("private fields");
  await expect(page.getByText("PRIVATE_TEST_MARKER", { exact: false })).toHaveCount(0);
});

test("keyboard users can skip to content and follow the workspace workflow", async ({ page }) => {
  await page.goto("/");
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "Skip to content", exact: true })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/#main-content$/);
  const flow = page.getByRole("group", { name: "Protection workflow" });
  await flow.getByRole("button", { name: /02 Verify/ }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { level: 1, name: "Verify artifact", exact: true })).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Main navigation" }).getByRole("button", { name: "Verify artifact", exact: true })).toHaveAttribute("aria-current", "page");
});

test("Results opens verification for the chosen job and preserves selection across pages", async ({ page }) => {
  await loadFixture(page);
  await expect(page.getByText("Signature verified", { exact: true })).toBeVisible();
  const secondId = "4".repeat(32);
  const second = { ...fixtureJob, job_id: secondId, input_artifact: { ...fixtureJob.input_artifact, name: "second.ll" } };
  await page.route(`**/v1/jobs/${secondId}`, route => route.fulfill({ json: second }));
  await page.route(`**/v1/jobs/${secondId}/report`, route => route.fulfill({ json: { ...second, summary: "Second synthetic report only", limitations: ["Not evidence"], evidence: [], attack_evaluations: [] } }));
  await page.route(`**/v1/jobs/${secondId}/attestation`, route => route.fulfill({ json: { ...fixtureAttestation(), job_id: secondId } }));
  await page.getByRole("button", { name: "Protection jobs", exact: true }).click();
  await page.getByLabel("Job ID", { exact: true }).fill(secondId);
  await page.getByRole("button", { name: "Load job", exact: true }).click();
  await expect(page.getByTestId("job-status")).toHaveCount(2);
  await page.getByRole("button", { name: "Results", exact: true }).click();
  await page.getByRole("button", { name: "Inspect verification for fixture.ll", exact: true }).click();
  await expect(page.getByLabel("Job to verify", { exact: true })).toHaveValue(jobId);
  await expect(page.getByText("Signature verified", { exact: true })).toBeVisible();
  await page.getByLabel("Job to verify", { exact: true }).selectOption(secondId);
  await expect(page.getByText("Signature verified", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Results", exact: true }).click();
  await page.getByRole("navigation", { name: "Main navigation" }).getByRole("button", { name: "Verify artifact", exact: true }).click();
  await expect(page.getByLabel("Job to verify", { exact: true })).toHaveValue(secondId);
});

test("synthetic signing and policy creation failures remain explicit alongside unsigned outputs", async ({ page }) => {
  await loadFixture(page, "unsigned");
  await expect(page.getByText("Unsigned", { exact: true })).toBeVisible();
  const failed = fixtureAttestation("unsigned");
  failed.signing.state = "signing_failed";
  failed.signing.message = "Synthetic signing failure";
  failed.sentinel.state = "creation_failed";
  failed.sentinel.message = "Synthetic policy creation failure";
  failed.artifacts[0].policy.status = "absent";
  failed.artifacts[0].policy.enforcement_mode = null;
  failed.artifacts[0].policy.policy_id = null;
  failed.artifacts[0].policy.policy_sha256 = null;
  failed.artifacts[0].policy.permissions = [];
  failed.artifacts[0].policy.disclaimer = null;
  await page.route(`**/v1/jobs/${jobId}/attestation`, route => route.fulfill({ json: failed }));
  await page.getByRole("button", { name: "Refresh verification", exact: true }).click();
  await expect(page.getByText("Signing failed", { exact: true })).toBeVisible();
  await expect(page.getByText("Sentinel policy creation failed", { exact: true })).toBeVisible();
  await expect(page.getByText("Absent · no policy available", { exact: true })).toBeVisible();
  await expect(page.getByText("Signature verified", { exact: true })).toHaveCount(0);
});

test("post-hoc imports keep original failure distinct, reject private review data and preserve rejected reviews", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Research evidence", exact: true }).click();
  const source = JSON.parse(await readFile(path.resolve(import.meta.dirname, "../../../../attack_lab/tests/fixtures/public-summary/synthetic-post-hoc.json"), "utf8"));
  let posts = 0; page.on("request", req => { if (req.method() === "POST") posts++; });
  async function importValue(value: unknown) {
    const text = JSON.stringify(value);
    await page.getByLabel("Evidence JSON").setInputFiles({ name: "synthetic-post-hoc.json", mimeType: "application/json", buffer: Buffer.from(text) });
    await page.getByLabel("Expected summary SHA-256").fill(createHash("sha256").update(text).digest("hex"));
    await page.getByRole("button", { name: "Verify and load summary", exact: true }).click();
  }
  await importValue(source);
  const review = page.getByRole("region", { name: "Post-hoc parser review", exact: true });
  await expect(review.getByText("candidate_text_revalidated_but_behaviorally_unscored", { exact: true })).toBeVisible();
  await expect(review.getByText("aegis.lab.nebius-reasoning-text.v2", { exact: true })).toBeVisible();
  await expect(review.getByText(source.summary.post_hoc_review.candidate_sha256, { exact: true })).toBeVisible();
  const original = page.locator("dl > div").filter({ has: page.getByText("Original generation state", { exact: true }) });
  await expect(original.locator("dd")).toHaveText("invalid_output");
  await expect(page.locator("dl > div").filter({ has: page.getByText("Original candidate SHA-256", { exact: true }) }).locator("dd")).toHaveText("No candidate recorded");
  await expect(review.getByText(/^The original /)).toContainText("remain unchanged");
  await expect(page.getByText("Synthetic fixture · not live inference evidence.", { exact: false })).toBeVisible();
  const privateRecord = structuredClone(source); privateRecord.summary.post_hoc_review.response_body = "PRIVATE_TEST_MARKER";
  await importValue(privateRecord);
  await expect(page.getByRole("alert")).toContainText("private fields");
  await expect(page.getByText("PRIVATE_TEST_MARKER", { exact: false })).toHaveCount(0);
  source.summary.post_hoc_review.post_hoc_status = "rejected";
  source.summary.post_hoc_review.candidate_envelope_valid = false;
  source.summary.post_hoc_review.candidate_sha256 = null;
  await importValue(source);
  await expect(review.first().getByText("Review rejected", { exact: true })).toBeVisible();
  await expect(review.first().getByText("No candidate accepted by this review", { exact: true })).toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.getByRole("button", { name: "Results", exact: true }).click();
  await expect(page.getByRole("region", { name: "Post-hoc parser review", exact: true })).toHaveCount(2);
  expect(posts).toBe(0);
});
