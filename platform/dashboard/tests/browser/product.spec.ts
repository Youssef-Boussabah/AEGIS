import { test, expect } from "@playwright/test";
import { createHash } from "node:crypto";
import { readFile, mkdtemp } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import path from "node:path";

const workspace = process.env.AEGIS_PRODUCT_WORKSPACE || "/tmp/aegis-product";
const root = path.resolve(import.meta.dirname, "../../../..");
const python = path.join(root, ".venv/bin/python");

test("documented HTTP smoke command verifies real local output digests", () => {
  const result = execFileSync(python, [path.join(root, "scripts/product.py"), "smoke", "--workspace", workspace], { encoding: "utf8", timeout: 45_000 });
  expect(JSON.parse(result).status).toBe("succeeded");
});
test("real LLVM upload succeeds, renders Core report and reloads by ID", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByText("llvm-shield is registered; its adapter executable is available.")).toBeVisible();
  await page.getByRole("button", { name: "Protect LLVM IR", exact: true }).click();
  await page.getByLabel("LLVM IR file").setInputFiles(path.join(workspace, "annotated.ll"));
  const accepted = page.waitForResponse(r => r.url().endsWith("/v1/jobs") && r.request().method() === "POST");
  await page.getByRole("button", { name: "Submit protection job" }).click();
  const response = await accepted;
  expect(response.status()).toBe(202);
  const job = await response.json();
  await expect(page.getByTestId("job-status")).toHaveText("succeeded", { timeout: 30_000 });
  await expect(page.getByRole("region", { name: "Protection report" })).toBeVisible();
  await expect(page.getByTestId("transformation-count")).toContainText("1 transformed sites");
  const report = await (await page.request.get(`/v1/jobs/${job.job_id}/report`)).json();
  const inputDigest = createHash("sha256").update(await readFile(path.join(workspace, "annotated.ll"))).digest("hex");
  expect(report.input_artifact.sha256).toBe(inputDigest);
  await expect(page.getByText(inputDigest, { exact: true })).toBeVisible();
  for (const artifact of report.output_artifacts) {
    await expect(page.getByText(artifact.sha256, { exact: true })).toBeVisible();
    const bytes = await readFile(path.join(workspace, "store", artifact.storage_path));
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(artifact.sha256);
  }
  const downloaded = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download report" }).click();
  const download = await downloaded;
  expect(download.suggestedFilename()).toBe(`aegis-${job.job_id}.json`);
  const downloadPath = await download.path();
  expect(JSON.parse(await readFile(downloadPath!, "utf8"))).toEqual(report);
  // Exact artifact bytes are served by the new integrity-checked route.
  const output = report.output_artifacts.find((a: { name: string }) => a.name === "protected.ll");
  const artifactDownloaded = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download protected.ll", exact: true }).click();
  const artifactDownload = await artifactDownloaded;
  expect(createHash("sha256").update(await readFile((await artifactDownload.path())!)).digest("hex")).toBe(output.sha256);
  await page.getByRole("button", { name: "Verify artifact", exact: true }).click();
  await expect(page.getByText("Not signed (signing not configured)", { exact: true })).toBeVisible();
  await expect(page.getByText("Unsigned", { exact: true })).toHaveCount(report.output_artifacts.length);
  await expect(page.getByText("Signature verified", { exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Continue to Results", exact: true }).click();
  await expect(page.getByText("Last verification:", { exact: false })).toBeVisible();
  await page.getByRole("button", { name: "Protection jobs", exact: true }).click();
  await page.screenshot({ path: "/tmp/aegis-product-browser-report.png", fullPage: true });
  await page.reload();
  await page.getByRole("button", { name: "Protection jobs", exact: true }).click();
  await page.getByLabel("Job ID", { exact: true }).fill(job.job_id);
  await page.getByRole("button", { name: "Load job" }).click();
  await expect(page.getByTestId("job-status")).toHaveText("succeeded");
  await expect(page.getByRole("region", { name: "Protection report" })).toBeVisible();
});

test("real adapter rejection remains a failed job with no output claims", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Protect LLVM IR", exact: true }).click();
  await page.getByLabel("LLVM IR file").setInputFiles({ name: "invalid.ll", mimeType: "text/plain", buffer: Buffer.from("invalid LLVM input; negative test") });
  await page.getByRole("button", { name: "Submit protection job" }).click();
  await expect(page.getByTestId("job-status")).toHaveText("failed", { timeout: 30_000 });
  await expect(page.getByText("ADAPTER_FAILED", { exact: true })).toBeVisible();
  await expect(page.getByText("No output artifacts registered.")).toBeVisible();
});

test("unknown jobs and backend outage are visible errors", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Protection jobs", exact: true }).click();
  await page.getByLabel("Job ID", { exact: true }).fill("0".repeat(32));
  await page.getByRole("button", { name: "Load job" }).click();
  await expect(page.getByRole("alert")).toContainText("JOB_NOT_FOUND");
  await page.route("**/healthz", route => route.abort());
  await page.getByRole("button", { name: "Check connection" }).click();
  await expect(page.getByRole("alert")).toContainText("Backend health unavailable");
  await expect(page.getByText("API unavailable", { exact: true })).toBeVisible();
});

test("degraded API health lists Core problems instead of reporting an outage", async ({ page }) => {
  // Same body shape and status Core returns when an adapter executable is missing.
  const degraded = { status: "degraded", version: "0.1.0", storage_writable: true, storage_root: null, attack_lab_enabled: false,
    backends: [{ name: "llvm-shield", tasks: ["protect"], available: false }], problems: ["adapter executable for backend 'llvm-shield' is not available"] };
  await page.route("**/healthz", route => route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify(degraded) }));
  await page.goto("/");
  await expect(page.getByText("API degraded", { exact: true })).toBeVisible();
  await expect(page.getByTestId("health-problems")).toContainText(degraded.problems[0]);
  await expect(page.getByText("llvm-shield is not available.", { exact: false })).toBeVisible();
  await expect(page.getByRole("alert")).toHaveCount(0);
});

test("local summary hash is checked and raw private records are rejected", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Research evidence", exact: true }).click();
  const raw = JSON.stringify({ schema_version: "aegis.lab.controlled-experiment.v1", request: "PRIVATE_MARKER" });
  await page.getByLabel("Evidence JSON").setInputFiles({ name: "private.json", mimeType: "application/json", buffer: Buffer.from(raw) });
  await page.getByLabel("Expected summary SHA-256").fill(createHash("sha256").update(raw).digest("hex"));
  await page.getByRole("button", { name: "Verify and load summary" }).click();
  await expect(page.getByRole("alert")).toContainText("Unsupported summary");
  await expect(page.getByText("PRIVATE_MARKER")).toHaveCount(0);
  await page.getByLabel("Expected summary SHA-256").fill("0".repeat(64));
  await page.getByRole("button", { name: "Verify and load summary" }).click();
  await expect(page.getByRole("alert")).toContainText("SHA-256 mismatch");
});

test("navigation and small-screen layout present availability honestly", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  for (const name of ["Overview", "Protect LLVM IR", "Protection jobs", "Research evidence", "Capabilities", "Verify artifact", "Results"]) {
    await page.getByRole("button", { name, exact: true }).click();
    await expect(page.getByRole("heading", { name, exact: true, level: 1 })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  }
  await page.getByRole("button", { name: "Research evidence", exact: true }).click();
  await expect(page.getByRole("heading", { name: "AI analysis · unavailable" })).toBeVisible();
});

test("workspace workflow links and unconfigured verification remain explicit", async ({ page }) => {
  await page.goto("/");
  const flow = page.getByRole("group", { name: "Protection workflow" });
  await flow.getByRole("button", { name: /01 Protect/ }).click();
  await expect(page.getByLabel("Protection profile")).toHaveValue("llvm-shield");
  const health = await (await page.request.get("/healthz")).json();
  const combinedReady = health.backends.some((b: { name: string; available: boolean; tasks: string[] }) => b.name === "llvm-shield-mirage" && b.available && b.tasks.includes("protect"));
  await expect(page.getByLabel("Protection profile").getByRole("option", { name: /Shield \+ Mirage/ })).toHaveJSProperty("disabled", !combinedReady);
  await flow.getByRole("button", { name: /02 Verify/ }).click();
  await expect(page.getByRole("heading", { name: "Provenance & Sentinel" })).toBeVisible();
  await expect(page.getByText("Unconfigured · no policy created", { exact: true })).toBeVisible();
  await flow.getByRole("button", { name: /03 Evaluate/ }).click();
  await expect(page.getByRole("heading", { name: "Adversarial Lab", exact: true })).toBeVisible();
  await flow.getByRole("button", { name: /04 Results/ }).click();
  await expect(page.getByText("No job loaded.", { exact: false })).toBeVisible();
  await expect(page.getByText("No reconstruction success rate, security score or GPU utilization is inferred.", { exact: false })).toBeVisible();
});

test("unavailable profiles prevent submissions and explain registration", async ({ page }) => {
  await page.route("**/healthz", route => route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({
    status: "degraded", version: "0.1.0", attack_lab_enabled: false, problems: ["adapter executable unavailable"],
    backends: [{ name: "llvm-shield", available: false, tasks: ["protect"] }],
  }) }));
  await page.goto("/");
  await page.getByRole("button", { name: "Protect LLVM IR", exact: true }).click();
  await page.getByLabel("LLVM IR file").setInputFiles(path.join(workspace, "annotated.ll"));
  await expect(page.getByRole("button", { name: "Submit protection job" })).toBeDisabled();
  await expect(page.getByLabel("Protection profile").getByRole("option", { name: "Shield · LLVM 22", exact: true })).toHaveJSProperty("disabled", true);
  await expect(page.getByText("Profiles require a registered, available backend", { exact: false })).toBeVisible();
});

test("real ImageLab comparison exports and loads locally without an upload", async ({ page }) => {
  const scratch = await mkdtemp("/tmp/aegis-product-evidence-test-");
  const comparison = path.join(scratch, "compare.json");
  const summary = path.join(scratch, "summary.json");
  execFileSync(python, [path.join(root, "demo/image_processor/tools/compare_variants.py"), "--build", path.join(workspace, "imagelab-build"), "--quick", "--output", comparison], { timeout: 30_000 });
  const verification = execFileSync(python, [path.join(root, "scripts/export-product-evidence.py"), "benchmark", comparison, "--output", summary], { encoding: "utf8", timeout: 10_000 });
  await page.goto("/");
  await page.getByRole("button", { name: "Research evidence", exact: true }).click();
  let uploads = 0;
  page.on("request", request => { if (request.method() === "POST") uploads++; });
  await page.getByLabel("Evidence JSON").setInputFiles(summary);
  await page.getByLabel("Expected summary SHA-256").fill(verification.split(" ")[0]);
  await page.getByRole("button", { name: "Verify and load summary" }).click();
  await expect(page.getByRole("heading", { name: "ImageLab benchmark", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Measurement conditions" })).toBeVisible();
  await expect(page.getByText("shield / tone")).toBeVisible();
  expect(uploads).toBe(0);
});
