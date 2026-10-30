import { test, expect } from "@playwright/test";
import { spawn, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, writeFile, mkdtemp } from "node:fs/promises";
import { createServer } from "node:net";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "../../../..");
const python = path.join(root, ".venv/bin/python");
const workspace = process.env.AEGIS_PRODUCT_WORKSPACE || "/tmp/aegis-product";

async function freePort() {
  const listener = createServer();
  await new Promise<void>((resolve, reject) => { listener.once("error", reject); listener.listen(0, "127.0.0.1", resolve); });
  const port = (listener.address() as { port: number }).port;
  await new Promise<void>(resolve => listener.close(() => resolve()));
  return port;
}

test("real registered Shield + Mirage profile submits the combined pipeline and binds its outputs", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Protect LLVM IR", exact: true }).click();
  await page.getByLabel("Protection profile").selectOption("llvm-shield-mirage");
  await page.getByLabel("LLVM IR file").setInputFiles(path.join(workspace, "annotated.ll"));
  await page.getByLabel("Deterministic seed").fill("18446744073709551615");
  await page.getByRole("button", { name: "Submit protection job", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("requires a seed no greater than");
  await page.getByLabel("Deterministic seed").fill("42");
  const accepted = page.waitForResponse(r => r.url().endsWith("/v1/jobs") && r.request().method() === "POST");
  await page.getByRole("button", { name: "Submit protection job", exact: true }).click();
  const response = await accepted;
  expect(response.request().postDataJSON().policy.backend).toBe("llvm-shield-mirage");
  const job = await response.json();
  await expect(page.getByTestId("job-status")).toHaveText("succeeded", { timeout: 30_000 });
  const report = await (await page.request.get(`/v1/jobs/${job.job_id}/report`)).json();
  expect(report.output_artifacts.map((a: { name: string }) => a.name).sort()).toEqual(["mirage-report.json", "protected.ll", "shield-report.json", "shield-stage.ll"]);
  for (const artifact of report.output_artifacts) {
    await expect(page.getByText(artifact.sha256, { exact: true })).toBeVisible();
    expect(createHash("sha256").update(await readFile(path.join(workspace, "store", artifact.storage_path))).digest("hex")).toBe(artifact.sha256);
  }
  const mirage = report.output_artifacts.find((a: { name: string }) => a.name === "mirage-report.json");
  const claims = JSON.parse(await readFile(path.join(workspace, "store", mirage.storage_path), "utf8"));
  expect(claims.input_sha256).toBe(report.output_artifacts.find((a: { name: string }) => a.name === "shield-stage.ll").sha256);
  expect(claims.output_sha256).toBe(report.output_artifacts.find((a: { name: string }) => a.name === "protected.ll").sha256);
  expect(claims.inserted_count).toBe(3);
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: "/tmp/aegis-dashboard-combined-report.png", fullPage: true });
});

test("real signing, Sentinel denial, trusted download, tampering and refresh work through the UI", async ({ page }) => {
  const scratch = await mkdtemp("/tmp/aegis-dashboard-signing-");
  execFileSync(python, [path.join(root, "platform/dashboard/tests/prepare_attestation.py"), workspace, scratch], { timeout: 10_000 });
  const port = await freePort();
  const origin = `http://127.0.0.1:${port}`;
  const apiToken = "public-browser-test-token"; // Test credential only, never an operator credential.
  const server = spawn(python, ["-m", "aegis_api", "--host", "127.0.0.1", "--port", String(port)], {
    cwd: root, env: { PATH: process.env.PATH, AEGIS_CONFIG: path.join(scratch, "aegis.toml"), AEGIS_API_TOKEN: apiToken }, stdio: "ignore",
  });
  try {
    await expect.poll(async () => {
      if (server.exitCode !== null) throw new Error(`Isolated signing API exited: ${server.exitCode}`);
      try { return (await page.request.get(`${origin}/healthz`)).status(); } catch { return 0; }
    }, { timeout: 15_000 }).toBe(200);
    // Forward to a real isolated API with real signing; no route supplies synthetic data.
    await page.route("**/v1/**", async route => {
      const url = new URL(route.request().url());
      await route.fulfill({ response: await route.fetch({ url: `${origin}${url.pathname}${url.search}` }) });
    });
    await page.goto("/");
    expect((await page.request.get(`${origin}/v1/attestation`)).status()).toBe(401);
    await page.getByRole("button", { name: "Capabilities", exact: true }).click();
    await page.getByLabel("API bearer token", { exact: true }).fill(apiToken);
    await page.getByRole("button", { name: "Protect LLVM IR", exact: true }).click();
    await page.getByLabel("LLVM IR file").setInputFiles(path.join(workspace, "annotated.ll"));
    const accepted = page.waitForResponse(r => r.url().endsWith("/v1/jobs") && r.request().method() === "POST");
    await page.getByRole("button", { name: "Submit protection job", exact: true }).click();
    const job = await (await accepted).json();
    await expect(page.getByTestId("job-status")).toHaveText("succeeded", { timeout: 30_000 });
    const report = await (await page.request.get(`${origin}/v1/jobs/${job.job_id}/report`, { headers: { Authorization: `Bearer ${apiToken}` } })).json();
    const artifact = report.output_artifacts.find((a: { name: string }) => a.name === "protected.ll");
    await page.getByRole("button", { name: "Verify artifact", exact: true }).click();
    await expect(page.getByText("Signature verified", { exact: true })).toHaveCount(report.output_artifacts.length);
    await expect(page.getByText("Dashboard browser test signer", { exact: true }).first()).toBeVisible();
    await page.getByLabel("Policy action for protected.ll").selectOption("execute");
    await page.getByRole("button", { name: "Evaluate Sentinel policy for protected.ll", exact: true }).click();
    await expect(page.getByRole("status")).toContainText("Denied");
    await page.getByLabel("Policy action for protected.ll").selectOption("redistribute");
    await page.getByRole("button", { name: "Evaluate Sentinel policy for protected.ll", exact: true }).click();
    await expect(page.getByRole("status")).toContainText("Permitted");
    const pendingDownload = page.waitForEvent("download");
    await page.getByRole("button", { name: "Download protected.ll", exact: true }).click();
    expect(createHash("sha256").update(await readFile((await (await pendingDownload).path())!)).digest("hex")).toBe(artifact.sha256);
    const manifestDownload = page.waitForEvent("download");
    await page.getByRole("button", { name: "Download manifest for protected.ll", exact: true }).click();
    const manifest = JSON.parse(await readFile((await (await manifestDownload).path())!, "utf8"));
    expect(manifest).toHaveProperty("signature");
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path: "/tmp/aegis-dashboard-signed-verification.png", fullPage: true });
    const localArtifact = path.join(scratch, "store", artifact.storage_path);
    const original = await readFile(localArtifact);
    await writeFile(localArtifact, Buffer.concat([original, Buffer.from("\n; tampering test\n")]));
    await page.getByRole("button", { name: "Refresh verification", exact: true }).click();
    await expect(page.getByText("ARTIFACT_TAMPERED", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Download protected.ll", exact: true }).click();
    await expect(page.getByRole("alert")).toContainText("ARTIFACT_INTEGRITY_ERROR");
    await writeFile(localArtifact, original);
    await page.getByRole("button", { name: "Refresh verification", exact: true }).click();
    await expect(page.getByText("Signature verified", { exact: true })).toHaveCount(report.output_artifacts.length);
    await page.getByRole("button", { name: "Continue to Results", exact: true }).click();
    await expect(page.getByText("Signature verified", { exact: true })).toHaveCount(report.output_artifacts.length);
    expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length }))).toEqual({ local: 0, session: 0 });
  } finally {
    server.kill("SIGTERM");
    await new Promise<void>(resolve => { if (server.exitCode !== null) resolve(); else server.once("exit", () => resolve()); });
  }
});
