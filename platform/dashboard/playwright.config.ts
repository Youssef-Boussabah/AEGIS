import { defineConfig } from "@playwright/test";

// Ports are configurable so the suite can run beside an operator's own demo server.
const apiPort = process.env.AEGIS_API_PORT ?? "8000";
const dashboardPort = process.env.AEGIS_DASHBOARD_PORT ?? "5173";
for (const value of [apiPort, dashboardPort]) {
  if (!/^[0-9]{4,5}$/.test(value) || Number(value) < 1024 || Number(value) > 65535) throw new Error("Browser test ports must be TCP ports from 1024 to 65535");
}
if (apiPort === dashboardPort) throw new Error("Browser API and dashboard ports must differ");
const base = `http://127.0.0.1:${dashboardPort}`;
export default defineConfig({
  testDir: "./tests/browser",
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: 0,
  timeout: 60_000,
  outputDir: `/tmp/aegis-dashboard-browser-results-${dashboardPort}`,
  reporter: "list",
  use: { baseURL: base, browserName: "chromium", trace: "retain-on-failure" },
  webServer: {
    command: `../../.venv/bin/python ../../scripts/product.py serve --api-port ${apiPort} --dashboard-port ${dashboardPort}`,
    url: `${base}/healthz`,
    reuseExistingServer: false,
    gracefulShutdown: { signal: "SIGTERM", timeout: 10_000 },
    timeout: 30_000,
  },
});
