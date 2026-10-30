import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./tests/browser",
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: 0,
  timeout: 60_000,
  outputDir: "/tmp/aegis-product-browser-results",
  reporter: "list",
  use: { baseURL: "http://127.0.0.1:5173", browserName: "chromium", trace: "retain-on-failure" },
  webServer: {
    command: "../../.venv/bin/python ../../scripts/product.py serve",
    url: "http://127.0.0.1:5173/healthz",
    reuseExistingServer: false,
    gracefulShutdown: { signal: "SIGTERM", timeout: 10_000 },
    timeout: 30_000,
  },
});
