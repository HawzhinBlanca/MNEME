import { defineConfig, devices } from "@playwright/test";

// In-browser receipt auditor (WASM) e2e: drives the Desk "Verify a Receipt" panel
// against ui/serve.mjs. No daemon needed — verification is client-side. Requires
// the auditor bundle at ui/auditor/ (build with scripts/ci/wasm-auditor.sh).
const UPORT = process.env.MNEME_VERIFY_UI_PORT || "3200";
const base = `http://127.0.0.1:${UPORT}`;

export default defineConfig({
  testDir: "./e2e/ui",
  testMatch: /desk-verify-wasm\.spec\.ts/,
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: [["list"]],
  timeout: 30_000,
  expect: { timeout: 15_000 },
  use: {
    baseURL: base,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  outputDir: "e2e/test-results-verify",
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: `MNEME_UI_PORT=${UPORT} node ui/serve.mjs`,
    url: base,
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
    stdout: "pipe",
    stderr: "pipe",
  },
});
