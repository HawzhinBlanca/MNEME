import { defineConfig, devices } from "@playwright/test";

// Live browser e2e for MNEME Desk Phase Y0: drives the real UI against a real
// mnemed through ui/serve.mjs (booted by scripts/ci/desk-e2e-boot.sh). Opt-in and
// separate from the default demo suite (playwright.config.ts).
const UPORT = process.env.MNEME_DESK_UI_PORT || "3100";
const base = `http://127.0.0.1:${UPORT}`;

export default defineConfig({
  testDir: "./e2e/ui",
  testMatch: /desk-live\.spec\.ts/,
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
    actionTimeout: 15_000,
    navigationTimeout: 15_000,
  },
  outputDir: "e2e/test-results-live",
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: "bash scripts/ci/desk-e2e-boot.sh",
    url: base,
    reuseExistingServer: false,
    timeout: 180_000,
    stdout: "pipe",
    stderr: "pipe",
  },
});
