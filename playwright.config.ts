import { defineConfig, devices } from "@playwright/test";

if (!process.env.MNEME_UI_BASE_URL) {
  process.env.MNEME_UI_BASE_URL = "http://localhost:3099";
}
const uiBaseUrl = process.env.MNEME_UI_BASE_URL.replace(/\/$/, "");

/**
 * Browser E2E is opt-in: MNEME v1 blueprint defines CLI + MCP only (§14).
 * Defaulting to local UI server to enable UI testing by default.
 */
export default defineConfig({
  testDir: "./e2e/ui",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: [["list"], ["html", { open: "never" }]],
  timeout: 30_000,
  expect: { timeout: 10_000 },
  use: {
    baseURL: uiBaseUrl,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    actionTimeout: 15_000,
    navigationTimeout: 15_000,
  },
  outputDir: "e2e/test-results",
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: "PORT=3099 node scripts/serve-ui.js",
    url: "http://localhost:3099",
    reuseExistingServer: !process.env.CI,
    stdout: "ignore",
    stderr: "pipe",
  },
});


