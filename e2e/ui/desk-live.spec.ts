import { test, expect } from "@playwright/test";

// Live DOM e2e: the real console driving a real mnemed through ui/serve.mjs.
// Run with: npx playwright test --config playwright.live.config.ts
// (the webServer boots the daemon + proxy and seeds notes/hello + notes/forgetme).
test.describe("MNEME Desk — live", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/"); // non-demo: talks to the live daemon
    await page.waitForLoadState("networkidle");
  });

  test("store opens only against a real signed head", async ({ page }) => {
    await expect(page.getByTestId("store-status")).toHaveAttribute("data-verified", "false");
    await page.getByRole("button", { name: /open store/i }).click();
    await expect(page.getByTestId("store-status")).toHaveAttribute("data-verified", "true");
    await expect(page.getByText(/root seq/i)).toBeVisible();
  });

  test("verified recall returns the committed entry with a receipt", async ({ page }) => {
    await page.getByRole("searchbox", { name: /recall query/i }).fill("notes/hello");
    await page.getByLabel(/minimum trust tier/i).selectOption("quarantine");
    await page.getByRole("button", { name: /^recall$/i }).click();
    const result = page.getByTestId("recall-result").first();
    await expect(result).toBeVisible();
    await expect(result).toContainText("verified-recall-works");
    await expect(page.getByTestId("receipt-status").first()).toHaveText(/verified/i);
  });

  test("missing key fails closed (no fabricated result)", async ({ page }) => {
    await page.getByRole("searchbox", { name: /recall query/i }).fill("notes/does-not-exist");
    await page.getByLabel(/minimum trust tier/i).selectOption("quarantine");
    await page.getByRole("button", { name: /^recall$/i }).click();
    await expect(page.getByText(/no authenticated entry/i)).toBeVisible();
    await expect(page.getByTestId("recall-result")).toHaveCount(0);
  });

  test("remember commits a new memory and it recalls back", async ({ page }) => {
    await page.locator("#remember-ns").fill("notes");
    await page.locator("#remember-name").fill("from-ui");
    await page.locator("#remember-body").fill("written-through-the-console");
    await page.getByRole("button", { name: /^remember$/i }).click();
    await expect(page.locator("#remember-result-grid")).toContainText(/committed/i);
    // and it is now recallable
    await page.getByRole("searchbox", { name: /recall query/i }).fill("notes/from-ui");
    await page.getByLabel(/minimum trust tier/i).selectOption("quarantine");
    await page.getByRole("button", { name: /^recall$/i }).click();
    await expect(page.getByTestId("recall-result").first()).toContainText("written-through-the-console");
  });

  test("promote raises an entry to the trusted tier", async ({ page }) => {
    await page.getByRole("searchbox", { name: /recall query/i }).fill("notes/promoteme");
    await page.getByLabel(/minimum trust tier/i).selectOption("quarantine");
    await page.getByRole("button", { name: /^recall$/i }).click();
    const result = page.getByTestId("recall-result").first();
    await expect(result).toBeVisible();
    await result.getByRole("button", { name: /promote/i }).click();
    await expect(result.locator(".tier-badge")).toHaveText(/trusted/i);
    await expect(result).toContainText(/promoted to trusted/i);
  });

  test("forget downloads a ForgetProof and marks the entry forgotten", async ({ page }) => {
    await page.getByRole("searchbox", { name: /recall query/i }).fill("notes/forgetme");
    await page.getByLabel(/minimum trust tier/i).selectOption("quarantine");
    await page.getByRole("button", { name: /^recall$/i }).click();
    const result = page.getByTestId("recall-result").first();
    await expect(result).toBeVisible();
    const [download] = await Promise.all([
      page.waitForEvent("download"),
      result.getByRole("button", { name: /forget/i }).click(),
    ]);
    expect(download.suggestedFilename()).toContain("forget-proof");
    await expect(result).toHaveClass(/forgotten/);
  });
});
