import { test, expect } from "@playwright/test";

const uiBaseUrl = process.env.MNEME_UI_BASE_URL?.replace(/\/$/, "");
const uiEnabled = Boolean(uiBaseUrl);

test.describe("MNEME memory UI", () => {
  test.skip(
    !uiEnabled,
    "MNEME_UI_BASE_URL unset — no web UI in blueprint v1 (§14 CLI/MCP only)",
  );

  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");
  });

  test("onboarding shows fail-closed store open", async ({ page }) => {
    await expect(page.getByRole("heading", { name: /mneme/i })).toBeVisible();
    await page.getByRole("button", { name: /open store/i }).click();
    await expect(page.getByTestId("store-status")).toHaveAttribute(
      "data-verified",
      "true",
    );
  });

  test("recall with min tier trusted returns only verified entries", async ({
    page,
  }) => {
    await page.getByRole("searchbox", { name: /recall query/i }).fill(
      "API base URL",
    );
    await page.getByLabel(/minimum trust tier/i).selectOption("trusted");
    await page.getByRole("button", { name: /recall/i }).click();
    const results = page.getByTestId("recall-result");
    await expect(results.first()).toBeVisible({ timeout: 15_000 });
    await expect(page.getByTestId("receipt-status")).toHaveText(/verified/i);
  });

  test("settings expose trust tier policy", async ({ page }) => {
    await page.getByRole("link", { name: /settings/i }).click();
    await expect(page.getByLabel(/default min tier/i)).toBeVisible();
    await expect(page.locator("#view-settings").getByText(/quarantine/i).first()).toBeVisible();
  });

  test("forget key generates ForgetProof and invalidates subsequent recall", async ({
    page,
  }) => {
    await page.getByRole("link", { name: /forget proofs/i }).click();
    await expect(
      page.getByRole("heading", { name: /memory erasure & deletion proofs/i }),
    ).toBeVisible();

    await page.getByLabel(/memory key to shred/i).fill("API base URL");
    await page.getByLabel(/namespace/i).selectOption("system");
    await page.getByRole("button", { name: /forget key/i }).click();

    const result = page.getByTestId("forget-proof-result");
    await expect(result).toBeVisible();
    await expect(page.getByTestId("forget-proof-status")).toHaveText(
      /verified proof/i,
    );

    await page.getByRole("link", { name: /dashboard/i }).click();
    await page.getByRole("searchbox", { name: /recall query/i }).fill(
      "API base URL",
    );
    await page.getByRole("button", { name: /recall/i }).click();

    await expect(
      page.getByText("No matching authenticated preimages found"),
    ).toBeVisible();
  });
});
