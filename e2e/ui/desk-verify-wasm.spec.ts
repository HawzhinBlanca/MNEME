// In-browser receipt auditor (WASM) — drives the Desk "Verify a Receipt" panel in
// a real browser: a genuine receipt verifies client-side, a tampered one fails
// closed. Requires the auditor bundle (ui/auditor/, built by
// scripts/ci/wasm-auditor.sh) and the Desk host (ui/serve.mjs) — wired in
// playwright.verify.config.ts.
import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';

// Playwright runs from the repo root; resolve the committed fixture from there.
const fixture = JSON.parse(
  readFileSync('crates/mneme-verify-wasm/test/fixtures/mtl_inclusion.json', 'utf8'),
);

test('a genuine MTL receipt verifies in-browser', async ({ page }) => {
  await page.goto('/');
  await page.selectOption('#verify-kind', 'mtl_inclusion');
  await page.fill('#verify-pk', fixture.operator_pk_hex);
  await page.fill('#verify-receipt', fixture.receipt_b64);
  await page.click('#btn-verify');
  const result = page.locator('[data-testid="verify-result"]');
  await expect(result).toHaveAttribute('data-ok', 'true', { timeout: 10000 });
  await expect(result).toContainText('Verified');
});

test('a tampered receipt is rejected (fail-closed)', async ({ page }) => {
  await page.goto('/');
  const flip = fixture.receipt_b64[40] === 'A' ? 'B' : 'A';
  const tampered = fixture.receipt_b64.slice(0, 40) + flip + fixture.receipt_b64.slice(41);
  await page.selectOption('#verify-kind', 'mtl_inclusion');
  await page.fill('#verify-pk', fixture.operator_pk_hex);
  await page.fill('#verify-receipt', tampered);
  await page.click('#btn-verify');
  const result = page.locator('[data-testid="verify-result"]');
  await expect(result).toHaveAttribute('data-ok', 'false', { timeout: 10000 });
  await expect(result).toContainText('Rejected');
});

test('a wrong operator key is rejected (fail-closed)', async ({ page }) => {
  await page.goto('/');
  await page.selectOption('#verify-kind', 'mtl_inclusion');
  await page.fill('#verify-pk', '00'.repeat(32));
  await page.fill('#verify-receipt', fixture.receipt_b64);
  await page.click('#btn-verify');
  const result = page.locator('[data-testid="verify-result"]');
  await expect(result).toHaveAttribute('data-ok', 'false', { timeout: 10000 });
});
