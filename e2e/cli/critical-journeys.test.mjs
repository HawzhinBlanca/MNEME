/**
 * CLI E2E smoke — blueprint §14.2 journeys (real `mneme` binary).
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { test, describe } from "node:test";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const defaultBin = path.join(repoRoot, "target/debug/mneme");
const mnemeBin = process.env.MNEME_BIN ?? defaultBin;
const operatorToolsEnabled = process.env.MNEME_CLI_OPERATOR_TOOLS === "1";

function runMneme(args, cwd = repoRoot) {
  if (!existsSync(mnemeBin)) {
    return {
      skipped: true,
      reason: `mneme binary missing at ${mnemeBin}; run: cargo build -p mneme-cli`,
    };
  }
  const result = spawnSync(mnemeBin, args, { encoding: "utf8", cwd });
  return {
    skipped: false,
    status: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

function assertNotSkipped(out) {
  if (out.skipped) assert.fail(out.reason);
}

describe("mneme CLI critical journeys", () => {
  test("default help lists core commands and hides operator/experimental commands", () => {
    const out = runMneme(["--help"]);
    assertNotSkipped(out);
    assert.equal(out.status, 0);
    for (const sub of ["verify", "recall", "forget", "remember"]) {
      assert.match(out.stdout, new RegExp(sub));
    }
    for (const operator of ["audit", "init", "determinism"]) {
      assert.doesNotMatch(out.stdout, new RegExp(operator));
    }
    for (const experimental of ["merge", "sync", "attest", "certify", "verify-cert"]) {
      assert.doesNotMatch(out.stdout, new RegExp(experimental));
    }
  });

  test("verify missing store exits 2 with not found", () => {
    const out = runMneme(["verify", "/nonexistent/mneme-e2e-store"]);
    assertNotSkipped(out);
    assert.equal(out.status, 2);
    assert.match(out.stderr, /not found/i);
  });

  test("init then verify succeeds", () => {
    if (!operatorToolsEnabled) {
      return;
    }
    const base = mkdtempSync(path.join(tmpdir(), "mneme-e2e-"));
    const store = path.join(base, "store");
    try {
      const init = runMneme(["init", store]);
      assertNotSkipped(init);
      assert.equal(init.status, 0, init.stderr);
      const verify = runMneme(["verify", store]);
      assertNotSkipped(verify);
      assert.equal(verify.status, 0, verify.stderr);
      assert.match(verify.stdout, /verify ok/i);
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  });

  test("recall on empty initialized store fails closed", () => {
    if (!operatorToolsEnabled) {
      return;
    }
    const base = mkdtempSync(path.join(tmpdir(), "mneme-e2e-"));
    const store = path.join(base, "store");
    try {
      runMneme(["init", store]);
      const out = runMneme([
        "recall",
        store,
        "-q",
        "theme",
        "--key",
        "theme",
        "--min-tier",
        "working",
      ]);
      assertNotSkipped(out);
      assert.notEqual(out.status, 0);
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  });
});
