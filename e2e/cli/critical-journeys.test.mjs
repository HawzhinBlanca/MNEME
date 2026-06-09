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
// Matches crates/mneme-cli/tests/cli_e2e.rs — init/verify/recall need sealed operator custody.
const TEST_KMS_MASTER_HEX =
  "5555555555555555555555555555555555555555555555555555555555555555";

function runMneme(args, cwd = repoRoot, { custody = false } = {}) {
  if (!existsSync(mnemeBin)) {
    return {
      skipped: true,
      reason: `mneme binary missing at ${mnemeBin}; run: cargo build -p mneme-cli`,
    };
  }
  const env = { ...process.env };
  if (custody) {
    env.MNEME_KMS_MASTER_KEY_HEX = TEST_KMS_MASTER_HEX;
  } else {
    delete env.MNEME_OPERATOR_SEED;
    delete env.MNEME_KMS_MASTER_KEY_HEX;
  }
  const result = spawnSync(mnemeBin, args, { encoding: "utf8", cwd, env });
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
  test("help lists verify, recall, forget, merge, init", () => {
    const out = runMneme(["--help"]);
    assertNotSkipped(out);
    assert.equal(out.status, 0);
    for (const sub of ["verify", "recall", "forget", "merge", "audit", "attest", "init"]) {
      assert.match(out.stdout, new RegExp(sub));
    }
  });

  test("verify missing store exits 2 with not found", () => {
    const out = runMneme(["verify", "/nonexistent/mneme-e2e-store"]);
    assertNotSkipped(out);
    assert.equal(out.status, 2);
    assert.match(out.stderr, /not found/i);
  });

  test("init then verify succeeds", () => {
    const base = mkdtempSync(path.join(tmpdir(), "mneme-e2e-"));
    const store = path.join(base, "store");
    try {
      const init = runMneme(["init", store], repoRoot, { custody: true });
      assertNotSkipped(init);
      assert.equal(init.status, 0, init.stderr);
      const verify = runMneme(["verify", store], repoRoot, { custody: true });
      assertNotSkipped(verify);
      assert.equal(verify.status, 0, verify.stderr);
      assert.match(verify.stdout, /verify ok/i);
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  });

  test("recall on empty initialized store fails closed", () => {
    const base = mkdtempSync(path.join(tmpdir(), "mneme-e2e-"));
    const store = path.join(base, "store");
    try {
      runMneme(["init", store], repoRoot, { custody: true });
      const out = runMneme(
        [
          "recall",
          store,
          "-q",
          "theme",
          "--key",
          "theme",
          "--min-tier",
          "working",
        ],
        repoRoot,
        { custody: true },
      );
      assertNotSkipped(out);
      assert.notEqual(out.status, 0);
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  });
});
