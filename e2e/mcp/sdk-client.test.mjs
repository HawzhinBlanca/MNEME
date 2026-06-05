/**
 * Real MCP client interop — drives `mneme-mcp` with the OFFICIAL
 * `@modelcontextprotocol/sdk` client (the same library real agents/Claude Desktop
 * use), not a hand-rolled framing. Proves: a standard MCP client can complete the
 * `initialize` handshake, discover the four lean record tools, write via
 * `record-with-provenance`, and get a RECEIPT-VERIFIED
 * `recall-with-signed-chain` (the handler is `recall_verified` only, INV-5)
 * with the content round-tripping. Closes blueprint §19 "MCP agent recall" for
 * the real-client path (a live-LLM loop is the optional credential-gated extra).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
// Binary resolution must NOT silently mask a broken/mis-targeted CI build:
// - If MNEME_MCP_BIN is set (CI), that EXACT path must exist — a missing binary is
//   a hard failure, never a fallback to a stale target/* artifact and never a skip.
// - Only when MNEME_MCP_BIN is unset (local dev) do we probe conventional paths and
//   skip gracefully if none exist.
const explicitBin = process.env.MNEME_MCP_BIN;
const fallbacks = [
  path.join(repoRoot, "target/release/mneme-mcp"),
  path.join(repoRoot, "target/debug/mneme-mcp"),
];
const bin = explicitBin ?? fallbacks.find((p) => existsSync(p));

const SEED = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

function toolJson(result) {
  assert.equal(result.isError, false, `tool returned error: ${JSON.stringify(result)}`);
  const text = (result.content ?? []).find((c) => c.type === "text")?.text;
  assert.ok(text, "tool result has text content");
  return JSON.parse(text);
}

test("official MCP SDK client gets receipt-verified recall from mneme-mcp", async (t) => {
  if (explicitBin && !existsSync(explicitBin)) {
    // CI set the path but the build did not produce it — fail loudly, do not skip.
    assert.fail(`MNEME_MCP_BIN=${explicitBin} does not exist — the mneme-mcp build did not produce the expected binary`);
  }
  if (!bin) {
    t.skip(`mneme-mcp binary not found (set MNEME_MCP_BIN or run: cargo build -p mneme-mcp); probed: ${fallbacks.join(", ")}`);
    return;
  }
  const storeDir = mkdtempSync(path.join(tmpdir(), "mneme-mcp-sdk-"));
  const transport = new StdioClientTransport({
    command: bin,
    args: [],
    env: { PATH: process.env.PATH ?? "", MNEME_STORE_PATH: storeDir, MNEME_OPERATOR_SEED: SEED },
  });
  const client = new Client({ name: "mneme-acceptance-client", version: "1.0.0" }, { capabilities: {} });

  await client.connect(transport); // real initialize handshake (protocolVersion negotiation)
  try {
    const { tools } = await client.listTools();
    const names = tools.map((tdef) => tdef.name).sort();
    assert.deepEqual(names, [
      "erase-with-receipt-and-proof-of-absence",
      "recall-with-signed-chain",
      "record-with-provenance",
      "verify",
    ]);

    const recorded = toolJson(
      await client.callTool({
        name: "record-with-provenance",
        arguments: { content: "dark mode preferred", kind: "semantic", namespace: "user", name: "theme" },
      }),
    );
    assert.ok(recorded.object_id_hex?.length >= 64, "record returns 32-byte object id");
    assert.ok(recorded.root_hash_hex?.length >= 64, "record returns signed root hash");
    assert.ok(recorded.root?.root_signature_hex?.length >= 64, "record returns signed root evidence");

    const recalled = toolJson(
      await client.callTool({
        name: "recall-with-signed-chain",
        arguments: { query: "theme", min_tier: "quarantine", namespace: "user" },
      }),
    );
    // Recall went through recall_verified (INV-5). The content must round-trip.
    const blob = JSON.stringify(recalled);
    assert.ok(blob.includes("dark mode preferred"), `recall_verified must return the remembered content: ${blob}`);

    const erased = toolJson(
      await client.callTool({
        name: "erase-with-receipt-and-proof-of-absence",
        arguments: { namespace: "user", target: "theme" },
      }),
    );
    assert.equal(erased.forget_proof?.mode, "shred");
    assert.equal(erased.forget_proof?.absence_path_len, 256);
    assert.ok(erased.forget_proof?.wire_hex?.length > 64, "erase returns canonical ForgetProof wire");
    assert.equal(erased.absence_proof?.path_len, 256);

    const verified = toolJson(await client.callTool({ name: "verify", arguments: {} }));
    assert.ok(verified.root?.root_signature_hex?.length >= 64, "verify returns signed root evidence");
  } finally {
    await client.close();
  }
});
