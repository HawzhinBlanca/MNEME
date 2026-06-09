/**
 * Real MCP client interop — drives `mneme-mcp` with the OFFICIAL
 * `@modelcontextprotocol/sdk` client (the same library real agents/Claude Desktop
 * use), not a hand-rolled framing. Proves: a standard MCP client can complete the
 * `initialize` handshake, discover the memory tools, write via `memory.remember`,
 * and get a RECEIPT-VERIFIED `memory.recall` (the handler is `recall_verified` only,
 * INV-5) with the content round-tripping. Closes blueprint §19 "MCP agent recall"
 * for the real-client path (a live-LLM loop is the optional credential-gated extra).
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
      "memory.forget",
      "memory.forget_proof",
      "memory.recall",
      "memory.remember",
    ]);

    const remembered = toolJson(
      await client.callTool({
        name: "memory.remember",
        arguments: { content: "dark mode preferred", kind: "semantic", namespace: "user", name: "theme" },
      }),
    );
    assert.ok(remembered.object_id_hex?.length >= 64, "remember returns 32-byte object id");
    assert.ok(remembered.root_hash_hex?.length >= 64, "remember returns signed root hash");

    const recalled = toolJson(
      await client.callTool({
        name: "memory.recall",
        arguments: { query: "theme", min_tier: "quarantine", namespace: "user" },
      }),
    );
    // Recall went through recall_verified (INV-5). The content must round-trip.
    const blob = JSON.stringify(recalled);
    assert.ok(blob.includes("dark mode preferred"), `recall_verified must return the remembered content: ${blob}`);
  } finally {
    await client.close();
  }
});
