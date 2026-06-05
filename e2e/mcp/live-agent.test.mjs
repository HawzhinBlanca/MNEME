/**
 * A2 — LIVE LLM agent loop over `mneme-mcp` (credential-gated, turn-key).
 *
 * Drives a REAL Anthropic model through the MCP tool-use loop against a live
 * `mneme-mcp` stdio server: the model is given the four lean record tools and
 * asked to record a fact and then recall it. We assert the model actually
 * invoked `record-with-provenance` and `recall-with-signed-chain`, and that the
 * recalled content (which came back through `recall_verified`, INV-5)
 * round-trips. This is the live counterpart to the deterministic session
 * simulation and the official SDK-client interop test (`sdk-client.test.mjs`).
 *
 * TURN-KEY / FAIL-CLOSED GATING (so the standard `node --test e2e/mcp/*.test.mjs` CI
 * lane stays green without credentials):
 *   - No ANTHROPIC_API_KEY  → skip (the common CI case). The skip happens BEFORE any
 *     optional dependency is touched, so this file never breaks the glob.
 *   - Key set but `@anthropic-ai/sdk` not installed → skip with the exact install hint.
 *   - Key + SDK + binary present → the live loop RUNS and must pass.
 *
 * To run locally:
 *   npm i @anthropic-ai/sdk
 *   cargo build -p mneme-mcp
 *   ANTHROPIC_API_KEY=sk-... MNEME_MCP_BIN=$PWD/target/debug/mneme-mcp \
 *     node --test e2e/mcp/live-agent.test.mjs
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
const explicitBin = process.env.MNEME_MCP_BIN;
const fallbacks = [
  path.join(repoRoot, "target/release/mneme-mcp"),
  path.join(repoRoot, "target/debug/mneme-mcp"),
];
const bin = explicitBin ?? fallbacks.find((p) => existsSync(p));
const SEED = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const MODEL = process.env.MNEME_LIVE_MODEL ?? "claude-sonnet-4-5";

function toolText(result) {
  return (result.content ?? []).find((c) => c.type === "text")?.text ?? "";
}

// Convert an MCP tool definition into the Anthropic tool-use schema.
function toAnthropicTool(t) {
  return {
    name: t.name.replace(/[^A-Za-z0-9_-]/g, "_"),
    description: t.description ?? "",
    input_schema: t.inputSchema ?? { type: "object", properties: {} },
  };
}

test("A2: a live LLM drives record + recall over MCP", async (t) => {
  if (!process.env.ANTHROPIC_API_KEY) {
    t.skip("ANTHROPIC_API_KEY unset — live-LLM agent loop is credential-gated (set the key to run)");
    return;
  }
  if (explicitBin && !existsSync(explicitBin)) {
    assert.fail(`MNEME_MCP_BIN=${explicitBin} does not exist — mneme-mcp build missing`);
  }
  if (!bin) {
    t.skip(`mneme-mcp binary not found (set MNEME_MCP_BIN or run: cargo build -p mneme-mcp)`);
    return;
  }

  let Anthropic;
  try {
    ({ default: Anthropic } = await import("@anthropic-ai/sdk"));
  } catch {
    t.skip("@anthropic-ai/sdk not installed — run: npm i @anthropic-ai/sdk");
    return;
  }

  const storeDir = mkdtempSync(path.join(tmpdir(), "mneme-live-"));
  const transport = new StdioClientTransport({
    command: bin,
    args: [],
    env: { PATH: process.env.PATH ?? "", MNEME_STORE_PATH: storeDir, MNEME_OPERATOR_SEED: SEED },
  });
  const mcp = new Client({ name: "mneme-live-agent", version: "1.0.0" }, { capabilities: {} });
  await mcp.connect(transport);

  try {
    const { tools } = await mcp.listTools();
    const anthropicTools = tools.map(toAnthropicTool);
    const nameMap = new Map(anthropicTools.map((a, i) => [a.name, tools[i].name]));
    const anthropic = new Anthropic();

    const invoked = new Set();
    let lastRecallText = "";
    const messages = [
      {
        role: "user",
        content:
          "Use the memory tools. First record this fact under namespace 'user', name " +
          "'theme': the content is exactly \"dark mode preferred\", kind 'semantic'. " +
          "Use record-with-provenance for the write. Then recall it with query 'theme' " +
          "(min_tier 'quarantine', namespace 'user') using recall-with-signed-chain and " +
          "tell me what you stored.",
      },
    ];

    // Bounded tool-use loop (a model may take several turns to call both tools).
    for (let turn = 0; turn < 6; turn++) {
      const resp = await anthropic.messages.create({
        model: MODEL,
        max_tokens: 1024,
        tools: anthropicTools,
        messages,
      });
      messages.push({ role: "assistant", content: resp.content });

      const toolUses = resp.content.filter((c) => c.type === "tool_use");
      if (toolUses.length === 0) break; // model produced a final answer

      const toolResults = [];
      for (const use of toolUses) {
        const mcpName = nameMap.get(use.name) ?? use.name;
        invoked.add(mcpName);
        const result = await mcp.callTool({ name: mcpName, arguments: use.input ?? {} });
        const text = toolText(result);
        if (mcpName === "recall-with-signed-chain") lastRecallText = text;
        toolResults.push({
          type: "tool_result",
          tool_use_id: use.id,
          content: text || JSON.stringify(result),
          is_error: result.isError === true,
        });
      }
      messages.push({ role: "user", content: toolResults });
    }

    assert.ok(
      invoked.has("record-with-provenance"),
      "the live model must invoke record-with-provenance",
    );
    assert.ok(
      invoked.has("recall-with-signed-chain"),
      "the live model must invoke recall-with-signed-chain",
    );
    assert.ok(
      lastRecallText.includes("dark mode preferred"),
      `recall_verified must return the remembered content (got: ${lastRecallText})`,
    );
  } finally {
    await mcp.close();
  }
});
