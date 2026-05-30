# mneme-mcp — module contract (§20.2)

## Responsibility

MCP stdio server exposing `memory.remember`, `memory.recall`, and `memory.forget` over the verified store kernel (blueprint §14.1).

## Public API

- `MemoryHandlers` — testable tool handlers (remember / recall_verified-only recall / forget).
- `MnemeMcpServer` — RMCP `ServerHandler` + stdio binary `mneme-mcp`.
- `open_runtime` / `MNEME_STORE_PATH` — store bootstrap.

## Invariants owned

- **INV-5** — `memory.recall` → `recall_verified` only; no unverified bytes on the MCP tool path.
- **§13.4** — `memory.remember` → tool-channel capability → quarantine tier default.
- **§3** — honesty strings in tool descriptions (authenticated≠true; receipt procedure-faithfulness).

## Proof obligations

| Test | Closes |
|------|--------|
| `remember_via_tool_channel_is_quarantine_tier` | §13.4 tool-channel write tier |
| `recall_uses_recall_verified_roundtrip` | §19 v0 verified recall path |
| `quarantine_blocked_from_trusted_recall_ainj_mitigation` | §21 A-INJ structural gate |
| `lists_three_memory_tools_with_honesty_descriptions` | §3 + §14.1 tool surface |
| `honesty_strings_present_in_tool_contract_constants` | No false anti-poisoning claims |

## Dependencies

- `mneme-store`, `mneme-cap`, `mneme-core`, `mneme-crypto`, `rmcp`

## May start when

- Wave 5 `mneme-store` green.

## Forbidden

- Calling `Store::recall` (unverified) from MCP handlers.
- Claiming A-INJ “detection” or truth adjudication in tool text.
- `unsafe`, `unwrap` on trusted paths in handlers.

## Handoff (§20.4)

See parent agent handoff block in PR / session summary.
