# mneme-mcp — module contract (§20.2)

## Responsibility

MCP stdio server exposing `memory.remember`, `memory.recall`, and `memory.forget` over the verified store kernel (blueprint §14.1).

## Public API

- `MemoryHandlers` — testable tool handlers (remember / recall_verified-only recall / forget).
- `protocol::{dispatch, run_stdio_loop, tool_definitions}` — hand-rolled JSON-RPC 2.0 over stdio (`tools/list`, `tools/call`, `initialize`).
- `open_runtime` / `MNEME_STORE_PATH` — store bootstrap.
- Binary `mneme-mcp` — wires `open_runtime` + `run_stdio_loop`.

## Invariants owned

- **INV-5** — `memory.recall` → `recall_verified` only; no unverified bytes on the MCP tool path.
- **§13.4** — `memory.remember` → tool-channel capability → quarantine tier default.
- **§3** — honesty strings in tool descriptions and tool-call errors
  (authenticated≠true / not truth; receipt procedure-faithfulness; not exact nearest-neighbor;
  Phase I `ExactDominance` proves membership/completeness plus top-k over prover-asserted distances;
  true top-k ranking is not proven and it is not top-k by true query-to-embedding distance).

## Proof obligations

| Test | Closes |
|------|--------|
| `remember_via_tool_channel_is_quarantine_tier` | §13.4 tool-channel write tier |
| `recall_uses_recall_verified_roundtrip` | §19 v0 verified recall path |
| `quarantine_blocked_from_trusted_recall_ainj_mitigation` | §21 A-INJ structural gate |
| `lists_three_memory_tools_with_honesty_descriptions` | §3 + §14.1 tool surface |
| `mcp_honesty_surface_preserves_exact_dominance_distance_caveat` | §3 MCP tool/error honesty boundary |
| `mcp_contract_doc_preserves_exact_dominance_distance_caveat` | §3 contract drift guard |
| `honesty_strings_present_in_tool_contract_constants` | No false anti-poisoning claims |

## Dependencies

- `mneme-store`, `mneme-cap`, `mneme-core`, `mneme-crypto`, `serde`, `serde_json`

## May start when

- Wave 5 `mneme-store` green.

## Forbidden

- Calling `Store::recall` (unverified) from MCP handlers.
- Claiming A-INJ "detection" or truth adjudication in tool text.
- `unsafe`, `unwrap` on trusted paths in handlers.

## Handoff (§20.4)

See parent agent handoff block in PR / session summary.
