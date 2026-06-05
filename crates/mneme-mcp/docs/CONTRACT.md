# mneme-mcp — module contract (§20.2)

## Responsibility

MCP stdio server exposing exactly the lean core record API over the verified
store kernel (blueprint §14.1):

- `record-with-provenance`
- `recall-with-signed-chain`
- `erase-with-receipt-and-proof-of-absence`
- `verify`

Honesty boundary stated on every public tool: the memory-and-record layer is
cryptographically airtight; model-side parametric residue is STATISTICAL
attestation only, never claimed as cryptographic deletion.

## Public API

- `MemoryHandlers` — testable tool handlers (record / recall_verified-only recall / shred erase + ForgetProof + absence proof / verify).
- `MnemeMcpServer` — RMCP `ServerHandler` + stdio binary `mneme-mcp`.
- `open_runtime` / `MNEME_STORE_PATH` — store bootstrap.

## Invariants owned

- **INV-5** — `recall-with-signed-chain` → `recall_verified` only; no unverified bytes on the MCP tool path.
- **§13.4** — `record-with-provenance` → tool-channel capability → quarantine tier default.
- **§3** — honesty strings in tool descriptions and error text (cryptographically airtight memory records; statistical model residue only).
- **Deletion guarantee** — `erase-with-receipt-and-proof-of-absence` uses shred mode and returns a verified `ForgetProof` plus an SMT absence proof.
- **Verifier guarantee** — `verify` runs the fail-closed store verifier and returns the checked signed root report.

## Proof obligations

| Test | Closes |
|------|--------|
| `record_via_tool_channel_is_quarantine_tier` | §13.4 tool-channel write tier |
| `recall_uses_recall_verified_roundtrip` | §19 v0 verified recall path |
| `quarantine_blocked_from_trusted_recall_ainj_mitigation` | §21 A-INJ structural gate |
| `lists_four_record_tools_with_honesty_descriptions` | §3 + §14.1 tool surface |
| `mcp_tools_call_record_recall_erase_verify_roundtrip` | Four public calls over one signed store root |
| `stdio_mcp_protocol_roundtrip_record_recall_erase_verify` | Live stdio transport roundtrip for the four public calls |
| `honesty_strings_present_in_tool_contract_constants` | No false anti-poisoning claims |

## Dependencies

- `mneme-store`, `mneme-verify`, `mneme-smt`, `mneme-cap`, `mneme-core`,
  `mneme-crypto`, `rmcp`

## May start when

- Wave 5 `mneme-store` green.

## Forbidden

- Calling `Store::recall` (unverified) from MCP handlers.
- Claiming A-INJ “detection” or truth adjudication in tool text.
- `unsafe`, `unwrap` on trusted paths in handlers.

## Handoff (§20.4)

See parent agent handoff block in PR / session summary.
