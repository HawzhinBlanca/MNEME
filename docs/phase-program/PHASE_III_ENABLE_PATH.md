# Phase III accountability — enable path (software)

**Honesty:** default production builds keep all Phase III gates **closed**. Enabling features does not ship Lean proofs, trust-ops pilots, or semantic truth guarantees.

## Cargo features (off by default)

| Goal | Crate / feature chain | Tests |
|---|---|---|
| Sign + verify `ActionReceipt` wire | `mneme-account/phase_iii_verify` | `cargo test -p mneme-account --features phase_iii_verify` |
| Mint receipts (`bind_action`) | `mneme-account/phase_iii_bind_action` (implies verify) | `cargo test -p mneme-account --features phase_iii_bind_action` |
| Store `bind_external_action` | `mneme-store/phase_iii_bind` → account bind | `cargo test -p mneme-store --features phase_iii_bind --test phase_iii_bind` |
| Mandatory receipt on remember/forget/promote | `mneme-store/phase_iii_require_action` (needs verify) | `cargo test -p mneme-store --features phase_iii_verify,phase_iii_require_action --test phase_iii_policy` |
| MCP auto-bind on tool paths | `mneme-mcp/phase_iii_bind` | `cargo test -p mneme-mcp --features phase_iii_bind --test phase_iii_mcp` |
| Shred forget + `ForgetProof` | `mneme-store/phase_iii_prove_forget` (+ verify) | `cargo test -p mneme-store --features phase_iii_prove_forget,phase_iii_verify --test phase_iii_forget` |

## Runtime constants

- `PHASE_III_GATE_OPEN` / `PHASE_III_BIND_ACTION_OPEN` / `PHASE_III_PROVE_FORGET_OPEN` remain `false` until an explicit program gate opens them (see `mneme-account`).

## Example (local dev only)

```bash
cargo test -p mneme-store \
  --features phase_iii_bind,phase_iii_verify,phase_iii_prove_forget \
  --test phase_iii_bind --test phase_iii_forget -- --nocapture
```

Red-team surfaces: `docs/redteam/PHASE_III_ACTION_RECEIPT.md`, `docs/redteam/PHASE_III_FORGET_PROOF.md`.
