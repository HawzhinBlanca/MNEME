# mneme-verify — module contract (§20.2)

## Responsibility

Fail-closed verifier TCB: root signature, membership/non-membership proofs, key and semantic recall receipts, and full-store verification (blueprint §9.3, §10, INV-5, INV-9).

## Public API

```rust
verify_root, verify_recall, verify_semantic_recall, verify_semantic_receipt
verify_membership_proof, verify_store, verify_store_head
HONESTY_PROCEDURE  // re-exported honesty boundary (§3)
TCB_LINE_BUDGET
```

## Invariants owned

- **INV-5** Fail-closed reads — no entry path without verified receipt against signed root
- **INV-9** Typed `MnemeError` only on trusted path (no `anyhow`, no stringly escape hatch)
- **§3 honesty** — exported `HONESTY_PROCEDURE` and semantic gate errors: authenticated `≠` true; receipts prove procedure-faithfulness over committed data, **not** exact nearest-neighbor optimality or semantic truth

## Proof obligations

| Test | Closes |
|------|--------|
| `tcb_budget` | TCB line budget (§17.6) |
| `tamper_inventory_matches_executed_verify_tests` | Verify tamper inventory equals executed `#[test]` count (147) |
| `appendix_b_receipts` | Byte-pinned recall fixtures |
| `tamper_*` suites (147 `#[test]`s) | Typed fail-closed rejection (§17.2) |
| `honesty_message_is_non_empty` (semantic tamper) | §3 boundary in `ProcedureMismatch` text |

## Dependencies

- `mneme-core`, `mneme-crypto`, `mneme-index`, `mneme-smt`, `mneme-dag`, `mneme-root`, `mneme-cap`

## May start when

- Wave 3 (`mneme-root`) + Wave 2 (`mneme-index`, `mneme-cap`) complete.

## Forbidden

- `unsafe`, `unwrap`, `panic`, `anyhow`, unchecked `as` casts on trusted paths
- Exceeding `TCB_LINE_BUDGET` without integration-owner review
- Claiming exact-NN, semantic truth, or SNARK verification in exports or error text

## Handoff (§20.4)

Report: files changed; invariant/gap closed; focused tests; validation-ladder status; tamper delta; what remains unproven.
