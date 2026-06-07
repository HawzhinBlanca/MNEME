# mneme-verify — module contract (§20.2)

> ## ⚠ WARNING — `verify_signed_head_only` is NOT a store integrity gate
>
> **`verify_signed_head_only`** (formerly `verify_store_head`) checks the root
> signature only. It does **not** walk persisted objects, key-index sidecars, or
> DAG state. A store with a valid signed head and tampered object bytes will
> **pass** this function and **fail** [`verify_store`].
>
> **Production adoption paths** (`mneme` CLI `verify`, `mnemed`, MCP, store
> boot) **must** call [`verify_store`] only. Signature-only head verify exists
> for adversarial/forgery tests that demonstrate the bypass. The old
> `verify_store_head` alias has been removed; tests that need the signature-only
> diagnostic must call `verify_signed_head_only`.

## Responsibility

Fail-closed verifier TCB: root signature, membership/non-membership proofs, key and semantic recall receipts, and full-store verification (blueprint §9.3, §10, INV-5, INV-9).

## Public API

```rust
verify_root, verify_recall, verify_semantic_recall, verify_semantic_receipt
verify_membership_proof, verify_store
verify_signed_head_only   // diagnostic / forgery tests ONLY — see WARNING above
SignatureOnlyHead, RootReport
HONESTY_PROCEDURE  // re-exported honesty boundary (§3)
TCB_LINE_BUDGET
```

Removed alias: `verify_store_head` → use `verify_signed_head_only` for tests, `verify_store` for gates.

## Invariants owned

- **INV-5** Fail-closed reads — no entry path without verified receipt against signed root
- **B1 / head-only verify** — `verify_signed_head_only` is signature-only; **never** substitute for `verify_store` on boot/CI/adoption paths (`adoption_lint` enforces)
- **INV-9** Typed `MnemeError` only on trusted path (no `anyhow`, no stringly escape hatch)
- **§3 honesty** — exported `HONESTY_PROCEDURE` and semantic gate errors: authenticated `≠` true; receipts prove procedure-faithfulness over committed data, **not** exact nearest-neighbor optimality or semantic truth; Phase I `ExactDominance` proves membership/completeness plus top-k over prover-asserted distances; true top-k ranking is not proven until verifiers recompute candidate distances

## Proof obligations

| Test | Closes |
|------|--------|
| `tcb_budget` | TCB line budget (§17.6) |
| `tamper_suite_meets_150_floor_counted_from_source` | Verify the dynamic source-counted tamper inventory stays at or above the ≥150 floor |
| `appendix_b_receipts` | Byte-pinned recall fixtures |
| `tamper_*` suites (source-counted ≥150 adversarial cases, excluding inventory/self-audit tests) | Typed fail-closed rejection (§17.2) |
| `honesty_message_preserves_distance_caveat` (mneme-index) | §3 exported semantic honesty string, including the distance-recompute caveat |
| `b1_adoption_no_head_only_verify_in_production_src` | No head-only verify in CLI / mnemed / MCP / store src |
| `b1_cli_verify_subcommand_uses_verify_store` | CLI `verify` subcommand calls `verify_store` only |

## Dependencies

- `mneme-core`, `mneme-crypto`, `mneme-index`, `mneme-smt`, `mneme-dag`, `mneme-root`, `mneme-cap`

## May start when

- Wave 3 (`mneme-root`) + Wave 2 (`mneme-index`, `mneme-cap`) complete.

## Forbidden

- `unsafe`, `unwrap`, `panic`, `anyhow`, unchecked `as` casts on trusted paths
- Exceeding `TCB_LINE_BUDGET` without integration-owner review
- Claiming exact-NN, semantic truth, or SNARK verification in exports or error text
- Calling `verify_signed_head_only` (or removed `verify_store_head`) from production adoption `src/` — use `verify_store`

## Handoff (§20.4)

Report: files changed; invariant/gap closed; focused tests; validation-ladder status; tamper delta; what remains unproven.
