# mneme-core — module contract (§20.2)

## Responsibility

Frozen object model, MNEME-dCBOR profile, BLAKE3 domain tags, HLC, and the closed `MnemeError` type — the seams every other crate builds on.

## Public API

Normative surface (blueprint §7, §20.3); extend only via interface-change request:

```rust
// Types: ObjectId, LogicalKey, Hlc, NodeId, MemoryKind, TrustTier, ObjectRecord, Draft, Query, …
// Serialization: to_bytes_canonical, from_bytes_strict
// Hashing: hash_obj, hash_smt_leaf, hash_smt_internal, hash_root_preimage, hash_cap, DomainTag
// Errors: MnemeError (closed enum)
```

## Invariants owned

- **INV-1** Content addressing
- **INV-2** Canonical serialization (MNEME-dCBOR)
- **INV-7** Strict parsing / unknown-field rejection
- **INV-9** Typed errors (definition only; enforcement in verify)
- **INV-10** No floats in identity-bearing fields (schema + dCBOR profile)
- **§3 honesty** — `MnemeError` messages for `ProcedureMismatch`, `BelowTierPolicy`, and `ZkProofInvalid` must never imply semantic truth, exact-NN optimality, true nearest neighbors, or SNARK verification (`authenticated ≠ true`; procedure-faithfulness `≠` exact-NN / not exact nearest-neighbor / not true nearest neighbors; Phase I `ExactDominance` is top-k over prover-asserted distances, not top-k by true query-to-embedding distance)

## Proof obligations

| Test | Closes |
|------|--------|
| `dcbor_*` / `object_id_*` | INV-1, INV-2 (Appendix B vectors) |
| `hlc_*` | HLC ordering bytes |
| `unknown_field_rejected` | INV-7 |

## Dependencies

- None (Wave 0 foundation).

## May start when

- Immediately (Wave 0).

## Forbidden

- No I/O, signing, or verification logic in this crate.
- No `unsafe`.
- Do not add `anyhow` on public APIs.

## Handoff (§20.4)

Report: files changed; which INV/gap closed; focused tests; `validation-lane quick|full`; Appendix B vector status; tamper delta N/A at core-only.
