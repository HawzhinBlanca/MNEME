# mneme-smt — module contract (§20.2)

## Responsibility

Sparse Merkle tree for the logical key index: root, membership proofs, non-membership proofs, tombstones.

## Public API

```rust
// SparseMerkleTree: new, root, upsert, tombstone, prove_membership, prove_non_membership,
//   verify_membership, verify_non_membership
// MembershipProof, NonMembershipProof
```

## Invariants owned

- **INV-1** via `hash_smt_leaf` / `hash_smt_internal` from core
- Tombstone / absence semantics for **§13** and **INV-5** (enforced with verify)

## Proof obligations

| Test | Closes |
|------|--------|
| `membership_roundtrip` | Live key membership |
| `non_membership_empty_tree` | Empty-tree absence |
| `fault_injection_membership_rejects_wrong_root` | §18 crypto fault hook |
| Appendix B `proof/vectors/smt/*` | Byte-pinned roots and proofs |

## Dependencies

- `mneme-core` only.

## May start when

- Wave 0 (`mneme-core`) domain tags and hashing API frozen.

## Forbidden

- No 256-bit sparse path compression beyond v0 scope without spec change.
- No `unsafe`.

## Handoff (§20.4)

Report: SMT tests + `validation-lane crypto`; Appendix B smt vectors; known v0 proof limitations (documented in code).
