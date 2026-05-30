# mneme-index — module contract (§20.2)

## Responsibility

Committed semantic ANN (wrapped `fast-hnsw` HNSW) with Merkle-committed index nodes, deterministic procedure P, and ADS verification-object prover for semantic recall receipts.

## Public API

```rust
// Key index (v0)
KeyIndex: new, upsert, resolve, prove_membership, prove_non_membership, recall_receipt

// Semantic index (90-day)
SemanticIndex: new, insert, semantic_commit, search_deterministic, recall_receipt, approximate_search
SemanticRecallReceipt: new, digest, binds_to_semantic_commit
verify_ads_vo, execute_procedure_p, replay_from_candidates, procedure_id

// Merkle
SemanticMerkleTree, hash_sem_leaf, hash_sem_internal, empty_semantic_root

// Commitment binding (`commitment_binding` feature — BLAKE3 envelope, not SNARK)
CommitmentBindingReceipt, prove_binding_receipt, verify_binding_receipt, BINDING_HONESTY
```

## Invariants owned

- **INV-10** Deterministic procedure P (ObjectId asc traversal, integer distance, tie-break by ObjectId)
- Semantic Merkle commitment under `semantic_commit` (§5.6, §5.7)
- **§3 honesty**: receipts prove procedure-faithfulness, not exact-NN optimality

## Proof obligations

| Test | Closes |
|------|--------|
| `procedure_tie_breaks_by_object_id` | INV-10 tie-break |
| `procedure_id_is_deterministic` | P_id stability |
| `semantic_search_is_deterministic` | `(P, query, semantic_commit)` replay |
| `receipt_binds_to_semantic_commit` | Receipt ↔ root semantic_commit |
| `ads_vo_verifies_against_semantic_commit` | ADS VO Merkle + replay |
| `ads_vo_rejects_wrong_semantic_commit` | Tamper fail-closed |
| `ads_vo_rejects_tampered_candidate_distance` | ProcedureMismatch on tamper |
| `honesty_message_is_non_empty` | §3 boundary documented |
| `semantic_recall_returns_receipt_bound_results` | Stub removed; receipt path live |
| `commitment_binding` feature tests (when enabled) | Binding roundtrip + forgery rejection (BLAKE3 only, not SNARK) |

## Dependencies

- `mneme-core`, `mneme-smt`, `fast-hnsw` (HNSW wrapper — not custom ANN)

## May start when

- Wave 0 (`mneme-core`) + Wave 1 (`mneme-smt`) complete.

## Forbidden

- No custom ANN implementation (§1.2)
- No ZK prover in default build (`commitment_binding` feature off; current envelope is BLAKE3 binding only, not SNARK)
- Do not change `mneme-core/src/interface.rs` without INTERFACE-CHANGE doc

## Handoff (§20.4)

See parent agent handoff in slice completion report.
