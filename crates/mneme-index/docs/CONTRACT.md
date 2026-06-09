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

// Commitment binding (`commitment_binding` feature — tagged BLAKE3 envelope; NOT SNARK, NOT Plonky2)
CommitmentBindingReceipt, prove_binding_receipt, verify_binding_receipt
BINDING_ENVELOPE_TAG, BINDING_HONESTY, BINDING_PROOF_LEN, B3_V0_BINDING_STATUS

// Pedersen + Schnorr (12-month only — `pedersen_schnorr_zk` feature; real transparent
// NIZK over Ristretto; previously mis-named `plonky2_prover` and renamed for honesty.
// `plonky2_prover` is retained only as a deprecated compatibility alias.
// Not Plonky2, not FRI, not a SNARK. See B3_DEFERRAL_STATUS for the Plonky2/FRI deferral.)
PedersenSchnorrRetrievalProof, prove_pedersen_schnorr, verify_pedersen_schnorr
PEDERSEN_SCHNORR_HONESTY, B3_DEFERRAL_STATUS
```

## Invariants owned

- **INV-10** Deterministic procedure P (ObjectId asc traversal, integer distance, tie-break by ObjectId)
- Semantic Merkle commitment under `semantic_commit` (§5.6, §5.7)
- **§3 honesty**: receipts prove procedure-faithfulness, not exact-NN optimality
  or semantic truth; Phase I `ExactDominance` proves membership/completeness plus
  top-k over prover-asserted distances; true top-k ranking is not proven and it is
  not top-k by true query-to-embedding distance until verifiers recompute candidate
  distances from carried embeddings
- **§9.2 honesty**: `commitment_binding` proves leaf commitment only; `BINDING_ENVELOPE_TAG` must never claim Plonky2 or SNARK; `ZkProofInvalid` on this path means binding verification failed — not SNARK verification

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
| `honesty_message_preserves_distance_caveat` | §3 exported honesty string, including the distance-recompute caveat |
| `semantic_recall_returns_receipt_bound_results` | Stub removed; receipt path live |
| `commitment_binding` feature tests (when enabled) | Binding roundtrip + forgery rejection (BLAKE3 only) |
| `forgery_vectors_reject_typed` | `proof/vectors/receipts/zk/forgery_expectations.json` |
| `privacy_fixture_roundtrip` | Pinned digests in `privacy_fixture.json` |
| `envelope_tag_is_not_plonky2` | Domain tag excludes PLONKY2/SNARK claims |
| `commitment_binding_receipt_is_not_zk` | `BINDING_HONESTY` + envelope tag honesty |
| `pedersen_schnorr_zk` feature tests (when enabled) | prove/verify pass; `B3_DEFERRAL_STATUS` honesty; forgery rejection |

## Dependencies

- `mneme-core`, `mneme-smt`, `fast-hnsw` (HNSW wrapper — not custom ANN)

## May start when

- Wave 0 (`mneme-core`) + Wave 1 (`mneme-smt`) complete.

## Forbidden

- No custom ANN implementation (§1.2)
- No linked Plonky2/SNARK prover in v0 (`commitment_binding` = BLAKE3 only; `pedersen_schnorr_zk` = real transparent Pedersen+Schnorr NIZK over Ristretto, NOT Plonky2/FRI). The `B3_DEFERRAL_STATUS` constant in `pedersen_schnorr_zk.rs` records the Plonky2/V3DB SNARK deferral.
- Do not label `commitment_binding` receipts as zero-knowledge, SNARK, or Plonky2 in code, docs, or vectors
- Plonky2/V3DB ZK retrieval is **12-month milestone only** — not a v0/90-day exit criterion (B3 closed)
- Do not change `mneme-core/src/interface.rs` without INTERFACE-CHANGE doc

## Handoff (§20.4)

See parent agent handoff in slice completion report.
