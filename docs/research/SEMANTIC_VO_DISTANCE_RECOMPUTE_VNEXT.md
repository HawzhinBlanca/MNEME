# Semantic VO Distance-Recompute v-next

**Status:** Design request only. No current wire or verifier behavior changes.
**Date:** 2026-06-08.

## Problem

Phase I semantic receipts authenticate candidate membership and replay top-k over
the candidate rows carried in the verification object. The current frozen v1 row
shape is:

```rust
(ObjectId, embedding_commit: [u8; 32], distance: i64)
```

That row does not carry the embedding vector. As a result, verifiers can prove
membership/completeness against `semantic_commit`, but they cannot recompute
`integer_distance(query, embedding)` and cannot prove the supplied distance is
the true query-to-embedding distance.

This is the known boundary documented in
`docs/redteam/PHASE_I_ZKANN_DISTANCE_UNBOUND.md`.

## Constraint

`mneme-core/src/interface.rs::VerificationObject` is a frozen seam under
`mneme-core-v1.0.0`. Do not mutate the v1 tuple field in place. A distance-bound
semantic VO needs a formal interface-change request and a contract-version
decision.

The v-next path must preserve:

- fail-closed verification,
- deterministic dCBOR,
- existing certificate v1/v2 draft verification,
- `mneme-crossref` independent verification,
- the `mneme-verify` TCB budget,
- the current honesty boundary until the new proof is actually verified.

## Proposed Additive Shape

Introduce a new candidate row and verification object instead of changing the
existing v1 type:

```rust
pub struct SemanticCandidateVNext {
    pub object_id: ObjectId,
    pub embedding: FixedPointEmbedding,
    pub embedding_commit: [u8; 32],
    pub distance: i64,
}

pub struct VerificationObjectVNext {
    pub nodes: Vec<([u8; 32], Vec<[u8; 32]>)>,
    pub candidates: Vec<SemanticCandidateVNext>,
    pub leaf_indices: Vec<usize>,
    pub procedure_id: [u8; 32],
    pub query_commit: [u8; 32],
    pub result_ids: Vec<ObjectId>,
}
```

Verifier obligations:

1. Decode only canonical embeddings; malformed embeddings fail closed.
2. Check `candidate.embedding.commit() == candidate.embedding_commit`.
3. Recompute `integer_distance(proc.distance, query, &candidate.embedding)`.
4. Require the recomputed distance to equal `candidate.distance`.
5. Replay top-k from recomputed distances, not untrusted numbers.
6. Keep Merkle membership rooted in `(object_id, embedding_commit)` so existing
   `semantic_commit` semantics do not change unless a separate commitment change
   is approved.

## Wire Strategy

Use a new semantic receipt / certificate version rather than overloading v1:

- keep current semantic receipt fields `1..7` unchanged,
- add a versioned v-next receipt body or new certificate version whose VO body
  encodes candidate rows as `(id, embedding, embedding_commit, distance)`,
- update `mneme-crossref` before any shipped claim is upgraded,
- keep v1 verification accepted with the current honest label:
  "top-k over prover-asserted distances."

## Required Tests Before Implementation Is Done

- A forged v-next candidate distance that does not match the carried embedding
  fails closed with a typed error.
- A forged v-next embedding whose commit does not match `embedding_commit` fails
  closed.
- A reordered/truncated v-next top-k fails after distance recomputation.
- v1 certificates still verify under the old honest label.
- `mneme-crossref` rejects the same forged v-next fixtures.
- Determinism and Appendix B fixtures are regenerated only after the interface
  change is approved.

## Human Gate

An integration owner must approve the interface-change request before code
changes add these public fields or bump certificate semantics. Until then, local
agents should keep improving tests/docs around the current boundary and must not
ship a silent `VerificationObject` mutation.
