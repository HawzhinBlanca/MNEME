# Red-team finding — retrieval-correctness verifier must bind completeness to the SIGNED ROOT

**Severity: CRITICAL (soundness).** **Design guidance for the future exact-NN / zkANN verifier.**
Date 2026-06-03.

## Status on `master`

The forgeable implementation described below **never reached `master`.** Master currently defers
exact-NN retrieval correctness to `mneme-index/src/piop_research.rs`, which is an *unimplemented*
research seam whose entry point **panics** (`unimplemented!()`) and proves nothing — correctly
fail-closed. This note exists so that whoever implements the *real* exact-dominance / zkANN
verifier does **not** repeat the soundness hole that a parallel draft (`zkann.rs` on a
`cursor/phase-i-*` branch) contained and that was proven forgeable during red-team.

## The hole (proven forgeable in the draft)

A draft "ExactDominance" verifier proved the returned top-k were the nearest *only over a
candidate set the prover supplied*, and bound completeness to a **prover-supplied count**
(`committed_leaf_count = candidates.len()`), so the completeness check was `n != n` → always true.

**The forge (the verifier returned `Ok(())`):** make the true nearest neighbor the
highest-ObjectId leaf (a *suffix* leaf). Drop it (candidate + its membership node); the remaining
lower-ObjectId leaves keep their sorted indices, so their Merkle paths still validate against the
real root. Self-supply the smaller count. Dominance over the surviving subset passes → the true
nearest neighbor is hidden and the verifier accepts. (Dropping a *low*-ObjectId leaf is incidentally
caught by index-shift → `IndexPathInvalid`, which is why a naive forge looks "rejected"; the
suffix-leaf forge is the clean break.)

Root causes: (1) completeness bound to a prover-supplied count; (2) the semantic Merkle root does
not commit to leaf cardinality (odd nodes self-promote), so the count can't be recovered from
`semantic_commit` either; (3) membership was only checked for candidates the prover listed a node
for, with no distinctness enforcement.

## The fix (sound, no interface change)

Authenticate the **complete** candidate set against the signed root: **rebuild the semantic Merkle
tree from exactly the presented `(id, embedding_commit)` leaves and require `root == semantic_commit`**,
plus reject duplicate ObjectIds. Any dropped / added / substituted / duplicated leaf changes the
root → fail closed. This replaces the prover-supplied count as the authoritative completeness proof.

```rust
fn verify_candidate_set_binds_root(vo, semantic_commit) -> Result<(), MnemeError> {
    // distinctness (no duplicate-padding)
    let mut ids: Vec<ObjectId> = vo.candidates.iter().map(|(id,_,_)| *id).collect();
    let n = ids.len(); ids.sort(); ids.dedup();
    if ids.len() != n { return Err(MnemeError::RetrievalDominanceFailed); }
    // completeness bound to the SIGNED root — not a prover-supplied count
    let entries = vo.candidates.iter().map(|(id,emb,_)| (*id,*emb)).collect::<Vec<_>>();
    if &SemanticMerkleTree::from_entries(&entries).root() != semantic_commit {
        return Err(MnemeError::RetrievalDominanceFailed);
    }
    Ok(())
}
```
Must be called **before** the dominance check in the exact path. Verified in the draft: with this
check the suffix-drop forge is rejected while the legit roundtrip and reordered-forge tests pass.

## Required test (must exist before any exact-dominance verifier is tagged "done")

`zkann_dropped_true_nearest_neighbor_must_be_rejected`: build an index where the true nearest
neighbor is the highest-ObjectId leaf; drop it + its node; set the count to the remaining candidates;
assert the verifier returns a typed rejection (`RetrievalDominanceFailed`), **not** `Ok`. The draft's
forgery suite tested *reordered* results but omitted this *dropped-better-neighbor* case — which is
exactly the gap that hid the break. Spec P1-1 lists "dropped-better-neighbor" as a required forgery
test; ensure it is real, not just listed.

## HNSW audit-on-demand caveat

A subset's sorted indices do not match full-tree leaf indices, so per-node Merkle paths cannot be
verified from the subset alone (the verifier doesn't know true indices). Any HNSW audit-on-demand
path must carry each candidate's *true* leaf index, or be explicitly gated/deferred — do not claim
it tested/working until it actually verifies a true subset.

## General lesson (applies to every PCC verifier)

Completeness, cardinality, and "as-of" anchors must be bound to a **signed/authenticated** value,
never to a number or set the prover supplies. When in doubt, **reconstruct and compare against the
signed root** rather than trust a count. This is the same class as the MNEME-2.0 finding where a
prover-supplied `committed_leaf_count` made a check vacuous.
