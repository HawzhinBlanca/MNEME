# Finding (HIGH) — crossref independent verifier is forgeable on exact-dominance + diverges from the main verifier

**Severity: SOUNDNESS + DIVERGENCE.** Date 2026-06-03. Found while watching the agent's Phase I.

## What

`mneme-crossref` is the **independent** Certificate-v1 verifier (zero `mneme-*` deps) — its whole
job is to *cross-check* the main verifier. But its exact-dominance path was **not** given the
completeness fix that the main verifier got (PR #5, `verify_candidate_set_binds_root`):

- `crates/mneme-crossref/src/wire_cert.rs:91` — `let committed_leaf_count = receipt.vo.candidates.len();`
  → the **prover-supplied** count.
- `crates/mneme-crossref/src/semantic_commit.rs:116-118` — ExactDominance does only
  `verify_ads_vo` (per-candidate membership via `leaf_indices`) + `verify_exact_dominance`
  (the vacuous `candidates.len() != committed_leaf_count` check). **No rebuild-root completeness.**

## Why it's forgeable (same dropped-NN attack as the main verifier had)

Drop the true nearest neighbor (a suffix leaf) from `candidates` + its node + its `leaf_index`.
The remaining candidates are all genuine members at genuine indices → `verify_ads_vo` passes.
`committed_leaf_count = candidates.len()` (now smaller) → count check passes (n == n). Dominance
over the surviving subset passes. **crossref returns Ok — the true nearest neighbor is hidden.**

Membership-via-`leaf_indices` proves each *presented* candidate is real; it does **not** prove the
set is *complete*. Completeness needs the root rebuild (or an authenticated cardinality).

## Why this is worse than a single-verifier bug: DIVERGENCE

The main verifier (`mneme-index`, with `verify_candidate_set_binds_root`) **rejects** this forge;
crossref **accepts** it. So the two implementations **disagree** on accept/reject — which defeats
the entire purpose of an independent cross-check and would let a forged certificate pass "the
independent verifier" in a deployment that trusts crossref.

## Fix (direct port of the main verifier's fix; crossref already has the primitives)

`crossref` already imports `hash_sem_leaf` + `hash_sem_internal` (`crate::domain`). Add a
completeness check called first in the `ExactDominance` arm of `verify_semantic_vo_zkann`:

```rust
// crates/mneme-crossref/src/semantic_commit.rs
fn rebuild_root(candidates: &[CandidateRow]) -> [u8; 32] {
    // mirror SemanticMerkleTree::from_entries: sort by object_id, hash_sem_leaf each,
    // then pairwise hash_sem_internal with odd-node self-promotion.
    let mut pairs: Vec<([u8;32],[u8;32])> =
        candidates.iter().map(|c| (c.object_id, c.embedding_commit)).collect();
    pairs.sort_by(|a,b| a.0.cmp(&b.0));
    let mut level: Vec<[u8;32]> = pairs.iter().map(|(id,ec)| hash_sem_leaf(id, ec)).collect();
    if level.is_empty() { return /* empty_semantic_root() */ }
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len()+1)/2);
        let mut i = 0;
        while i < level.len() {
            let l = level[i];
            let r = if i+1 < level.len() { level[i+1] } else { level[i] }; // odd-promotion
            next.push(hash_sem_internal(&l, &r));
            i += 2;
        }
        level = next;
    }
    level[0]
}

fn verify_candidate_set_binds_root(vo: &VerificationObject, semantic_commit: &[u8;32])
    -> Result<(), CrossrefError> {
    let mut ids: Vec<[u8;32]> = vo.candidates.iter().map(|c| c.object_id).collect();
    let n = ids.len(); ids.sort(); ids.dedup();
    if ids.len() != n { return Err(CrossrefError::RetrievalDominanceFailed); }
    if rebuild_root(&vo.candidates) != *semantic_commit {
        return Err(CrossrefError::RetrievalDominanceFailed);
    }
    Ok(())
}
```
Call it before `verify_exact_dominance` in the `ExactDominance` arm. Confirm the empty-tree root
constant matches `mneme-index::commit::empty_semantic_root()` exactly (it must, for the
cross-impl vectors to agree).

## Required test

Add a crossref test mirroring `zkann_dropped_true_nearest_neighbor_must_be_rejected`: a Certificate
whose VO drops the true nearest neighbor must be **rejected** by `verify_committed_certificate`.
Also assert **agreement**: any certificate accepted/rejected by the main verifier gets the same
verdict from crossref (this is what `cross-implementation-vectors.sh` should enforce).

## Note on HNSW

crossref's `verify_hnsw_audit_on_demand` shares the same "trusts visited_order, no walk replay"
limitation as the main verifier (see PHASE_I_HNSW_AUDIT_OVERCLAIM.md) — fix both together or
neither, and keep the honesty label identical across the two implementations.
