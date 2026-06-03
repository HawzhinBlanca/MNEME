# Finding — HNSW "audit-on-demand" does not replay the graph walk (overclaim)

**Severity: HONESTY / OVERCLAIM (not a leak; membership is sound).** Date 2026-06-03.
Found while watching the agent's `leaf_indices` HNSW work.

## Claim vs. reality

`PHASE_I_TASK_SPEC.md` P1-1 marks **`[x]`**:
> HNSW path (approximate): audit-on-demand (V3DB-style) — on challenge, **replay the declared
> graph walk against the committed snapshot and prove the returned set equals the walk's output**.

`verify_hnsw_audit_on_demand` (`crates/mneme-index/src/zkann.rs`) does **not** replay any walk.
It only:
1. checks `result_ids ⊆ visited_order` and `candidates ⊆ visited_order`,
2. runs `dominance_over_candidates` (top-k of the candidates).

The prover-supplied `visited_order` is **trusted**. There is no replay of the HNSW traversal and
no proof that `visited_order` is what the algorithm would actually visit.

## Why it can't currently be replayed

`semantic_commit` is a Merkle root over the **leaves** (`(object_id, embedding_commit)`), not over
the **HNSW graph adjacency**. The verifier therefore has nothing to replay the walk against — it
cannot recompute the neighborhood the genuine HNSW search would visit. So the spec's "replay the
graph walk" is not achievable with the current commitment, regardless of verifier code.

## Actual guarantee (what is truly proven)

With the agent's `leaf_indices` fix, every candidate **is** a distinct, authenticated member of
the committed set (membership is sound). So the HNSW path proves:

> **dominance over a prover-CHOSEN set of authenticated members** — *not* dominance over the
> genuine HNSW-visited neighborhood, and *not* global exact-NN.

A malicious prover can choose a `visited_order` that excludes the true nearest neighbor and favors
a poisoned result; every member it presents is real, dominance holds over that chosen subset, and
the verifier accepts. Membership can't be forged; **neighborhood selection is unconstrained.**

## Fix options

- **A (honesty, cheap, do now):** downgrade the claim. Un-check the "replay the graph walk" line
  in P1-1; state the HNSW level as *"dominance over a prover-asserted set of authenticated
  members."* Surface that level in `retrieval_proof_level` / `ZK_BACKEND` honesty strings so a
  certificate consumer knows the neighborhood is prover-chosen.
- **B (real enforcement, larger):** commit the HNSW graph adjacency (a Merkle/au­thenticated
  structure over the graph) and have the verifier **replay the deterministic walk** from the entry
  point using the committed graph, proving `visited_order` equals the genuine traversal. Only then
  is "audit-on-demand replay" truthfully met.
- **C:** for strong guarantees, prefer the **ExactDominance** path (already sound — rebuilds the
  full committed set and binds to the signed root), and treat HNSW as a best-effort fast path with
  the honest, weaker label from A.

## Recommendation

Ship **A immediately** (it's a one-line honesty correction + un-check the spec box), and schedule
**B** for the Phase IV PIOP work (global exact-NN over HNSW) where the graph commitment naturally
belongs. Do **not** leave P1-1's HNSW box `[x]` with the "replay the graph walk" wording — it
overstates the guarantee.
