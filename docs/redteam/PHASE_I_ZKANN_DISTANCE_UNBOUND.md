# Finding — zkANN distances are prover-supplied (ranking forgeable; "true top-k" overclaimed)

**Severity: MEDIUM (retrieval-correctness / honesty — not content injection).** Date 2026-06-04.
Found by the generative adversarial harness
(`crates/mneme-index/tests/zkann_generative_adversarial.rs`).

## What

The zkANN-1 verification object's candidate rows are `(ObjectId, embedding_commit: [u8;32], distance: i64)`.
The **distance is prover-supplied and never recomputed by the verifier:**
- the prover computes it from the real embedding (`execute_procedure_p` → `integer_distance(query, entry.embedding)`),
- but the verifier's `replay_from_candidates` sorts/selects by the **supplied** `distance` field, and
- the VO carries the embedding **commit** (a BLAKE3 hash), *not* the embedding vector — so the verifier
  *cannot* recompute the distance even though it has the query embedding.

`verify_candidate_set_binds_root` proves the candidate set is the **complete** committed member set
(ids + embedding_commits rebuild the signed `semantic_commit`), and membership/Merkle checks are
sound (the generative harness confirms all root-bound mutation classes fail closed). But the
**ranking among those members is computed from numbers the prover can choose.**

## The forgery

A malicious prover (a compromised/dishonest store) returns an **authentic, real member** that is
*not* the true nearest neighbour: claim a small `distance` for the chosen member and large
`distance`s for the others (including the true nearest, which `binds_root` forces to be present).
`replay_from_candidates` ranks the chosen member top-1; dominance holds over the claimed distances;
the verifier accepts. The agent receives an *authentic* memory — just not the *relevant* one. So an
attacker-controlled store can **steer which genuine memory surfaces** for a query.

Weaker than content injection (the returned object is a real, authenticated member — it cannot be
fabricated), but it **breaks the retrieval-correctness claim**: "exact dominance ⇒ true top-k" is
overclaimed. The honest level actually proven is:

> **top-k of the prover-asserted distances over the COMPLETE authenticated member set** — not top-k
> by the true query-to-embedding distances.

## Fix (makes "true top-k" sound)

Bind distance to the committed embedding so the verifier recomputes it:
1. Carry each candidate's embedding **vector** in the VO (not only its commit).
2. In the verifier, for every candidate: check `embedding.commit() == embedding_commit` (binds the
   vector to the committed leaf) **and** `integer_distance(query_embedding, embedding) == distance`
   (binds the claimed distance to the truth). The query embedding is already available to the recall
   verifier (`emb.commit() == receipt.query_commit` is checked).
3. Then `replay_from_candidates` operates on verifier-recomputed distances → dominance is over true
   distances → genuine top-k.

Cost: larger VO/receipt (embeddings, not just 32-byte commits); `mneme-crossref` and the Cognition
Certificate must mirror the recompute to stay in agreement. Schedule alongside the Phase IV
PIOP/global-NN work (which addresses the HNSW-approximate axis).

## Interim honesty (shipped + guarded)

Current wording states exact-dominance proves
**"top-k of the prover-asserted distances over the complete authenticated member set."** Membership
and completeness are sound; *distance correctness* is not yet verified. `PHASE_I_TASK_SPEC.md` §5,
`docs/ROADMAP.md`, the Phase IV PIOP baseline, and `RetrievalProofLevel::ExactDominance` docs now
use this boundary, with a core source guard preventing the old "True top-k" wording from returning
to the interface seam.

## Regression

`zkann_generative_adversarial.rs` asserts all root-bound mutation classes fail closed (4000
mutations) and explicitly records distance (class 3) + leaf_index (class 6) as the known
non-binding fields, so this finding cannot silently regress into a *membership* fail-open.
