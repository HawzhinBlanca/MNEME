# Verifiable Absence & Provably-Complete Retrieval

**Status:** research spec / north-star. Not yet wired into the TCB. Honesty boundary unchanged:
this proves **completeness of retrieval** (no closer neighbor was hidden), *not* that any memory
is true. Authenticated ≠ true; complete ≠ wise.

---

## 0. The unification

Every hard open problem in MNEME ∞ is the **same** problem — a *proof of absence*:

| Open problem | As an absence claim | Primitive |
|---|---|---|
| True top-k retrieval | "no un-returned point is closer than the k-th" | **geometry (this doc)** |
| Nothing else entered context | "no extra entry is in the context set" | set non-membership (SMT ✅) |
| Not used after forgetting | "shredded item absent from all later certs" | log non-membership |
| Poison-free recall | "no unauthorized writer's entry is present" | set non-membership (SMT ✅) |

MNEME already ships set non-membership (`mneme-smt`). The **Verifiable Absence Calculus** is the
generalization: one composable interface,

```
prove_absent(commitment C_S, predicate P) -> π        // succinct
verify_absent(C_S, P, π) -> bool                       // fail-closed, tiny TCB
```

instantiated over **sets** (have it), **geometry** (§2, the missing piece), and **time** (log).
Soundness ("what I returned is real") is easy. **Completeness ("nothing was hidden") is the
universal hard part**, and it is one shape every time.

---

## 1. Problem statement — Authenticated Complete k-NN (ACkNN)

Let `(M, d)` be a metric space, `D = {x_1,…,x_n} ⊂ M` a dataset with a public commitment `C_D`.

**Prover** receives `(q, k)` and returns `R ⊆ D, |R| = k`, plus a proof `π`.
**Verifier** receives `(C_D, q, k, R, π)` and must accept iff `R` is **exactly** the true
k-nearest neighbors of `q` (ties broken by committed index, deterministically).

Two requirements:

- **(S) Soundness** — every `x ∈ R` is genuinely in `D` (Merkle membership) and each claimed
  distance is correct (verifier recomputes `d(q,x)`).
- **(C) Completeness** — `∀ x ∈ D\R : d(q,x) ≥ τ`, where `τ = max_{x∈R} d(q,x)`. *This is the part
  no shipping verifiable-RAG system proves.*

Cost target: verifier work and proof size **sublinear in n** (ideally `O(k + log n)`).

---

## 2. Construction — geometric completeness via pruning certificates

**Authenticated ball tree.** Commit a binary ball tree `T` over `D`: each node `v` carries a
pivot `p_v ∈ M` and covering radius `R_v` with the invariant `∀ x ∈ subtree(v): d(p_v,x) ≤ R_v`.
Hash `(p_v, R_v, h(left), h(right))` Merkle-style into `C_D` — so **both the node data and the
tree topology are bound** (you cannot later hide that a node had two children).

**The pruning certificate (reverse triangle inequality = a proof of absence).**
For any node `v` and query `q`, every `x ∈ subtree(v)` satisfies
```
d(q,x) ≥ d(q,p_v) − R_v.            (reverse triangle inequality)
```
So if `d(q,p_v) − R_v > τ`, then **no point under `v` can be a top-k member**. The certificate
for `v` is the authenticated `(p_v, R_v)` + its Merkle path. The verifier does **one** distance
eval per pruned node — not one per point.

**The proof π** is a *frontier* `F` of tree nodes plus the returned set `R` such that:

1. **Cover (antichain partition):** every root→leaf path of the committed `T` passes through
   exactly one returned leaf (`x ∈ R`) **or** one frontier node (`v ∈ F`). Checkable from the
   committed topology alone — *this is what makes omission impossible.*
2. **Membership:** each `x ∈ R` has a Merkle membership proof; verifier recomputes `d(q,x)`.
3. **Pruning:** each `v ∈ F` satisfies `d(q,p_v) − R_v > τ` (verifier recomputes `d(q,p_v)`).

**Theorem (completeness).** If `verify` accepts, `R` are the true k-NN.
*Proof.* Take any `x ∈ D`. By the cover, `x ∈ R` or `x ∈ subtree(v)` for some `v ∈ F`. In the
latter case `d(q,x) ≥ d(q,p_v) − R_v > τ`, so `x` is strictly farther than every returned
neighbor and cannot belong to the true k-NN. Hence `D\R` holds no closer point. ∎

**Theorem (soundness).** Returned points are real and correctly ranked, by Merkle membership +
verifier-side distance recomputation; tree-data forgery reduces to a Merkle/hash collision. ∎

**Cost.** Verifier: `O(k)` + `O(|F|)` distance evals + Merkle checks. For well-separated
low/moderate-dim data `|F| = O(log n)`. **Worst case `|F| = O(n)` — see §3.**

---

## 3. Where it breaks — the actual research prize (stated honestly)

In raw `D`-dim embedding space (768–1536), the **curse of dimensionality** makes
`d(q,p_v) − R_v` almost always ≤ 0, so nothing prunes and `|F| → O(n)`. The pruning certificate
is *correct* but *not succinct*. Two honest escape routes:

**(a) JL-projected pruning.** Draw a random projection `Φ: R^D → R^m`, `m = O(ε⁻² log n)`, from a
**public randomness beacon** (drand / NIST beacon) so the prover cannot choose `Φ` adversarially.
By Johnson–Lindenstrauss, w.h.p. `(1−ε)‖u−v‖ ≤ ‖Φu−Φv‖ ≤ (1+ε)‖u−v‖`. Build/commit the ball
tree in projected space. Two modes:

- **Sound-conservative:** prune only when `d(Φq,Φp_v) − R^Φ_v > (1+ε)·τ^Φ` (inflate by worst-case
  distortion). **Never wrongly prunes ⇒ exact completeness**, but compresses less.
- **Probabilistic:** prune on the raw projected bound ⇒ completeness with explicit soundness
  error `δ` = JL failure probability. Because `Φ` is beacon-derived, the adversary cannot aim at
  the failure set; amplify by independent beacon-seeded projections.

**The open problem:** find the `(m, ε)` regime where JL-projected pruning is **both** sublinear
(`|F| = o(n)`) **and** sound on real embedding distributions. Land that with a tight distortion
bound and you have the result verifiable-RAG is missing.

**(b) Graph-completeness over HNSW.** Alternative: prove a *local-optimum certificate* on the
committed HNSW graph (returned nodes' neighborhoods contain no closer node). Cheaper but only
proves graph-local completeness, not global — honest, weaker, and a fallback when (a) won't
compress.

---

## 4. Implementation plan (for an AI agent)

Discipline carried from MNEME: **fail-closed**, **tiny verifier**, **generative tamper tests**,
**byte-deterministic**. Each phase has an acceptance gate; nothing advances on red.

**Phase 0 — Exact geometry, no crypto.** New crate-internal module `mneme-index/src/complete_knn/`.
Implement ball-tree build + brute-force k-NN + pruning-frontier search in `R^m`.
- *Accept:* proptest over random low-dim datasets — frontier-pruned k-NN == brute-force k-NN for
  1000 random queries; ties broken by index deterministically.

**Phase 1 — Authenticated tree.** Commit `(p_v, R_v, h(children))` via `mneme-smt`/Merkle; bind
topology. Membership proofs for leaves.
- *Accept:* a flipped pivot/radius/child-hash changes `C_D`; membership verifies; round-trip
  byte-identical (determinism gate).

**Phase 2 — Prover + verifier.** Prover emits `(R, F, paths)`; verifier checks cover-antichain +
membership + pruning bound. Keep the verifier **minimal and panic-free** (TCB discipline; if it
touches the trusted surface, add to `verify-tcb-guard.sh` per WO-9's rule).
- *Accept:* honest prover → accept; verifier work measured `O(k + |F|)`.

**Phase 3 — Generative tamper suite (the signature gate).** Adversary attempts, all must
**fail closed** with typed errors: (a) omit a branch from the cover; (b) inflate a radius to
over-prune; (c) understate `τ`; (d) return a non-member; (e) forge a pivot.
- *Accept:* ≥150 generated adversarial cases, 100% rejected; mirrors `validation-lane tamper`.

**Phase 4 — JL variant.** Beacon-seeded `Φ` (commit the beacon round + seed in the proof);
implement sound-conservative **and** probabilistic modes with the distortion check.
- *Accept:* conservative mode never wrongly prunes (property test vs exact); probabilistic mode's
  empirical error ≤ `δ`; beacon value is bound and re-derivable offline.

**Phase 5 — Certificate integration.** Add `RetrievalProofLevel::CompleteTopK` to `mneme-core`;
emit the completeness proof inside `cognition_cert`; extend `mneme verify-cert` with an offline
complete-k-NN check.
- *Accept:* `certify`/`verify-cert` round-trip green; cert byte-identical across two runs
  (determinism); cross-impl vector added.

**Phase 6 — Honest compression curve.** Benchmark `|F|/n` vs dimension `D`, projected dim `m`,
and `ε`, on real embeddings. Publish the regime where it works **and where it doesn't**.
- *Accept:* a reproducible plot + a one-paragraph honest disposition in `REMAINING_ITEMS.md`
  (named modes, proven properties, the dimension ceiling).

**Sequencing:** 0→1→2→3 is the buildable core (exact, low-dim, fully adversarially tested) and is
worth shipping alone — it is already beyond any verifiable-RAG system. 4→6 is the research frontier.

---

## 5. Reference pseudocode

```text
# Prover: complete k-NN with pruning frontier (projected space assumed)
search(T, q, k):
    R = top_k_by_bruteforce_or_tree(T, q, k)       # candidate answer
    τ = max(d(q,x) for x in R)
    F = []                                          # pruned frontier
    def visit(v):
        if is_leaf(v):
            assert v.point in R                     # else not complete → abort
            return
        lo = d(q, v.pivot) - v.radius               # reverse-triangle bound
        if lo > τ: F.append(v); return              # prune whole subtree
        visit(v.left); visit(v.right)
    visit(root(T))
    return R, F, merkle_paths(R ∪ F)

# Verifier: fail-closed, O(k + |F|)
verify(C_D, q, k, R, F, paths):
    require |R| == k
    require merkle_paths_valid(C_D, R ∪ F, paths)   # data + TOPOLOGY bound
    require is_antichain_cover(C_D, R, F)            # every leaf under exactly one of R∪F
    τ = max(recompute d(q,x) for x in R)
    for v in F:
        require (d(q, v.pivot) - v.radius) > τ       # (conservative: > (1+ε)·τ)
    return ACCEPT                                     # ⇒ R are the true k-NN
```

The whole verifier is a handful of checks: Merkle validity, the antichain-cover predicate, `k`
distance recomputations, `|F|` pruning-bound comparisons. That smallness is the point — it stays
inside the "read it in an afternoon" TCB budget.
