# JL Distortion Bound for Complete k-NN Pruning (CR-6 research)

**Status:** research note — conservative mode is **exact**; probabilistic mode is **heuristic**.

Companion: [`VERIFIABLE_ABSENCE_AND_COMPLETE_RETRIEVAL.md`](VERIFIABLE_ABSENCE_AND_COMPLETE_RETRIEVAL.md) §3a.

---

## Setup

Let `Φ: ℝ^D → ℝ^m` be a linear Johnson–Lindenstrauss map drawn from a **public beacon**
(round + seed committed in the proof). For all pairs `u, v` in the dataset and query:

```
(1 − ε) ‖u − v‖₂ ≤ ‖Φu − Φv‖₂ ≤ (1 + ε) ‖u − v‖₂        (w.h.p., failure prob ≤ δ_JL)
```

MNEME commits a ball tree in **projected** space: each internal node has pivot `p` and radius
`R_Φ` covering its subtree in `‖·‖₂` after projection.

Reverse triangle in projected space: for any `x` in subtree(`v`),

```
‖Φq − Φx‖₂ ≥ ‖Φq − Φp‖₂ − R_Φ = lb_Φ .
```

JL lower bound on original distance:

```
‖q − x‖₂ ≥ lb_Φ / (1 + ε) .
```

Let `τ = max_{r ∈ R} ‖q − r‖₂` (original metric, returned set `R`).

---

## Sound-conservative mode (proved exact completeness)

**Prune** subtree `v` only when:

```
lb_Φ > (1 + ε) · τ .
```

Then for every `x` in the subtree:

```
‖q − x‖₂ ≥ lb_Φ / (1 + ε) > τ ,
```

so no `x` can belong to the true top-k in original space. **Conservative search never wrongly
prunes** ⇒ frontier-pruned k-NN equals brute-force k-NN (property-tested in
`complete_knn_jl.rs`).

**Cost honesty:** inflation by `(1+ε)` reduces pruning versus raw projected bounds; in high `D`
the bound may still fail to compress (`|F|/n → 1`). That is an acceptable outcome, not a bug.

Implementation: `JlPruningMode::SoundConservative` in
`crates/mneme-index/src/complete_knn/jl_projection.rs`.

---

## Probabilistic mode (explicit failure probability)

**Prune** when `lb_Φ > τ_Φ` where `τ_Φ = max_{r ∈ R} ‖Φq − Φr‖₂`.

Under the JL event, completeness holds w.h.p. with failure probability ≤ `δ_JL` per projection.
Beacon-derived `Φ` prevents the prover from choosing a map that targets a failure set.

**Not proven here:** `δ_JL` on real embedding manifolds (768–1536-d) or ANN-skewed trees.
Empirical mismatch rate is gated in tests with a generous margin — not a theorem.

---

## Open problem (dimension ceiling)

Find `(m, ε)` where JL-projected pruning is **both**:

1. sublinear (`|F| = o(n)`), and
2. sound on production embedding distributions.

Until that bound is tight, ship **exact low/moderate-dim complete k-NN (CR-1..CR-4)** and treat
JL as an optional research mode with the conservative ceiling above.

**Beacon offline check:** `JlProjector::commitment()` hashes `(round, seed, D, m)`; verifiers
re-derive `Φ` from committed beacon fields before checking pruning bounds.
