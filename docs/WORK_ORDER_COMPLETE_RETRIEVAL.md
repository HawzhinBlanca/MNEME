# Work Order — Provably-Complete Retrieval (Verifiable Absence Calculus)

**Source spec:** [`docs/research/VERIFIABLE_ABSENCE_AND_COMPLETE_RETRIEVAL.md`](research/VERIFIABLE_ABSENCE_AND_COMPLETE_RETRIEVAL.md)
**For:** the autonomous hardening agent. **Reviewer/verifier:** watcher agent (per-phase gate).
**Goal:** upgrade retrieval from *procedure-faithful* to **provably-complete top-k** — prove no
closer neighbor was hidden — composed into the Cognition Certificate.

**Honesty boundary (do not weaken):** this proves **completeness of retrieval**, not truth and
not exact-NN-by-semantic-relevance. Authenticated ≠ true; complete ≠ wise. State the dimension
ceiling honestly (§3 of the spec).

**Discipline (carried from WO-1..20):** fail-closed everywhere; tiny panic-free verifier (if it
joins the trusted surface, add to `verify-tcb-guard.sh` per the WO-9 rule and name it in
`TCB_MANIFEST.md`); ≥150-case generative tamper suite; byte-deterministic certs; nothing advances
on a red gate.

---

## Tasks (CR-1 … CR-7 → spec Phases 0…6)

### CR-1 — Exact geometry, no crypto  **[buildable now]** ✅ 2026-06-11
New module `crates/mneme-index/src/complete_knn/`. Ball-tree build + brute-force k-NN +
pruning-frontier search in `R^m` (reverse-triangle bound `d(q,p)−R > τ`).
**Accept:** proptest, 1000 random low-dim queries, frontier k-NN == brute-force k-NN; deterministic
index tiebreak.

### CR-2 — Authenticated tree ✅ 2026-06-11
Commit `(pivot, radius, h(left), h(right))` via `mneme-smt`/Merkle; bind **node data AND topology**;
leaf membership proofs.
**Accept:** any flipped pivot/radius/child-hash changes `C_D`; membership verifies; build is
byte-identical across two runs (determinism gate).

### CR-3 — Prover + verifier ✅ 2026-06-11
Prover emits `(R, F, paths)`. Verifier checks **antichain-cover** + membership + pruning bound,
fail-closed, `O(k+|F|)`. Keep the verifier minimal/panic-free.
**Accept:** honest prover accepts; measured verifier cost `O(k+|F|)`; verifier guard-clean if trusted.

### CR-4 — Generative tamper suite  **[the signature gate]** ✅ 2026-06-11
Adversary must **fail closed** on: (a) omit a branch from the cover; (b) inflate a radius to
over-prune; (c) understate `τ`; (d) return a non-member; (e) forge a pivot.
**Accept:** ≥150 generated cases, 100% rejected with typed errors (mirror `validation-lane tamper`).

### CR-5 — JL-projected variant ✅ 2026-06-11
Beacon-seeded projection `Φ: R^D→R^m` (`jl_projection.rs`; commit via `JlProjector::commitment()`).
**Sound-conservative** (`lb_Φ > (1+ε)·√τ_orig`) AND **probabilistic** (raw projected bound) modes.
**Accept:** conservative never wrongly prunes (proptest + 1000 queries); probabilistic empirical
error ≤ δ+margin; beacon binding re-derivable offline. Proof sketch:
[`docs/research/JL_DISTORTION_BOUND.md`](research/JL_DISTORTION_BOUND.md).

### CR-6 — Distortion bound + cert wire ✅ 2026-06-11
Distortion proof sketch in [`docs/research/JL_DISTORTION_BOUND.md`](research/JL_DISTORTION_BOUND.md).
`RetrievalProofLevel::CompleteTopK`, receipt field 8, `verify-cert` offline path, and
`complete_knn_cert_v1` round-trip. **Parked:** `SemanticIndex::recall` wiring + cross-impl vector
(see `docs/HUMAN_TASKS.md`).

### CR-7 — Honest compression + sequencing ✅ 2026-06-11 (synthetic gate)
Reproducible `|F|/n` benchmark on synthetic cubes (`complete_knn_compression` test + CSV stderr).
Disposition in [`REMAINING_ITEMS.md`](REMAINING_ITEMS.md) and
[`docs/benchmarks/COMPLETE_KNN_COMPRESSION.md`](benchmarks/COMPLETE_KNN_COMPRESSION.md).
**Not done:** real 768–1536-d embedding sweep (needs operator embedding corpus).

---

## Sequencing
**CR-1 → CR-2 → CR-3 → CR-4** is the buildable core: exact, low/moderate-dim, fully adversarially
tested — ship it alone; it already exceeds any shipping verifiable-RAG system. **CR-5 → CR-7** is
the research frontier (the JL distortion bound that stays sound *and* compresses is the prize; it
may not close in raw high-dim — that's an acceptable, honest outcome to document, not hide).

After each CR, the standard sweep (fmt/clippy/TCB-budget/honesty/tests/tamper/determinism/cross-impl)
must stay green before the next. Cross-reference: `docs/TCB_MANIFEST.md`, `docs/REMAINING_ITEMS.md`.
