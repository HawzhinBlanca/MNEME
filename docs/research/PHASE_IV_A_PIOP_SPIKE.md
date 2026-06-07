# Phase IV-A — zkRAG-style PIOP Spike (research memo)

**Task:** `docs/PHASE_IV_TASK_SPEC.md` P4-1 (roadmap Phase IV step 1: "Global
exact-NN — land the [zkRAG-style PIOP](https://eprint.iacr.org/2026/709) over
HNSW → succinct global exact-NN, retiring the last retrieval caveat").

**Status:** Research spike / decision memo. **Not** a build commitment, **not** a
benchmark report. No code on the recall path changes as a result of this memo.

**Honesty contract for this document (binding):** every quantitative figure
below is an *author-reported* number from an external paper, explicitly labelled
as such and **not** independently reproduced inside MNEME. This memo states **no
new theorem**, proves nothing, and claims no MNEME benchmark. If a later
engineer needs a number to make a decision, they must measure it (see §6, Step
4) — they may not cite this memo as evidence of performance.

---

## 1. What we have today (the baseline this spike would improve on)

The honest level reached by Phase I `zkANN-1` (`docs/PHASE_I_TASK_SPEC.md` §5,
`crates/mneme-index`):

| Path | What is *proven* | What is *not* proven |
|---|---|---|
| **ADS verification object** (`verify_ads_vo`, default `ads` feature) | The returned `result_ids` are the faithful output of deterministic procedure **P** (`execute_procedure_p`, INV-10) replayed over candidates whose embedding commitments are Merkle-included under the signed `semantic_commit`. | Exact global nearest neighbors. The candidate set in the VO is what the procedure examined; nothing proves no *better* unexamined vector exists in the committed set. |
| **Exact / flat path** (`PHASE_I_TASK_SPEC.md` P1-1) | Membership/completeness over the committed set, plus top-k dominance over prover-asserted distances. | True query-to-embedding distance ordering. The VO carries embedding commitments, not embedding vectors, so current verifiers cannot recompute candidate distances. It is also not succinct: the VO carries every examined candidate + Merkle paths. |
| **HNSW audit-on-demand** (`PHASE_I_TASK_SPEC.md` P1-1b) | Procedure-faithful replay over a prover-asserted authenticated `visited_order`, with dominance over that visited set. | Replay of the actual HNSW graph walk or dominance over the whole committed set. The walk can miss a true nearest neighbor; that is the defining caveat of approximate ANN. |
| **`pedersen_schnorr_zk`** (12-month B3; `pedersen_schnorr_zk.rs`) | *Witness privacy* for a single committed retrieval-match: "I know an opening of `public_commit` equal to the (hidden) query," via a Pedersen+Schnorr equality-of-openings NIZK over Ristretto (transparent, no trusted setup). Currently attached for the top-1 result only (`try_attach_zk_retrieval`). | Anything about ranking, dominance, or exact-NN. It hides *which* entry matched; it does not prove the match was the *best* match. It is **not** Plonky2/FRI and **not** a SNARK. |

The standing §3 honesty boundary
(`mneme_verify::HONESTY_PROCEDURE`, `MNEME_BLUEPRINT.md` §3) is the thing
Phase IV-A would narrow:

> "receipt proves faithful execution of procedure P over committed data, not
> true nearest neighbors"

This memo's subject is: **can a zkRAG-style PIOP retire the
*global-exact-NN* caveat without spending the things MNEME refuses to spend
(TCB budget, fail-closed discipline, stable toolchain, honesty)?**

---

## 2. What a zkRAG-style PIOP would prove vs Phase I zkANN-1

A *Polynomial Interactive Oracle Proof* (PIOP), compiled to a non-interactive
argument via a polynomial-commitment scheme and Fiat–Shamir, is the standard
machinery behind succinct arguments (PLONK/Plonky2/FRI/sumcheck families). The
zkRAG/V3DB line of work (refs in §7) applies this to vector retrieval.

**The statement a Phase IV-A PIOP would target** (stated as a *goal*, not a
proven claim):

> Given the committed vector multiset `V` fixed by `semantic_commit`, a declared
> distance metric `D`, a query `q`, and an integer `k`, the returned set
> `R = {id_1 … id_k}` is **exactly** the top-k of `V` under `D` — i.e. for every
> returned `r ∈ R` and every *non-returned* `u ∈ V \ R`, `D(q, v_r) ≤ D(q, v_u)`
> — and this holds over the **entire** committed set, with a proof whose size and
> verification time are **succinct** (sub-linear, ideally polylogarithmic, in
> `|V|`).

The delta against what we ship today:

| Property | Phase I `zkANN-1` (ADS / audit-on-demand) | Phase IV-A PIOP target |
|---|---|---|
| **Scope of dominance** | Examined / visited candidate set only | **Whole committed set** `V` (global) |
| **Approximation caveat** | Remains for HNSW (visited neighborhood) | **Retired** (this is the entire point) |
| **Proof size / verify cost** | Linear-ish in examined candidates (VO carries candidates + Merkle paths) | **Succinct** (sub-linear in `|V|`) — the property an ADS VO structurally cannot give |
| **Witness privacy** | Optional, top-1 only (`pedersen_schnorr_zk`) | Can be designed in (zk-PIOP) but is **orthogonal** to exactness; do not conflate |
| **Trust assumptions** | Hash function (BLAKE3) + Ed25519 root only | + polynomial-commitment soundness, Fiat–Shamir in ROM, possibly a structured reference string |

Two honesty points that must survive into any future certificate field:

1. **Exact-NN ≠ semantic truth.** Even a perfect global-exact-NN proof still only
   says "these are the closest committed vectors under `D`." Authenticated ≠
   true (§3.1) is untouched. The PIOP retires *one* caveat (caveat #2 of the
   roadmap), not the truth caveat.
2. **Exactness is relative to the committed embeddings and `D`.** It proves
   nothing about whether the *embeddings themselves* faithfully represent the
   underlying content. That is an upstream modelling question, out of scope.

---

## 3. Dependency on the frozen `semantic_commit` + procedure P

The PIOP statement in §2 is only meaningful because it is **bound to existing
frozen seams**. This is a strength (it composes with the signed root) and a
hard engineering constraint (the seams were not designed to be
proof-system-friendly).

### 3.1 Binding to `semantic_commit`

`semantic_commit` is today a **BLAKE3 Merkle root** over `(ObjectId,
embedding_commit)` leaves (`semantic.rs::semantic_commit`,
`commit::SemanticMerkleTree`, `hash_sem_leaf`). The signed `Root` commits to it,
and the ADS VO proves Merkle inclusion against it.

**The tension:** BLAKE3 is *not* an arithmetization-friendly commitment. PIOP
provers operate over a prime field; a BLAKE3 Merkle path expressed as an
in-circuit constraint system is expensive (every compression function call
becomes thousands of constraints). Two honest options, both with costs:

- **(a) Prove BLAKE3 in-circuit.** Keeps `semantic_commit` byte-identical and
  therefore keeps determinism + the signed-root preimage unchanged. Cost: large
  prover blow-up; this is the dominant cost driver in hash-heavy verifiable-DB
  papers.
- **(b) Add a parallel field-friendly commitment** (e.g. a Poseidon/Rescue
  Merkle tree or an algebraic vector commitment) computed alongside the BLAKE3
  tree, with a one-time proof that the two commit to the same multiset. Cost: a
  second commitment in the index, a new determinism surface to pin, and a
  binding argument between the two roots.

Either way, **`mneme-core/src/interface.rs` and the signed-root preimage must
not change** (interface freeze; determinism foundation-gate). Option (b) is
additive (a sidecar commitment) and is the lower-risk path *if* the cross-commit
binding can be made cheap; Option (a) is zero-interface-change but proving-cost
heavy. **This memo does not pick a winner** — that is Step 2 of §6.

### 3.2 Binding to procedure P

Procedure **P** (`procedure_id`, `execute_procedure_p`) is a deterministic,
integer-distance, ObjectId-tie-broken selection (INV-10). The PIOP must prove
its statement *relative to the same `P` and `D`* that the receipt declares, or
the proof and the receipt describe different computations.

Crucially, the *exact-NN* statement (§2) is **stronger than** "P ran
faithfully": for a flat/brute-force `P`, faithful execution already implies
exact-NN; for an HNSW `P`, faithful execution does **not** imply exact-NN. So a
Phase IV-A PIOP that proves *global exact-NN* effectively proves the result a
*correct exhaustive* procedure would have produced — it does not need to prove
the HNSW walk faithfully, it needs to prove the **output dominates the whole
committed set**. This is an important framing the spec should fix early: we are
proving the *answer is exact*, not that *the approximate walk was faithful*.
(`distance::integer_distance` is already integer-only, which is friendly to a
field encoding — a genuine point in our favor.)

---

## 4. Why this does NOT belong in the `mneme-verify` TCB

This is the load-bearing constraint and the reason Phase IV-A is research, not a
near-term feature.

- **TCB line budget.** `mneme-verify` is capped at **500 lines**
  (`TCB_LINE_BUDGET = 500`, enforced by `scripts/ci/verify-tcb-guard.sh`) and
  carries `#![forbid(unsafe_code)]`. A PIOP verifier — field arithmetic,
  polynomial-commitment opening checks, FRI/sumcheck rounds, transcript/
  Fiat–Shamir handling — cannot fit in 500 auditable lines, and it pulls a large
  third-party dependency tree (the opposite of a tiny, hand-auditable TCB).
- **The whole MNEME thesis is a *small* trust core.** "The tiny verifier TCB is
  the only thing anyone must trust; everything else is checked" (ROADMAP
  cross-cutting). Folding a proof system into the TCB would make the trusted
  surface *larger and harder to audit than the system it verifies* — a net loss
  even if the math is sound.
- **Correct architecture: PIOP verifier is an out-of-TCB checked artifact.** The
  precedent already exists: the optional `pedersen_schnorr_zk` attachment is
  verified **outside** the core fail-closed gate
  (`verify_semantic_receipt_vo` feature-gates `verify_zk_retrieval_attachment`;
  if the attachment is present but the feature is off, it **fails closed** with
  `ZkProofInvalid`). A Phase IV-A PIOP verifier should follow the same shape:
  - The 500-line TCB keeps doing exactly what it does (signed root + Merkle
    inclusion + procedure replay), and continues to **fail closed** on its own.
  - The PIOP verifier is a separate, separately-audited crate whose single
    boolean output can *upgrade a certificate's `retrieval_proof_level`* but can
    **never** be the thing that lets a recall into context on its own. A missing
    or invalid PIOP must degrade to the existing honest level, not open the gate.
- **Fail-closed must be preserved.** Adding a proof system must not introduce a
  path where "proof present but unverifiable" silently passes. The existing
  feature-off-but-attachment-present → `ZkProofInvalid` rule is the template.

**Decision:** the PIOP prover lives in (or beside) `mneme-index`; the PIOP
verifier lives in its **own** crate, out of the `mneme-verify` TCB, wired only as
an *optional certificate enrichment*. The TCB budget and `forbid(unsafe_code)`
are non-negotiable.

---

## 5. 90-day vs 12-month vs Phase IV boundary

| Horizon | Retrieval crypto | Honest level | Exact-NN? |
|---|---|---|---|
| **v0 / 90-day** | `ads` VO + optional `commitment_binding` (BLAKE3 envelope, **not** ZK) | Procedure-faithful over committed data | No |
| **12-month (B3)** | `pedersen_schnorr_zk` (real transparent Pedersen+Schnorr NIZK) | + witness privacy for a committed match (top-1) | No |
| **Phase IV-A (this memo)** | zkRAG-style PIOP (research) | + **global exact-NN** over the committed set | **Target** |

Phase IV-A sits **beyond** the 12-month milestone for concrete, non-negotiable
reasons already recorded in the tree:

1. **Toolchain.** The blueprint's named target is Plonky2/V3DB (FRI-based).
   Plonky2 1.x requires the **nightly** compiler (`feature(specialization)` in
   `plonky2_field`); the repo pins **stable 1.86.0** (`rust-toolchain.toml`).
   This is exactly why B3 shipped Pedersen+Schnorr instead
   (`B3_DEFERRAL_STATUS`). A stable-buildable PIOP stack must be found (or the
   pin re-litigated) before any of this is an engineering task, not a research
   one. **No nightly pin should be adopted to chase this.**
2. **Commitment mismatch (§3.1).** `semantic_commit` is BLAKE3; PIOPs want a
   field-friendly commitment. Resolving this is itself a multi-week spike.
3. **TCB architecture (§4).** Requires a new out-of-TCB verifier crate and a
   certificate-level `retrieval_proof_level` upgrade path — net-new surface.

So: 90-day and 12-month are **shipped, honest, and non-exact**. Phase IV-A is the
first time "global exact-NN" becomes a candidate claim, and only after the three
blockers above are cleared.

---

## 6. Concrete next engineering steps (if the team pursues this)

Ordered, each independently abandonable. None of these is started by this memo.

1. **Formalize the statement (paper artifact, no code).** — **Done (research slice):**
   `docs/research/PHASE_IV_A_PIOP_STATEMENT.md` (exact-NN statement, integer-distance
   encoding, threat model §4, fail-closed degradation §4.4).
2. **Toolchain buildability matrix (spike, no proofs).** — **Done (research slice):**
   `docs/research/PHASE_IV_A_PIOP_TOOLCHAIN_MATRIX.md` (stable 1.86.0 survey; no nightly
   for Plonky2; out-of-TCB verifier architecture unchanged).
3. **Commitment-bridge spike (§3.1).** Prototype Option (b): a field-friendly
   sidecar commitment over the same `(ObjectId, embedding_commit)` multiset,
   computed deterministically alongside the BLAKE3 tree, plus a microbenchmark of
   the determinism cost. Must leave `semantic_commit` and the signed-root
   preimage byte-identical. Output: measured insert/commit overhead + a
   cross-commit binding sketch.
4. **Out-of-TCB prototype prover/verifier on a tiny flat index.** Prove *exact
   top-1 dominance* over a small committed set end-to-end in a standalone crate
   (never in `mneme-verify`). Measure prover time, verifier time, and proof size
   on a labelled microbenchmark and report them **honestly** (with hardware,
   `|V|`, and dimension stated; no extrapolation). Output: the first *real* MNEME
   number to replace the author-reported figures in §7.
5. **Threat model + certificate integration design.** Document the new trust
   assumptions (ROM, commitment soundness, any SRS), the
   `retrieval_proof_level` certificate field upgrade, and the fail-closed
   degradation rule (PIOP absent/invalid → fall back to the current honest
   level, never open the gate). Output: a soundness doc + a go/no-go against the
   blueprint kill criteria (§"Kill criteria": abandon if the receipt proves too
   little to be useful, or overhead cannot be amortized).

**Recommended gate:** do Steps 1–2 first and cheaply. If Step 2 finds **no**
stable-buildable, transparent, acceptably-weighted stack, Phase IV-A stays a memo
and the honest level remains "dominance over the committed/visited set" — which
is already a defensible, shipped position.

---

## 7. References (external; figures are author-reported, NOT reproduced here)

These are the citations already recorded in `MNEME_BLUEPRINT.md` and
`docs/VISION_PROOF_CARRYING_COGNITION.md`. Any number attached to them is the
*paper authors'* claim and has **not** been independently measured in MNEME.

- **zkRAG-style HNSW PIOP** — IACR ePrint [2026/709](https://eprint.iacr.org/2026/709). The roadmap's named Phase IV target.
- **V3DB** — arXiv:2603.03065 (Mar 2026): Plonky2 ZK verifiable vector DB; proves *faithful execution*, **not** exact-NN (author-reported ~22× prover speedup — not reproduced here).
- **ANNProof** — *FGCS* Vol. 156 (2024): authenticated HNSW retrieval; author-reported VO-gen/verify/size ratios — not reproduced here.
- **Efficient Sparse Merkle Trees** — Dahlberg, Pulls & Peeters, NordSec 2016 / IACR ePrint 2016/683 (the SMT MNEME already ships).

---

## 8. Bottom line

A zkRAG-style PIOP is the *right* tool to retire the last retrieval caveat
(global exact-NN), and it composes with our frozen `semantic_commit` + procedure
P **in principle**. But it is gated behind three real blockers — a stable
toolchain for a succinct-argument stack, a field-friendly commitment bridge, and
an out-of-TCB verifier architecture — none of which are 90-day or 12-month work.
Until Steps 1–2 of §6 clear, MNEME's honest retrieval level remains *dominance
over the committed/visited set*, and the §3 boundary stands unchanged. Nothing in
this memo is a proof, a benchmark, or a commitment.
