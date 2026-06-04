# Phase IV-A — Exact-NN PIOP Statement & Threat Model (Step 1)

**Task:** `docs/PHASE_IV_TASK_SPEC.md` P4-1, `PHASE_IV_A_PIOP_SPIKE.md` §6 Step 1.

**Status:** Paper artifact only. **No code** on the recall path. **No theorem proved here.**

**Honesty:** This document formalizes a *target statement* and a *red-team sketch*. It does not
claim the statement is achievable on MNEME's current pins, does not cite MNEME benchmarks, and
must not be used as evidence of prover/verifier performance.

---

## 1. Symbols (bound to frozen seams)

| Symbol | Meaning | MNEME seam |
|---|---|---|
| `V` | Finite multiset of committed vectors | Leaves under `semantic_commit` (BLAKE3 Merkle root in signed `Root`) |
| `id(v)` | `ObjectId` for vector `v` | `hash_sem_leaf` leaf key |
| `emb(v)` | `embedding_commit` for `v` | 32-byte leaf payload |
| `D` | Distance function | `integer_distance` (`i64`, field-friendly target) |
| `P` | Declared retrieval procedure | `procedure_id` + `execute_procedure_p` (INV-10) |
| `q` | Query | `query_commit` (committed query embedding) |
| `k` | Result count | Receipt `k` |
| `R` | Returned id set | `result_ids` in semantic receipt / VO |

**Precondition (binding):** `semantic_commit` in the PIOP public input equals the
`semantic_commit` field in the signed root the receipt binds to. The PIOP does not re-sign the
root; it assumes an already-verified Ed25519 `Root` (out of scope for the PIOP itself).

---

## 2. Exact top-k dominance statement (goal, not proven)

Let `V = { v_1, …, v_n }` be the committed multiset fixed by `semantic_commit`. Let
`R ⊆ V` with `|R| = k` be the prover's claimed answer set with corresponding `ObjectId`s.

**Global exact top-k (dominance over all of `V`):**

For every `r ∈ R` and every `u ∈ V \ R`:

```
D(q, emb(r)) ≤ D(q, emb(u))
```

with ties broken by the same deterministic `ObjectId` order as procedure **P** (INV-10).

**Succinctness requirement (engineering, not formalized here):**

Proof size `|π|` and verifier time `T_v` must be **sub-linear in `n`** (target: polylog in `n`
and dimension), or the PIOP does not retire the ADS VO size caveat from Phase I.

**What this statement does *not* claim:**

- Semantic truth of embeddings (§3.1 honesty: authenticated ≠ true).
- That `D` or the embedding model is correct for the application.
- Faithful execution of an approximate HNSW walk (we prove the *answer*, not the *walk*).
- Witness privacy (orthogonal; optional zk-PIOP layer).

---

## 3. Integer distance encoding (advantage for arithmetization)

MNEME already uses `i64` distances in procedure replay. A PIOP circuit should use the same
encoding:

- Public: `query_commit`, `semantic_commit`, `procedure_id`, `k`, claimed `R` (ids + distances).
- Witness: openings of embedding commitments, full candidate distance table for dominance checks.
- Constraint: recompute `D(q, emb(v))` in-field and compare against claimed distances; Merkle
  inclusion of each `(id, emb)` under `semantic_commit` (BLAKE3 or bridged field commitment — see
  spike §3.1).

Mismatch between PIOP `D` and receipt `procedure_id` → **fail closed** at certificate integration
(not silent downgrade).

---

## 4. Threat model & red-team sketch

### 4.1 Malicious prover goals

| Goal | Attack idea | Required defense |
|---|---|---|
| **Smuggle a non-member** | Return `id` not in `V` | Merkle / vector-commitment membership for every `r ∈ R` |
| **Hide a better neighbor** | Omit a `u ∈ V` with smaller distance than some `r ∈ R` | Dominance constraints over **all** `V`, not visited set |
| **Weaken distance** | Claim smaller `D` than true | In-circuit `D` matches `integer_distance` |
| **Procedure swap** | PIOP for `P'` while receipt says `P` | Bind `procedure_id` in PIOP public input + transcript |
| **Root swap** | PIOP for commit `C'` while receipt binds `C` | `semantic_commit` in PIOP input = receipt field |
| **Proof theater** | Attach invalid π; hope verifier skipped | Fail closed: invalid/missing PIOP → current honest level only |
| **TCB smuggling** | Put PIOP verify inside `mneme-verify` | Architecture rejection (spike §4); separate crate |

### 4.2 Malicious verifier / operator (honesty boundary)

A verifier that **ignores** a present PIOP and still upgrades `retrieval_proof_level` would be a
policy bug, not a crypto break. Mitigation: certificate field `retrieval_proof_level` may only
advance when an **out-of-TCB** PIOP verifier returns `Ok(())`; the 500-line TCB unchanged.

### 4.3 Trusted assumptions (if PIOP ships later)

- Hash / Merkle soundness (BLAKE3 path or bridged commitment).
- Polynomial commitment scheme soundness + Fiat–Shamir (ROM).
- Any structured reference string (if stack is non-transparent) — must be documented per stack
  row in `PHASE_IV_A_PIOP_TOOLCHAIN_MATRIX.md`.
- **Not** trusted: semantic truth, approximate-ANN faithfulness, Plonky2 nightly toolchain.

### 4.4 Fail-closed degradation rule (certificate integration)

Template from `pedersen_schnorr_zk`:

| Condition | Behavior |
|---|---|
| PIOP attachment absent | Honest level = Phase I (dominance over committed/visited set) |
| PIOP present, verifier crate disabled | `UnsupportedVersion` or `ZkProofInvalid` — **reject** |
| PIOP present, verify fails | **Reject** — never enter context |
| PIOP present, verify ok | May set `retrieval_proof_level = GlobalExactNn` (name TBD) — still not semantic truth |

The PIOP verifier **never** opens the recall gate alone; the TCB path remains mandatory.

---

## 5. Soundness sketch (informal)

If the succinct argument is sound and the in-circuit `D` and membership checks are correct,
then any accepting proof implies the dominance predicate in §2 over all committed leaves. A
break reduces to breaking the argument system, the commitment binding, or mis-implementing `D`.

**Known composition gap:** BLAKE3 `semantic_commit` vs field-native commitments requires an
explicit binding proof (spike §3.1 Option (a) or (b)) — until bridged, a PIOP over a sidecar
commitment does not automatically bind the signed root the store uses.

---

## 6. Gate question (Step 1 exit)

Does this statement retire roadmap caveat #2 (global exact-NN) **without** smuggling trust into
the 500-line TCB or implying semantic truth?

**Answer for MNEME today:** Yes *as a specification*; **no** as shipped software. Steps 2–5 in
the spike remain blockers. This doc is the Step 1 deliverable only.

---

## 7. References

- `docs/research/PHASE_IV_A_PIOP_SPIKE.md` — parent memo
- `docs/research/PHASE_IV_A_PIOP_TOOLCHAIN_MATRIX.md` — Step 2 stack survey
- `docs/redteam/PHASE_I_ZKANN_SOUNDNESS.md` — Phase I baseline attacks
