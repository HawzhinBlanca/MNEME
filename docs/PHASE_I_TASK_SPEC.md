# MNEME ∞ — Phase I Task Specification

**Verifiable Retrieval + Cognition Certificate v1** — the first credible step from
*"novel verifiable memory"* toward *Proof-Carrying Cognition* (see
[`VISION_PROOF_CARRYING_COGNITION.md`](VISION_PROOF_CARRYING_COGNITION.md)).

**Status:** Active build spec (draft). **Baseline:** v0 kernel + MNEME 2.0 on `master`, CI green.
**Language:** Rust 1.86.0 (stable). **Prime directive unchanged:** fail-closed verified recall only;
TCB ≤ 500 lines; authenticated ≠ true; procedure-faithful ≠ exact-NN (Phase I narrows this — see §5).

---

## 0. What Phase I is (and is not)

Phase I delivers, **on a single host, default-build-safe (heavy crypto feature-gated)**, the
three proofs that can be built today on the existing kernel — plus the artifact that fuses them.
It deliberately stops *before* the TEE Context Gate (Phase II).

| In scope (Phase I) | Out of scope (later phases) |
|---|---|
| **zkANN-1**: proven-correct retrieval (exact dominance now; HNSW audit-on-demand) | TEE Context Gate / attested inference (Phase II) |
| **Bi-temporal ledger**: `recall_verified_at` against historical signed roots | ZK-proving the model (never — seal the boundary instead) |
| **Poison-evidence**: provenance-scoped recall whose receipt proves the filter held | Capability→action non-repudiation (Phase III) |
| **Certificate v1** + offline verifier SDK (memory + retrieval + time) | Machine-checked TCB proof (Phase III) |
| Feature-gated heavy crypto; default build unchanged | New ANN engine; blockchain; truth claims |

---

## 1. Exit criteria (Phase I = done when all green)

### P1-1 — zkANN-1: proven-correct retrieval (P0)
- [ ] **Exact path (flat/brute-force index):** a recall returns `(entries, proof)` where the proof
  establishes **dominance** — every returned top-k distance is ≤ every non-returned candidate's
  distance over the *committed* vector set, bound to the signed `semantic_commit`. Verifier
  rejects any reordered/truncated/padded result with a typed `MnemeError`.
- [ ] **HNSW path (approximate):** **audit-on-demand** (V3DB-style) — on challenge, replay the
  declared graph walk against the committed snapshot and prove the returned set equals the walk's
  output. Honestly labeled: this proves *procedure-faithful + reproducible*, upgraded to
  *dominance over the visited neighborhood*, **not** global exact-NN (that needs the Phase-N PIOP).
- [ ] Default build remains non-ZK; honesty strings preserved in errors + exports (`ZK_BACKEND`).
- [ ] Forgery tests: reordered / dropped-better-neighbor / wrong-commit → typed rejection.

### P1-2 — Bi-temporal verifiable recall (P0)
- [ ] `Draft` gains an optional **valid-time** (when the fact is true in the world), distinct from
  transaction-time (HLC ingest). Both recorded; neither enters a *current* recall by default.
- [ ] `Store::recall_verified_at(query, proc, cap, AsOf::{RootSeq(n) | ValidTime(t)})` returns a
  receipt bound to the **historical signed root** at that point (membership *or* non-membership).
- [ ] A-REPLAY safe: historical recall cannot be served from a root not in the verified checkpoint chain.
- [ ] Test: "what did trusted memory hold at seq N / valid-time T" reconstructs deterministically;
  a backdated/forged history fails closed.

### P1-3 — Poison-evidence (provenance-scoped recall) (P1)
- [ ] A recall procedure may declare a **provenance filter** (`written_by: cap_subject`, `since: t`,
  `min_tier`). The recall receipt **proves the filter was honored** — i.e. proves every returned
  entry's write-provenance satisfies it, and (fail-closed) that no excluded entry leaked in.
- [ ] Quarantine-by-default already holds; add an **auditable promotion event** record.
- [ ] Test (anti-[MINJA](https://arxiv.org/html/2604.16548v1)): inject a memory via a low/untrusted
  cap → a trusted, provenance-scoped recall provably excludes it; the receipt shows the exclusion.

### P1-4 — Cognition Certificate v1 + offline verifier SDK (P0)
- [ ] A `CognitionCertificate` schema (dCBOR, versioned) binds: signed root + recall receipt(s) +
  zkANN-1 proof + bi-temporal anchor + provenance-filter attestation.
- [ ] `mneme certify` (CLI) emits a certificate for a recall; `mneme verify-cert FILE` checks it
  **offline** with no store access beyond the public root — fail-closed, typed errors.
- [ ] The verifier path stays inside / adjacent to the TCB budget; no new trust assumptions.
- [ ] Cross-impl: the `mneme-crossref` reference verifier can check a Certificate v1 (independent reimpl).

### P1-5 — Proof obligations & docs (P1)
- [ ] `validation-lane.sh full` green; new generative tamper cases for each proof; fuzz target for the certificate wire.
- [ ] Determinism foundation-gate unaffected (proofs are off the signed-root preimage path) — byte-identical ×2.
- [ ] README + `REMAINING_ITEMS.md` updated; honesty boundary section for zkANN-1 (dominance vs global-NN).

---

## 2. Prioritized task DAG

```
Wave I-A (parallel):  zkANN-1 exact-dominance (Crypto/ZK)  ┐
                      bi-temporal ledger (Core Kernel)     ├─▶ Certificate v1 assembler (Verifier TCB)
                      provenance-filter recall (Core Kernel)┘            │
Wave I-B:             zkANN-1 HNSW audit-on-demand ────────────────────▶ offline verifier SDK + crossref
Wave I-C:             tamper + fuzz + determinism + docs ─────────────▶ validation-lane full → tag Phase I
```

Dependencies: Certificate v1 (P1-4) consumes the outputs of P1-1/2/3; verifier SDK depends on the
schema; the HNSW audit-on-demand path (P1-1b) can land after the exact path proves the shape.

---

## 3. Module ownership

| Module | Phase I responsibility |
|---|---|
| `mneme-index` | zkANN-1 prover (dominance + audit-on-demand) on the existing HNSW/flat path; `pedersen_schnorr_zk`-gated (renamed from `plonky2_prover` for honesty) |
| `mneme-verify` | zkANN-1 + certificate verification gates (budgeted; justify every line) |
| `mneme-core` | `Draft` valid-time field; `CognitionCertificate` + `AsOf` interface types (freeze-reviewed) |
| `mneme-store` | `recall_verified_at`; provenance-filter recall; auditable promotion event |
| `mneme-cli` | `certify` / `verify-cert` subcommands; operator UX |
| `mneme-crossref` | independent Certificate v1 verifier (no `mneme-*` deps) |

---

## 4. Proof obligations (before tagging Phase I)

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings        # incl. --features plonky2_prover
scripts/ci/verify-tcb-guard.sh                                # mneme-verify ≤ 500 lines
cargo test -p mneme-index --features plonky2_prover -- zkann --nocapture
cargo test -p mneme-store recall_verified_at -- --nocapture
cargo test -p mneme-store provenance_scoped -- --nocapture
cargo test -p mneme-cli certify -- --nocapture
cargo test -p mneme-cli verify_cert -- --nocapture
scripts/ci/validation-lane.sh full                            # tamper ≥150, determinism ×2, fuzz, vectors
scripts/ci/cross-implementation-vectors.sh                    # crossref verifies Certificate v1
```

---

## 5. Honesty boundary (Phase I refinement — non-negotiable)

1. **Authenticated ≠ true.** Unchanged.
2. **zkANN-1 narrows, does not eliminate, the NN caveat.** The exact path proves **dominance over
   the committed set** (true top-k for a flat index). The HNSW path proves **procedure-faithful +
   reproducible + dominance over the visited neighborhood** — *not* global exact nearest neighbors.
   Global succinct exact-NN over HNSW awaits the [zkRAG-style PIOP](https://eprint.iacr.org/2026/709)
   (later phase). Label the level achieved in the certificate (`retrieval_proof_level`).
3. **Bi-temporal recall proves what was *authenticated* when — not what was *true* when.**
4. Pedersen/Schnorr ZK is **not** Plonky2/FRI; `ZK_BACKEND` exports the honest backend name.

---

## 6. Implementation log

| Date | Item | Status |
|---|---|---|
| 2026-06-03 | Phase I spec authored (from `VISION_PROOF_CARRYING_COGNITION.md`) | Done |
| 2026-06-03 | Phase I public seams scaffolded: `AsOf`, `Store::recall_verified_at`, `Store::provenance_scoped_recall`, and `mneme certify`; all fail closed with tests. | **Landed (gated scaffold only)** |

---

*Build the three provable claims first (retrieval, time, provenance), fuse them into Certificate v1,
ship an offline verifier — then Phase II seals the boundary around the model. One integration owner
runs `validation-lane.sh full` and an adversarial forgery red-team before tagging Phase I.*
