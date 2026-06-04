# MNEME ∞ — Phase I Task Specification

**Verifiable Retrieval + Cognition Certificate v1** — the first credible step from
*"novel verifiable memory"* toward *Proof-Carrying Cognition* (see
[`VISION_PROOF_CARRYING_COGNITION.md`](VISION_PROOF_CARRYING_COGNITION.md)).

**Status:** Done (software-complete on `master`; release tag pending). **Baseline:** v0 kernel + MNEME 2.0 on `master`, CI green.
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
- [x] **Exact path (flat/brute-force index):** a recall returns `(entries, proof)` where the proof
  establishes **dominance** — every returned top-k distance is ≤ every non-returned candidate's
  distance over the *committed* vector set, bound to the signed `semantic_commit`. Verifier
  rejects any reordered/truncated/padded result with a typed `MnemeError`.
- [x] **HNSW path (approximate):** **prover-asserted authenticated set** — `visited_order` is
  checked for membership + top-k dominance over that set only; the verifier does **not** replay an
  HNSW graph walk (adjacency is not committed). Honest level: *dominance over prover-chosen
  authenticated members* (`RetrievalProofLevel::HnswAuditOnDemand`), **not** global exact-NN
  (Phase IV PIOP / graph commitment). Red-team #5 resolved (`docs/redteam/PHASE_I_HNSW_AUDIT_OVERCLAIM.md`).
- [x] Default build remains non-ZK; honesty strings preserved in errors + exports (`ZK_BACKEND`).
- [x] Forgery tests: reordered / dropped-better-neighbor / wrong-commit → typed rejection.

### P1-2 — Bi-temporal verifiable recall (P0)
- [x] `Draft` gains an optional **valid-time** (when the fact is true in the world), distinct from
  transaction-time (HLC ingest). Both recorded; neither enters a *current* recall by default.
- [x] `Store::recall_verified_at(query, proc, cap, AsOf::{RootSeq(n) | ValidTime(t)})` returns a
  receipt bound to the **historical signed root** at that point (membership *or* non-membership).
- [x] A-REPLAY safe: historical recall cannot be served from a root not in the verified checkpoint chain.
- [x] Test: "what did trusted memory hold at seq N / valid-time T" reconstructs deterministically;
  a backdated/forged history fails closed.

### P1-3 — Poison-evidence (provenance-scoped recall) (P1)
- [x] A recall procedure may declare a **provenance filter** (`written_by: cap_subject`, `since: t`,
  `min_tier`). The recall receipt **proves the filter was honored** — i.e. proves every returned
  entry's write-provenance satisfies it, and (fail-closed) that no excluded entry leaked in.
- [x] Quarantine-by-default already holds; add an **auditable promotion event** record.
- [x] Test (anti-[MINJA](https://arxiv.org/html/2604.16548v1)): inject a memory via a low/untrusted
  cap → a trusted, provenance-scoped recall provably excludes it; the receipt shows the exclusion.
  Red-team #3 resolved (`docs/redteam/PHASE_I_PROVENANCE_SCOPED.md`); TCB fail-open fixed (`docs/redteam/PHASE_I_TCB_FAILOPEN_PROVENANCE.md`).

### P1-4 — Cognition Certificate v1 + offline verifier SDK (P0)
- [x] A `CognitionCertificate` schema (dCBOR, versioned) binds: signed root + recall receipt(s) +
  zkANN-1 proof + bi-temporal anchor + provenance-filter attestation.
- [x] `mneme certify` (CLI) emits a certificate for a recall; `mneme verify-cert FILE` checks it
  **offline** with no store access beyond the public root — fail-closed, typed errors.
- [x] The verifier path stays inside / adjacent to the TCB budget; no new trust assumptions.
- [x] Cross-impl: the `mneme-crossref` reference verifier can check a Certificate v1 (independent reimpl).

### P1-5 — Proof obligations & docs (P1)
- [x] `validation-lane.sh full` green; new generative tamper cases for each proof; fuzz target for the certificate wire (`cognition_cert_parse`).
- [x] Determinism foundation-gate unaffected (proofs are off the signed-root preimage path) — byte-identical ×2.
- [x] README + `REMAINING_ITEMS.md` updated; honesty boundary section for zkANN-1 (dominance vs global-NN).

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
cargo clippy --workspace --all-targets -- -D warnings        # incl. --features pedersen_schnorr_zk
scripts/ci/verify-tcb-guard.sh                                # mneme-verify ≤ 500 lines
cargo test -p mneme-index --features pedersen_schnorr_zk -- zkann --nocapture
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
   the committed set** (true top-k for a flat index). The HNSW path proves **dominance over a
   prover-asserted set of authenticated members** (`visited_order`) — *not* graph-walk replay and
   *not* global exact nearest neighbors.
   Global succinct exact-NN over HNSW awaits the [zkRAG-style PIOP](https://eprint.iacr.org/2026/709)
   (later phase). Label the level achieved in the certificate (`retrieval_proof_level`).
3. **Bi-temporal recall proves what was *authenticated* when — not what was *true* when.**
4. Pedersen/Schnorr ZK is **not** Plonky2/FRI; `ZK_BACKEND` exports the honest backend name.

---

## 6. Implementation log

| Date | Item | Status |
|---|---|---|
| 2026-06-03 | Phase I spec authored (from `VISION_PROOF_CARRYING_COGNITION.md`) | Done |
| 2026-06-03 | Phase I public seams scaffolded: `AsOf`, `Store::recall_verified_at`, `Store::provenance_scoped_recall`, `mneme certify`, and `mneme verify-cert`; all fail closed with tests. | **Landed (initial gated scaffold; superseded by full integration on `master`)** |
| 2026-06-03 | Phase I full integration (`7b19c13`): zkANN-1 dominance + HNSW prover-asserted-set path; bi-temporal `recall_verified_at`; provenance-scoped recall; Cognition Certificate v1 (`mneme certify` / `verify-cert`); `mneme-crossref` vectors exercised; CLI certify path wired. | **Landed** |
| 2026-06-04 | Red-team #3 (provenance-scoped) + #5 (HNSW honesty) closed @ `d433999`; TCB fail-open (provenance skip) @ `a494fe0`; `validation-lane full` + `cognition_cert_parse` fuzz green @ `9462a04`. | **Done (software-complete; `phase-i` @ `42079de`; `phase-i-software` @ `be2b536` predates `a494fe0`)** |

---

*Build the three provable claims first (retrieval, time, provenance), fuse them into Certificate v1,
ship an offline verifier — then Phase II seals the boundary around the model. One integration owner
runs `validation-lane.sh full` and an adversarial forgery red-team before tagging Phase I.*
