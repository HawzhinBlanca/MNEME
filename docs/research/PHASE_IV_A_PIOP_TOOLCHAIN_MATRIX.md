# Phase IV-A — Succinct-Argument Toolchain Matrix (Step 2)

**Task:** `PHASE_IV_A_PIOP_SPIKE.md` §6 Step 2; `docs/PHASE_IV_TASK_SPEC.md` P4-1.

**Status:** Survey memo. **No crate added.** Cells marked *survey* were assessed for
**Rust 1.86.0 stable** compatibility via public crate docs and known MSRV pins — **not**
reproduced as a full workspace compile matrix in CI.

**Honesty header (binding):** This table records **engineering judgment for go/no-go**, not
benchmarks. No prover/verify times appear. Do not cite this doc as proof that any stack works
for MNEME's BLAKE3 `semantic_commit` without a commitment-bridge spike (Step 3).

---

## 1. Evaluation criteria

| Criterion | Requirement |
|---|---|
| **Toolchain** | Must build on **stable 1.86.0** (`rust-toolchain.toml`). **No nightly pin** to chase Plonky2 1.x. |
| **Transparency** | Prefer transparent setup (FRI / IPA / Spartan-style). SRS documented if unavoidable. |
| **TCB fit** | Verifier logic lives **out of** `mneme-verify` (≤500 lines, `forbid(unsafe_code)`). |
| **Dependency weight** | Heavy arkworks/plonky trees are a risk for supply-chain and audit surface. |
| **BLAKE3 bridge** | Stack must tolerate hash-heavy or sidecar field commitment (spike §3.1). |

---

## 2. Stack matrix (candidates — not endorsements)

| Stack / family | Stable 1.86? | Transparency | Recursion / PIOP | Dependency weight | MNEME notes |
|---|---|---|---|---|---|
| **arkworks (groth16 / marlin / etc.)** | *survey:* generally stable pins | Often **SRS** (non-transparent) | Mature R1CS; PIOP via custom gates | **Heavy** (multi-crate ecosystem) | Poor fit for "no trusted setup" honesty story unless carefully scoped |
| **halo2 / halo2-axiom** | *survey:* stable with pinned versions | **Transparent** (IPA) | PLONKish; good for custom gates | Medium–heavy | Strong candidate for out-of-TCB verifier crate; hash-in-circuit still costly |
| **Spartan / Nova / HyperNova family** | *survey:* varies by crate MSRV | **Transparent** | Succinct for certain statements | Medium | Good for "prove dominance + Merkle" statements; integration effort high |
| **plonky2 1.x** | **No** (nightly `specialization`) | Transparent (FRI) | Roadmap-named target | Heavy | **Deferred** — `B3_DEFERRAL_STATUS`; do not adopt nightly |
| **plonky3** | *survey:* early; check per-crate MSRV | Transparent (FRI) | Successor line to Plonky2 | Medium–heavy | Watch for stable pin; not selected in this slice |
| **gnark (Go)** | N/A (non-Rust) | Varies | Production provers exist | External toolchain | Violates single-Rust-pin discipline unless isolated as **external** prover only |
| **circom + snarkjs** | N/A | Groth16 SRS typical | Mature for hash-heavy | External | Same as gnark — interop only, not TCB |

---

## 3. Go / no-go inputs (Step 2 outcome)

| Question | Current answer |
|---|---|
| Any **stable** Rust stack with transparent setup + acceptable deps? | **Plausible** (halo2 / Spartan-family) — needs measured prototype (Step 4), not this memo |
| Can we use blueprint-default Plonky2 without nightly? | **No** — remains deferred |
| Can PIOP verifier fit `mneme-verify`? | **No** — architectural non-starter (spike §4) |
| Is BLAKE3-in-circuit the default path? | **No** — sidecar field commitment (Option b) lower interface risk |

**Recommended gate (unchanged from spike):** Proceed to Step 3 (commitment bridge) only if product
still wants global exact-NN after accepting out-of-TCB verifier + sidecar commit cost. If Step
4 prototype fails SLA, Phase IV-A stays research-only.

---

## 4. Next measurement (Step 4 — not done here)

The first **MNEME-measured** row must be added by `scripts/ci/phase-iv-cost-report.sh` (planning
harness) or a future prototype crate:

- Hardware label, `|V|`, embedding dimension, prover seconds, verifier seconds, `|π|` bytes.
- Label: **lab microbenchmark — not production SLA**.

---

## 5. References

- `docs/research/PHASE_IV_A_PIOP_SPIKE.md`
- `docs/research/PHASE_IV_A_PIOP_STATEMENT.md`
- `crates/mneme-index/src/pedersen_schnorr_zk.rs` — `B3_DEFERRAL_STATUS`
