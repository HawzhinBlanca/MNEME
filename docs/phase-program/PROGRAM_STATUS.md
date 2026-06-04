# MNEME Phase Program — Status (master)

**Date:** 2026-06-04 • **Branch:** `master` • **Honesty:** no PIOP/FRI prover; no TEE/enclave; fail-closed defaults unchanged.

**Integrator (2026-06-04):** Phase I **closed in docs** — P1-1..P1-5 match `docs/phase-program/manifest.yaml`; HNSW labeled *prover-asserted authenticated set* (not graph replay / not global exact-NN). Red-team #3/#5 @ `d433999`; TCB fail-open fixed @ `a494fe0`. **`git tag phase-i` pending** integrator gate (`PHASE_GATE_LEVEL=full` green). Phase III in-flight on master pre-P3 merge. Prior slices: ii @ `14a87df`, iii @ `bfda439`, iv @ `c8368d8`.

---

## Phase completion (honest %)

| Phase | Done | Partial | Deferred | Honest % | Notes |
|---|---:|---:|---:|---:|---|
| **I** — Verifiable retrieval + Certificate v1 | 5/5 | 0 | 0 | **100%** | Software-complete; red-team #3/#5 closed; TCB fail-open fixed @ `a494fe0`. |
| **II** — Context Gate (software-only) | 6/8 | 0 | 2 | **75%** | P2-3..P2-8 done; P2-1 TEE + P2-2 enclave verify deferred (`PHASE_II_TEE_DEFERRED.md`). |
| **III** — Accountability scaffolding | 0/4 | 2/4 | 2/4 | **~78%** | In-flight slice (P3-1+P3-2): P3-1 partial (bind+verify gated); P3-2 partial/**wire+verify done** @ `a8c8cd6` (store forget receipts deferred); P3-3/P3-4 deferred. |
| **IV** — Scale & standard (research) | 0/4 | 3/4 | 1/4 | **~38%** | Federation wire sketch + interop stub doc; `piop_research` off-by-default; no prover/verifier/SDK shipped. |
| **Program total** | 11/21 | 5/21 | 5/21 | **~52% done** | Excludes hardware/TEE/PIOP delivery; Phase III ~78% is in-flight (P3-1+P3-2) only, not the 21-item roll-up. |

---

## On master (software slices)

- **Phase I:** zkANN-1 + bi-temporal + provenance + Certificate v1 + proof obligations **done** (P1-1..P1-5). Red-team **#3** / **#5** at `d433999`; TCB fail-open (provenance skip) fixed at `a494fe0`.
- **Phase II:** Context Gate **software slice done** (P2-3..P2-8 @ `14a87df`). Output binding forgery surface documented + tested (`docs/redteam/PHASE_II_OUTPUT_BINDING.md`). Enclave-report placeholder (verify always fail-closed), Certificate v2 draft behind `context_gate` (off by default).
- **Phase III:** Accountability scaffolding **~78% in-flight** — P3-1 partial (`ActionReceipt` bind+verify gated @ `946021e`). P3-2 partial/**software done** @ `a8c8cd6`: `ForgetProof` shred witness (`shred_witness_commit`) + SMT absence verify (`phase_iii_prove_forget` / `phase_iii_verify`; default off); red-team `PHASE_III_FORGET_PROOF.md`. Store mandatory forget proofs + per-forget A-REPLAY **deferred**. P3-3/P3-4 **deferred**.
- **Phase IV:** **Research slice** @ `c8368d8` — federation cert wire forgery surface documented + tested (`docs/redteam/PHASE_IV_FEDERATION_WIRE.md`); decode-only, gate closed. `piop_research` off-by-default. No global exact-NN prover, no cross-org verifier, no shipped interop SDK.

Approx. program progress by item count: **~52% done (11/21)**, **~24% partial (5/21)**, **~24% deferred (5/21)** — honest, excluding hardware/TEE/PIOP delivery. Phase III honest % (~78%) counts only in-flight items P3-1+P3-2, not deferred P3-3/P3-4.

---

## Merged branches

| Branch | Tip SHA | Merged |
|---|---|---|
| `cursor/phase-ii-max` | `14a87df` | Yes |
| `cursor/phase-iii-max` | `bfda439` | Yes |
| `cursor/phase-iv-max` | `c8368d8` | Yes |

---

## Blocked / deferred work

- **Hardware / TEE**: Enclave, remote attestation, and hardware cost envelopes remain unimplemented (Phase II P2-1, P2-2).
- **Formal proof & trust ops**: Phase III machine-checked verifier proof + trust-ops pilot deferred.
- **Phase IV PIOP**: Global exact-NN remains a research target only (`piop_research` panics if enabled).
- **Federation verify**: Cross-org certificate verification and interop SDK packages not started (wire sketch only).

---

## Evidence

- `docs/phase-program/manifest.yaml`
- `docs/PHASE_I_TASK_SPEC.md`
- `docs/PHASE_II_TASK_SPEC.md`
- `docs/PHASE_III_TASK_SPEC.md`
- `docs/PHASE_IV_TASK_SPEC.md`
- `docs/phase-program/INTEROP_SDK_STUB.md`
- `docs/research/PHASE_IV_A_PIOP_SPIKE.md`
- `crates/mneme-index/src/federation_cert.rs`
- `docs/redteam/PHASE_II_TEE_DEFERRED.md`
- `docs/redteam/PHASE_II_OUTPUT_BINDING.md`
- `docs/redteam/PHASE_III_ACTION_RECEIPT.md`
- `docs/redteam/PHASE_III_FORGET_PROOF.md`
- `docs/redteam/PHASE_IV_FEDERATION_WIRE.md`
- `docs/redteam/PHASE_I_PROVENANCE_SCOPED.md`
- `docs/redteam/PHASE_I_HNSW_AUDIT_OVERCLAIM.md`
- `docs/redteam/PHASE_I_TCB_FAILOPEN_PROVENANCE.md`
