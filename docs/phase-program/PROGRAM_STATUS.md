# MNEME Phase Program — Status (master)

**Date:** 2026-06-04 • **Branch:** `master` @ `673b210` • **Honesty:** no PIOP/FRI prover; no TEE/enclave; fail-closed defaults unchanged.

**Integrator (2026-06-04):** Merged `origin/cursor/phase-ii-max` → `origin/cursor/phase-iii-max` → `origin/cursor/phase-iv-max` on master (ii @ `14a87df`, iii @ `bfda439`, iv @ `c8368d8`). `PHASE_GATE_LEVEL=full` green post-merge; `mneme-verify` TCB 494/500 lines.

---

## Phase completion (honest %)

| Phase | Done | Partial | Deferred | Honest % | Notes |
|---|---:|---:|---:|---:|---|
| **I** — Verifiable retrieval + Certificate v1 | 5/5 | 0 | 0 | **100%** | Software-complete; red-team #3/#5 closed; TCB fail-open fixed @ `a494fe0`. |
| **II** — Context Gate (software-only) | 6/8 | 0 | 2 | **75%** | P2-3..P2-8 done; P2-1 TEE + P2-2 enclave verify deferred (`PHASE_II_TEE_DEFERRED.md`). |
| **III** — Accountability scaffolding | 0/4 | 2/4 | 2/4 | **~25%** | ActionReceipt Ed25519 verify behind `phase_iii_verify` (default off); ForgetProof stubbed; P3-3/P3-4 deferred. |
| **IV** — Scale & standard (research) | 0/4 | 3/4 | 1/4 | **~38%** | Federation wire sketch + interop stub doc; `piop_research` off-by-default; no prover/verifier/SDK shipped. |
| **Program total** | 11/21 | 5/21 | 5/21 | **~52% done** | Excludes hardware/TEE/PIOP delivery; partial items count as half in phase % only. |

---

## On master (software slices)

- **Phase I:** zkANN-1 + bi-temporal + provenance + Certificate v1 + proof obligations **done** (P1-1..P1-5). Red-team **#3** / **#5** at `d433999`; TCB fail-open (provenance skip) fixed at `a494fe0`.
- **Phase II:** Context Gate **software slice done** (P2-3..P2-8 @ `14a87df`). Output binding, enclave-report placeholder (verify always fail-closed), Certificate v2 draft behind `context_gate` (off by default). Integration tests in `crates/mneme-context/tests/phase_ii_integration.rs`.
- **Phase III:** Accountability scaffolding **partial** @ `bfda439` — ActionReceipt Ed25519 verify behind `phase_iii_verify` (default off); ForgetProof shred/absence stubbed. Formal verifier proof and trust-ops **deferred** (P3-3, P3-4).
- **Phase IV:** **Research slice** @ `c8368d8` — federation cert wire sketch (decode-only, gate closed), `piop_research` off-by-default; `docs/phase-program/INTEROP_SDK_STUB.md`. No global exact-NN prover, no cross-org verifier, no shipped interop SDK.

Approx. program progress by item count: **~52% done (11/21)**, **~24% partial (5/21)**, **~24% deferred (5/21)** — honest, excluding hardware/TEE/PIOP delivery.

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
- `docs/redteam/PHASE_I_PROVENANCE_SCOPED.md`
- `docs/redteam/PHASE_I_HNSW_AUDIT_OVERCLAIM.md`
- `docs/redteam/PHASE_I_TCB_FAILOPEN_PROVENANCE.md`
