# MNEME Phase Program — Status (master)

**Date:** 2026-06-04 • **Branch:** `master` • **Honesty:** no PIOP/FRI prover; no TEE/enclave; fail-closed defaults unchanged.

**Integrator (2026-06-04):** Phase I **closed in docs** — P1-1..P1-5 match `docs/phase-program/manifest.yaml`; HNSW labeled *prover-asserted authenticated set* (not graph replay / not global exact-NN). Red-team #3/#5 @ `d433999`; TCB fail-open fixed @ `a494fe0`. **`git tag phase-i` pending** integrator gate (`PHASE_GATE_LEVEL=full` green). P3-1 store `*_with_action` policy (`phase_iii_require_action`, default off) + MCP optional bind; P3-2 store `forget_with_proof` emit+verify (`phase_iii_prove_forget`, default off). P3-3/P3-4 deferred. Prior slices: ii @ `14a87df`, iii @ `bfda439`, iv @ `c8368d8`.

---

## Phase completion (honest %)

| Phase | Done | Partial | Deferred | Honest % | Notes |
|---|---:|---:|---:|---:|---|
| **I** — Verifiable retrieval + Certificate v1 | 5/5 | 0 | 0 | **100%** | Software-complete; red-team #3/#5 closed; TCB fail-open fixed @ `a494fe0`. |
| **II** — Context Gate (software-only) | 6/8 | 0 | 2 | **75%** | P2-3..P2-8 done; P2-1 TEE + P2-2 enclave verify deferred (`PHASE_II_TEE_DEFERRED.md`). |
| **III** — Accountability scaffolding | 2/4 | 0 | 2 | **~50%** | P3-1/P3-2 store paths done (feature-gated, default off); P3-3 Lean proof + P3-4 trust-ops **deferred**. |
| **IV** — Scale & standard (research) | 0/4 | 3/4 | 1/4 | **~38%** | Federation wire sketch + interop stub doc; `piop_research` off-by-default; no prover/verifier/SDK shipped. |
| **Program total** | 13/21 | 3/21 | 5/21 | **~62% software ceiling** | 13 done items on master; excludes TEE/Lean/PIOP/hardware; partial IV counts half in phase % only. |

---

## On master (software slices)

- **Phase I:** zkANN-1 + bi-temporal + provenance + Certificate v1 + proof obligations **done** (P1-1..P1-5). Red-team **#3** / **#5** at `d433999`; TCB fail-open (provenance skip) fixed at `a494fe0`.
- **Phase II:** Context Gate **software slice done** (P2-3..P2-8 @ `14a87df`). Output binding forgery surface documented + tested (`docs/redteam/PHASE_II_OUTPUT_BINDING.md`). Enclave-report placeholder (verify always fail-closed), Certificate v2 draft behind `context_gate` (off by default).
- **Phase III:** Accountability scaffolding **partial** — P3-1 store/MCP `ActionReceipt` policy (`phase_iii_require_action` / `phase_iii_bind`; default off). P3-2 store shred `forget_with_proof` (`phase_iii_prove_forget`; default off). P3-3 machine-checked verifier proof + P3-4 trust-ops pilot **deferred**.
- **Phase IV:** **Research slice** @ `c8368d8` — federation cert wire forgery surface documented + tested (`docs/redteam/PHASE_IV_FEDERATION_WIRE.md`); decode-only, gate closed. `piop_research` off-by-default. No global exact-NN prover, no cross-org verifier, no shipped interop SDK.

Approx. program progress (software ceiling): **~62% done (13/21)**, **~14% partial (3/21)**, **~24% deferred (5/21)** — honest, excluding hardware/TEE/PIOP/Lean delivery.

---

## Merged branches

| Branch | Tip SHA | Merged |
|---|---|---|
| `cursor/docs-reconcile` | `bcb5684` | Yes |
| `cursor/p3-store-mandatory` | `f573726` | Yes |
| `cursor/phase-ii-max` | `14a87df` | Yes |
| `cursor/phase-iii-max` | `bfda439` | Yes |
| `cursor/phase-iv-max` | `c8368d8` | Yes |

---

## Blocked / deferred work

- **Hardware / TEE**: Enclave, remote attestation, and hardware cost envelopes remain unimplemented (Phase II P2-1, P2-2).
- **Formal proof & trust ops**: Phase III machine-checked verifier proof (Lean) + trust-ops pilot deferred (P3-3, P3-4).
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
