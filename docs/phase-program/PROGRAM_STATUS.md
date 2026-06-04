# MNEME Phase Program — Status (master)

**Date:** 2026-06-04 • **Branch:** `master` • **Honesty:** no PIOP/FRI prover; no TEE/enclave; fail-closed defaults unchanged.

---

## On master (software slices)

- **Phase I:** zkANN-1 + bi-temporal + provenance + Certificate v1 + proof obligations **done** (P1-1..P1-5). Red-team **#3** / **#5** at `d433999`; TCB fail-open (provenance skip) fixed at `a494fe0`.
- **Phase II:** Context Gate **software slice done** (P2-3..P2-8). Output binding, enclave-report placeholder (verify always fail-closed), Certificate v2 draft behind `context_gate` (off by default). **P2-1 TEE** and **P2-2 enclave verify** documented deferred — see `docs/redteam/PHASE_II_TEE_DEFERRED.md`. Integration tests in `crates/mneme-context/tests/phase_ii_integration.rs`. **Honest completion: 75%** (6/8 items; hardware deferred).
- **Phase III:** Accountability scaffolding **partial** — ActionReceipt Ed25519 verify behind `phase_iii_verify` (default off); ForgetProof shred/absence stubbed. Formal verifier proof and trust-ops **deferred** (P3-3, P3-4). **Honest completion: ~24%** (2/4 items partial; 0/4 done; 2/4 deferred).
- **Phase IV:** **Partial research slice** — `piop_research` flag off-by-default; federation cert wire sketch (decode-only, gate closed). No global exact-NN prover, no federation verifier, no interop SDKs shipped.

Approx. program progress by item count: **~65% done (13/20)**, **~10% partial (2/20)**, **~25% deferred (5/20)** — honest, excluding hardware/TEE/PIOP delivery.

---

## Blocked / deferred work

- **Hardware / TEE**: Enclave, remote attestation, and hardware cost envelopes remain unimplemented (Phase II P2-1, P2-2).
- **Formal proof & trust ops**: Phase III machine-checked verifier proof + trust-ops pilot deferred.
- **Phase IV PIOP**: Global exact-NN remains a research target only.
- **Federation & interop**: Cross-org certificate verification and verifier SDKs are not started (wire sketch only).

---

## Evidence

- `docs/phase-program/manifest.yaml`
- `docs/PHASE_II_TASK_SPEC.md`
- `docs/PHASE_III_TASK_SPEC.md`
- `docs/PHASE_IV_TASK_SPEC.md`
- `docs/research/PHASE_IV_A_PIOP_SPIKE.md`
- `docs/phase-program/INTEROP_SDK_STUB.md`
- `docs/redteam/PHASE_II_TEE_DEFERRED.md`
- `docs/redteam/PHASE_I_PROVENANCE_SCOPED.md`
- `docs/redteam/PHASE_I_HNSW_AUDIT_OVERCLAIM.md`
- `docs/redteam/PHASE_I_TCB_FAILOPEN_PROVENANCE.md`
