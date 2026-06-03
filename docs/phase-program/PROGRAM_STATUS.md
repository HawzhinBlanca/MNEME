# MNEME Phase Program — Status (master)

**Date:** 2026-06-03 • **Branch:** `master` • **Honesty:** no PIOP/FRI prover; fail-closed defaults unchanged.

---

## On master (software slices)
- Phase I: zkANN-1 + bi-temporal + provenance + Certificate v1 **landed** (P1-1..P1-4 done); docs/tamper/fuzz lane **partial** (P1-5).
- Phase II: Context Gate software scaffolding **landed** (P2-3..P2-6 done); enclave/RA remains out-of-scope for this slice.
- Phase III: Accountability scaffolding **partial** (P3-1, P3-2); formal verifier proof and trust-ops **deferred** (P3-3, P3-4).
- Phase IV: **Research-only**; `piop_research` flag off-by-default, panicking entry; no global exact-NN prover or federation/interop work on master.

Approx. software progress by item count: **~47% done (8/17)**, **~18% partial (3/17)**, **~35% deferred (6/17)** — honest, excluding any hardware/TEE/PIOP delivery.

---

## Blocked / deferred work
- **Hardware / TEE**: Enclave, remote attestation, and hardware cost envelopes remain unimplemented (Phase II hardware gate).
- **Formal proof & trust ops**: Phase III machine-checked verifier proof + trust-ops pilot deferred.
- **Phase IV PIOP**: Global exact-NN remains a research target only; stable-toolchain PIOP stack, commitment bridge, and out-of-TCB verifier prototype are outstanding.
- **Federation & interop**: Cross-org certificates and verifier SDKs are not started.

---

## Evidence
- `docs/phase-program/manifest.yaml`
- `docs/PHASE_I_TASK_SPEC.md`
- `docs/PHASE_II_TASK_SPEC.md`
- `docs/PHASE_III_TASK_SPEC.md`
- `docs/PHASE_IV_TASK_SPEC.md`
- `docs/research/PHASE_IV_A_PIOP_SPIKE.md`
