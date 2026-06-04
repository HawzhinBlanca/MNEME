# MNEME Phase Program — Status (cursor/phase-ii-max)

**Date:** 2026-06-04 • **Branch:** `cursor/phase-ii-max` @ `8abb72d`+ • **Honesty:** no PIOP/FRI prover; no TEE/enclave; fail-closed defaults unchanged.

---

## On cursor/phase-ii-max (software slices)
- Phase I: zkANN-1 + bi-temporal + provenance + Certificate v1 + proof obligations **done** (P1-1..P1-5). Red-team **#3** / **#5** at `d433999`; TCB fail-open (provenance skip) fixed at `a494fe0`.
- Phase II: Context Gate **software slice done** (P2-3..P2-8). Output binding, enclave-report placeholder (verify always fail-closed), Certificate v2 draft behind `context_gate` (off by default). **P2-1 TEE** and **P2-2 enclave verify** documented deferred — see `docs/redteam/PHASE_II_TEE_DEFERRED.md`. Integration tests in `crates/mneme-context/tests/phase_ii_integration.rs`.
- Phase III: Accountability scaffolding **partial** (P3-1, P3-2); formal verifier proof and trust-ops **deferred** (P3-3, P3-4).
- Phase IV: **Research-only**; `piop_research` flag off-by-default; no global exact-NN prover or federation/interop work.

Approx. software progress by item count: **~65% done (13/20)**, **~10% partial (2/20)**, **~25% deferred (5/20)** — honest, excluding hardware/TEE/PIOP delivery.

**Phase II honest completion:** 6/8 items done (75%) — software slice complete; P2-1/P2-2 hardware deferred.

---

## Blocked / deferred work
- **Hardware / TEE**: Enclave, remote attestation, and hardware cost envelopes remain unimplemented (Phase II P2-1, P2-2).
- **Formal proof & trust ops**: Phase III machine-checked verifier proof + trust-ops pilot deferred.
- **Phase IV PIOP**: Global exact-NN remains a research target only.
- **Federation & interop**: Cross-org certificates and verifier SDKs are not started.

---

## Evidence
- `docs/phase-program/manifest.yaml`
- `docs/PHASE_I_TASK_SPEC.md`
- `docs/PHASE_II_TASK_SPEC.md`
- `docs/PHASE_III_TASK_SPEC.md`
- `docs/PHASE_IV_TASK_SPEC.md`
- `docs/research/PHASE_IV_A_PIOP_SPIKE.md`
- `docs/redteam/PHASE_II_TEE_DEFERRED.md`
- `docs/redteam/PHASE_I_PROVENANCE_SCOPED.md`
- `docs/redteam/PHASE_I_HNSW_AUDIT_OVERCLAIM.md`
- `docs/redteam/PHASE_I_TCB_FAILOPEN_PROVENANCE.md`
