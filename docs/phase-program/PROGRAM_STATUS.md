# MNEME Phase Program — Status (master)

**Date:** 2026-06-04 • **Branch:** `master` @ `a494fe0` • **Honesty:** no PIOP/FRI prover; no TEE/enclave; fail-closed defaults unchanged.

---

## On master (software slices)
- Phase I: zkANN-1 + bi-temporal + provenance + Certificate v1 + proof obligations **done** (P1-1..P1-5). `validation-lane full` and `phase-program-gate full` green; `cognition_cert_parse` fuzz in smoke/meaningful lanes. Red-team **#3** / **#5** at `d433999`; **TCB fail-open** (provenance skip) fixed at `a494fe0` — see `docs/redteam/PHASE_I_TCB_FAILOPEN_PROVENANCE.md`. Tag `phase-i-software` points at `58b13fa` (predates TCB fix). HNSW: prover-asserted set only (`PHASE_I_HNSW_AUDIT_OVERCLAIM.md`).
- Phase II: Context Gate software scaffolding **landed** (P2-3..P2-6). CCA wire fail-closed coverage at `9462a04`: adversarial decode/verify tests in `crates/mneme-core/src/context.rs` (malformed wire, wrong version, unknown fields, non-32-byte hashes) and `crates/mneme-gate/src/lib.rs` (garbage wire, tampered context hash). Software gate closed; **no enclave / remote-attestation claims**.
- Phase III: Accountability scaffolding **partial** (P3-1, P3-2); formal verifier proof and trust-ops **deferred** (P3-3, P3-4).
- Phase IV: **Research-only**; `piop_research` flag off-by-default, panicking entry; no global exact-NN prover or federation/interop work on master.

Approx. software progress by item count: **~59% done (10/17)**, **~12% partial (2/17)**, **~29% deferred (5/17)** — honest, excluding hardware/TEE/PIOP delivery.

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
- `docs/redteam/PHASE_I_PROVENANCE_SCOPED.md`
- `docs/redteam/PHASE_I_HNSW_AUDIT_OVERCLAIM.md`
- `docs/redteam/PHASE_I_TCB_FAILOPEN_PROVENANCE.md`
