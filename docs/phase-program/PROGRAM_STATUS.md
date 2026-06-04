# MNEME Phase Program — Status (master)

**Date:** 2026-06-04 • **Branch:** `master` @ `c8368d8` • **Honesty:** no PIOP/FRI prover; no TEE/enclave; fail-closed defaults unchanged.

**Integrator (2026-06-04):** Merged `origin/cursor/phase-iv-max` only. Phase II/III not ready on `origin` (see waiting SHAs below). `PHASE_GATE_LEVEL=full` green post-merge; `mneme-verify` TCB 494/500 lines.

---

## On master (software slices)

- Phase I: zkANN-1 + bi-temporal + provenance + Certificate v1 + proof obligations **done** (P1-1..P1-5). Red-team **#3** / **#5** at `d433999`; TCB fail-open (provenance skip) fixed at `a494fe0`.
- Phase II: Context Gate **software slice done** on master through `8abb72d` (P2-3..P2-8). Output binding, enclave-report placeholder (verify always fail-closed), Certificate v2 draft behind `context_gate` (off by default). **P2-1 TEE** and **P2-2 enclave verify** deferred — `docs/redteam/PHASE_II_TEE_DEFERRED.md`.
- Phase III: Accountability scaffolding **partial** (P3-1, P3-2); formal verifier proof and trust-ops **deferred** (P3-3, P3-4).
- Phase IV: **Research-only slice** at `c8368d8` — federation cert wire sketch (decode-only, gate closed), `piop_research` off-by-default; `docs/phase-program/INTEROP_SDK_STUB.md`. No global exact-NN prover, no cross-org verifier, no shipped interop SDK.

Approx. software progress by item count: **~65% done (13/20)**, **~10% partial (2/20)**, **~25% deferred (5/20)** — honest, excluding hardware/TEE/PIOP delivery.

**Phase II honest completion:** 6/8 items done (75%) — software slice complete; P2-1/P2-2 hardware deferred.

---

## Waiting branches (not merged)

| Branch | `origin` ref | Tip SHA | Ready? | Reason |
|---|---|---|---|---|
| `cursor/phase-ii-max` | **missing** | `8abb72d` (local only) | No | No remote branch; zero commits ahead of pre-IV `master` base |
| `cursor/phase-iii-max` | **missing** | `8abb72d` (local only) | No | No remote branch; zero commits ahead of pre-IV `master` base |
| `cursor/phase-iv-max` | present | `c8368d8` | Yes (merged) | Landed on `master` via fast-forward |

Push Phase II/III work to `origin` before the next integrator pass.

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
