## MNEME ∞ — Phase II Task Specification (software-only)

**Context Gate (software-only increment)** — deterministic prompt assembly and context
consumption attestation scaffolding with the gate **closed** (no enclave, no remote
attestation claims). Baseline: Phase I on `master`, red-team/tag pending (P1-5).

**Status:** Draft spec for Phase II software slice. **Language:** Rust 1.86.0.
**Honesty:** *Authenticated ≠ true; no enclave present; the gate stays closed;*
attestations remain stubbed and fail-closed.

---

## 0. Scope (what Phase II is / is not)

| In scope (Phase II software) | Out of scope (later) |
|---|---|
| Deterministic context assembly (`mneme-context`) with golden digests | Live TEE / enclave binding (P2-1) |
| Context-consumption attestation wire + verifier stub (`mneme-core` / `mneme-gate`) | In-enclave recall + remote attestation (P2-2) |
| Output-binding types + domain-separated output hash (P2-7) | Model attestation or remote measurement |
| Enclave-report placeholder wire (fail-closed verify) (P2-8) | Opening the gate; any claim that the model actually executed |
| Certificate v2 **draft** wire behind `context_gate` (opt-in) | Production cognition certificate v2 |
| Wire stability + fail-closed tests; `context_gate` feature **off by default** | Hardware cost envelopes |

---

## 1. Exit criteria (green = Phase II software slice)

### P2-1 — TEE / GPU confidential compute (deferred)
- [ ] Real enclave integration (NVIDIA CC or equivalent).
- [x] Document-only deferral (`docs/redteam/PHASE_II_TEE_DEFERRED.md`).

### P2-2 — Enclave verify + remote attestation (deferred)
- [ ] In-enclave recall + zkANN-1 re-check before assembly.
- [x] Document-only deferral; no fake RA strings on wire.

### P2-3 — Deterministic assembly (mneme-context)
- [x] Golden test for `MNEME-CTX-ASM-v1`: assembled prompt bytes + certified memory-set
  hash are frozen and repeatable across runs.
- [x] Wire stability: prompt layout `magic ‖ (object_id ‖ payload)*` enforced; order
  mismatch rejects; profile id pinned.

### P2-4 — Context-consumption attestation (CCA) wire
- [x] Canonical CCA wire (versioned, dCBOR) carries `assembly_profile`, `context_hash`,
  `certified_memory_set_hash`; domain-separated hashes only.
- [x] Decode rejects schema drift / wrong version; no enclave claim strings.

### P2-5 — Attestation verifier stub (mneme-gate)
- [x] Verifier stays **fail-closed**: mismatched profile or hash → typed error; domain
  separation enforced; observability string declares gate closed.

### P2-6 — Feature flag + wire stability
- [x] `context_gate` feature **off by default** (opt-in only).
- [x] Wires documented and tests prove byte-stable behavior.

### P2-7 — Output binding (software hook)
- [x] `OutputBinding` type + `hash_model_output` domain tag.
- [x] Wire encode/decode + `verify_output_binding` in `mneme-gate`.
- [x] Integration test: assembly → output binding → verify.

### P2-8 — Certificate v2 draft + enclave placeholder
- [x] Cognition Certificate v2 draft wire behind `context_gate` (opt-in).
- [x] `EnclaveReportPlaceholder` wire; verify **always fail-closed**.
- [x] Context attestation draft status `unverified_until_phase_ii_gate`.

---

## 2. Honesty boundary (Phase II refinement)

1. **Gate closed:** `context_gate` is experimental and disabled by default; attestation
   verifier is a stub that only checks digests, never opens a TEE gate.
2. **Authenticated ≠ true:** A matching attestation only proves hash equality over the
   assembled prompt and certified set — not that a model ran, nor that outputs are
   correct or safe.
3. **No enclave claims:** There is no remote attestation or hardware-bound guarantee in
   this phase. Any such claim must be explicitly absent.

---

## 3. Implementation log

| Date | Item | Status |
|---|---|---|
| 2026-06-03 | Spec authored (software-only slice; gate closed; no TEE claims). | Draft |
| 2026-06-03 | Phase II software slice landed: deterministic assembly goldens, CCA wire encode/decode, verifier stub tests, `context_gate` default-off. | **Done (software-only; gate closed)** |
| 2026-06-04 | Phase II max honest increment: output binding, enclave placeholder (fail-closed), cert v2 draft seam, integration tests; P2-1/P2-2 documented deferred. | **Done (software-only; gate closed)** |

