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
| Deterministic context assembly (`mneme-context`) with golden digests | Live TEE / enclave binding |
| Context-consumption attestation wire + verifier stub (`mneme-core` / `mneme-gate`) | Model attestation or remote measurement |
| Wire stability + fail-closed tests; `context_gate` feature **off by default** | Opening the gate; any claim that the model actually executed |

---

## 1. Exit criteria (green = Phase II software slice)

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

