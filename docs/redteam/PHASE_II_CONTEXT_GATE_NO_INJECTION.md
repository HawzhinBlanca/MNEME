# Finding (Phase II core invariant) — Context Gate "nothing injected"

**Severity: HIGH for the Phase II claim (scaffold — `PHASE_II_GATE_OPEN = false` — so not a live
production exploit).** Date 2026-06-04. **Status: FIXED (software) — see Resolution.**

## The claim (VISION / ROADMAP Phase II)

> The enclave emits a Context-Consumption Attestation binding `H(assembled_context)` to the
> certified memory set, so *a verifier, offline, can check the model was fed **precisely** the
> certified context (and nothing injected out-of-band)*.

## The gap (as originally implemented)

`mneme_gate::verify_consumption_attestation(att, assembled_context, certified_memory_set_payload, profile)`
checked three things independently:
1. profile match, 2. `att.context_hash == hash(assembled_context)`, 3. `att.certified_memory_set_hash == hash(certified_payload)`.

With `certified_memory_set_payload = count ‖ (id ‖ id)*` (ids only) and
`assembled_context = magic ‖ (id ‖ plaintext)*`, **nothing cross-binds the prompt's plaintext to the
certified ids.** So an `assembled_context` with **injected plaintext** + a legit certified payload
**passes**: digest (2) matches the injected bytes, digest (3) matches the legit payload. The offline
"nothing injected" guarantee was therefore not enforced, and only happy-path tests existed.

## Resolution (2026-06-04)

Added `mneme_gate::verify_consumption_attestation_strict(att, result_ids, entries, profile)` — the
**sound, offline no-injection check**. It **re-derives** the assembled prompt and certified-set
digest from the AUTHENTICATED verified-recall entries via `assemble_verified_context` (which
re-hashes every entry: `record.compute_id() == id`, enforces `result_ids` order, and rejects
length mismatch), then requires the CCA digests to match the *re-derived* values. The prover's
prompt bytes are never trusted — they are reconstructed from the certified set — so injection,
reorder, drop, or substitution all change the re-derived `context_hash` (or fail entry
authentication) and the gate fails closed.

The bytes-only `verify_consumption_attestation` is retained for the "caller already produced the
bytes from authenticated entries" case, with a doc-comment stating it does **not** prove
no-injection on its own and pointing callers to the strict gate.

**Tests** (`crates/mneme-context/tests/phase_ii_integration.rs`):
- `phase_ii_strict_gate_accepts_genuine_assembly` — happy path.
- `phase_ii_strict_gate_rejects_injected_context` — injected prompt → `ProvenanceBroken`.
- `phase_ii_strict_gate_rejects_reordered_results` — reordered → rejected.
- `phase_ii_strict_gate_rejects_dropped_entry` — dropped → rejected.
- `phase_ii_bytes_only_gate_misses_injection_strict_catches_it` — pins the contrast: bytes-only
  accepts the forge, strict rejects it.

## Still pending (honest)

- **Wire the strict gate into the live flows** (store/cert/mnemed) so they use
  `verify_consumption_attestation_strict` rather than the bytes-only form. (Phase II gate remains
  closed — `PHASE_II_GATE_OPEN = false` — so no production path depends on it yet.)
- **Real GPU-TEE remote attestation** (the enclave report) — separately external-gated (needs real
  H100/Blackwell + vendor RA service). The enclave-report verifier still fails closed by design.
