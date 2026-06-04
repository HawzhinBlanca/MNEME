# Finding — output binding forgery surface (P2-7)

**Severity: INTEGRITY (gate-closed digest hook).** Date 2026-06-04.

## What

Phase II P2-7 ships `OutputBinding` wire encode/decode (`mneme-core/output.rs`) and
`verify_output_binding` in `mneme-gate`. The hook binds three digests:

- `context_hash` = `hash_context_assembled(assembled_context)`
- `output_hash` = `hash_model_output(model_output)`
- `model_identity` = opaque 32-byte model label

No TEE or remote attestation is present; verification is digest equality only.

## Attack surface

| Forgery | Vector | Expected rejection |
|---|---|---|
| Output hash swap | Bind hash of output B while presenting output A | `MnemeError::ProvenanceBroken` |
| Context hash swap | Bind hash of context B while presenting context A | `MnemeError::ProvenanceBroken` |
| Model mismatch | Binding claims model M₂ while caller expects M₁ | `MnemeError::SchemaDrift` |
| Spliced fields | Honest context + forged output (or vice versa) | `MnemeError::ProvenanceBroken` |
| Wire tamper | Truncated CBOR, wrong fixed32 length, bad version | `SchemaDrift` / `UnsupportedVersion` |

## Why it matters

An agent runtime that trusts a binding without verification could accept a model output
that was not produced from the certified context. The digest hook is the software-only
anchor until P2-1/P2-2 enclave work lands.

## Required tests (landed)

- `crates/mneme-core/src/output.rs` — wire forgery: truncated wire, wrong field length, version drift
- `crates/mneme-gate/src/lib.rs` — `forgery_*` tests: hash swap, model mismatch, spliced binding

Run:

```bash
cargo test -p mneme-core output_binding -- --nocapture
cargo test -p mneme-gate forgery -- --nocapture
```

## Honesty boundary

Matching digests prove **hash equality**, not that a model executed, nor that outputs are
true or safe. See `docs/redteam/PHASE_II_TEE_DEFERRED.md` for enclave deferral.

## Strict context re-derivation (2026-06-04)

`verify_output_binding` trusts prover-supplied assembled context bytes (same injection class as the
bytes-only CCA gate). `verify_output_binding_strict(binding, result_ids, entries, model_output,
model_identity, profile)` re-derives `context_hash` via `assemble_verified_context` before checking
output and model digests. See `docs/redteam/PHASE_II_CONTEXT_GATE_NO_INJECTION.md`.

## Status

**Mitigated (software slice):** digest forgeries fail closed; strict gate closes injected-context
forgery on the binding's `context_hash` when entries are the verified recall set.
