# Finding — ForgetProof witness + absence surface (P3-2)

**Severity: VERIFIABLE FORGETTING (feature-gated).** Date 2026-06-04.

## What

Phase III P3-2 wires crypto-shred witness commits and SMT non-membership
verification for `ForgetProof` behind Cargo features (default **off**):

| Feature | Behavior |
|---|---|
| *(default)* | `prove_forget` → `UnsupportedVersion`; wire verify → `UnsupportedVersion` |
| `phase_iii_prove_forget` | `prove_forget` / `mint_forget_proof` with `ForgetProofWitness` (shred outcome + absence proof) |
| `phase_iii_verify` | Offline verify: `verify_forget_proof`, `verify_forget_proof_bound`, `verify_forget_proof_wire` |

Shred witness: `mneme_forget::shred_witness_commit` (BLAKE3 over key hash, object id,
optional destroyed `KeyId`). Absence: `mneme_forget::verify_absence` on the wire
`absence_path` reconstructed as a tombstone non-membership proof against
`Root::key_index_root`, with `root_bound` tied to `Root::preimage_hash`.

## Attack surface

| Forgery | Vector | Expected rejection |
|---|---|---|
| Tampered shred commit | Flip `shred_commit` after mint | `ProvenanceBroken` (bound) / structural |
| Tampered absence path | Flip auth-path node | `IndexPathInvalid` |
| Wrong root binding | `root_bound` ≠ supplied root preimage | `ReceiptRootMismatch` |
| Resurrected key | Re-insert live mapping; old absence proof | `IndexPathInvalid` |
| Zero shred commit | Clear witness commit | `ProvenanceBroken` |
| Redact mode splice | Set `mode = Redact` on shred proof | `UnsupportedVersion` |
| Gate-off bypass | Well-formed wire when features disabled | `UnsupportedVersion` |

## Honesty boundary

A valid `ForgetProof` proves **crypto-shred witness + proof-of-absence under a
signed root** (deleted, not served from the trusted index afterward). It does
**not** prove that no out-of-band copy ever existed elsewhere (CLAUDE.md §honesty).

## Required tests (landed)

- `crates/mneme-account/src/verify.rs` — `redteam_forget::*` (`phase_iii_verify`)
- `crates/mneme-account/tests/prove_forget.rs` — end-to-end mint/wire/verify
- `crates/mneme-account/tests/fail_closed.rs` — gate-off pins (default build)
- `crates/mneme-forget` — existing `forget_invariants` + `shred_witness_commit`

Run:

```bash
cargo test -p mneme-account --features phase_iii_verify redteam_forget -- --nocapture
cargo test -p mneme-account --features phase_iii_verify --test prove_forget -- --nocapture
cargo test -p mneme-account --test fail_closed prove_forget -- --nocapture
cargo test -p mneme-forget -- --nocapture
```

## Status

**Mitigated (P3-2 software slice):** witness + absence forgeries fail closed when
`phase_iii_verify` is enabled; default build remains `UnsupportedVersion`.

**Store path (2026-06-04):** shred `forget_with_proof` mints and verifies `ForgetProof` when
`mneme-store/phase_iii_prove_forget` (+ `phase_iii_verify`) are enabled (default **off**).
`root_bound` is the post-commit root; monotonic `sequence` rejects stale bindings (A-REPLAY).
