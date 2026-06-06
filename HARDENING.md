# MNEME — Hardening Log

Autonomous, hourly reliability/hardening pass. Each entry: what was audited or
improved, the evidence, and follow-ups. Human-needed items go to
[HUMAN_TASKS.md](HUMAN_TASKS.md).

## 2026-06-06 — Panic-surface audit + provenance fail-closed

**Audit (verified, no fix needed):** swept production (non-test) code in the TCB
and kernel crates for panic surfaces (`unwrap`/`expect`/`panic!`/`unreachable!`/
slice-index) on untrusted-input paths:

- `mneme-verify` (TCB): **0** — panic-free.
- `mneme-store`, `mneme-root`, `mneme-crypto`: **0**.
- Untrusted-input parsers all guard before indexing:
  - `dcbor.rs`: `read_bytes(n)` returns exactly `n` bytes or errors; map-key
    slice uses forward-only cursor positions (proven in-range); length reads are
    minimal-form checked.
  - `hex.rs::decode_hex32`: length `== 64` checked, `chunks_exact(2)`.
  - `smt/wire.rs::parse_proof_blob`: `is_empty()` checked before `bytes[0]`.
  - `cap/wire.rs`, `smt/wire.rs`: use bounded `read_exact::<N>` → fixed arrays.

  Conclusion: the verifier/parse attack surface is fail-closed on malformed
  input (consistent with the existing fuzz targets). No bug found.

**Fix (defense in depth):** `mneme-dag` topological sort
(`crates/mneme-dag/src/lib.rs`) used `.expect("id present")`,
`.expect("child tracked")`, and an unchecked `*deg -= 1`. Unreachable for
validated input (duplicate-id / dangling-parent / cycle are already rejected
with `ProvenanceBroken`), but a CORE provenance path must be *provably*
panic-free, and `-= 1` could underflow-panic in debug builds. Converted all
three to fail-closed `Result` (`ok_or(MnemeError::ProvenanceBroken)?`,
`checked_sub`). Evidence: `cargo clippy -p mneme-dag --lib --tests -D warnings`
clean; `cargo test -p mneme-dag` 15 passed.

**Follow-ups:** none blocking. `mneme-dag::sequence()` keeps an infallible
`u64::try_from(usize).expect(...)` (cannot fail on supported targets); left as-is
to avoid a needless signature change.
