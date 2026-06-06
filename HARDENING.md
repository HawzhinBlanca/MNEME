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

## 2026-06-06 — Real bug: panic-on-corruption in sidecar hex decode (fail-closed)

**Found + fixed (genuine latent panic bug).** `mneme-store/src/layout.rs::parse_hex32`
validated only the *byte* length (`s.len() == 64`) then sliced the `&str` by
byte range (`&s[i*2..i*2+2]`). A corrupted/tampered sidecar packing 64 bytes of
multibyte UTF-8 (e.g. `"€"` + 61 ASCII == 64 bytes, not 64 chars) makes that
slice land on a non-char boundary → **panic**, not a typed error. `parse_hex32`
decodes 10 untrusted on-disk sidecar fields (key-index, object-keys, tombstones,
embeddings), so a single bad byte on disk could crash store open/recall — a
fail-closed violation.

Reproduced the panic (`byte index 2 is not a char boundary`). Fixed by
delegating to the canonical byte-safe `mneme_core::decode_hex32` (already
hardened + tested for this exact multibyte case), which also removes the
duplicated decoder. Added 3 regression tests in `layout.rs` (multibyte→
`SchemaDrift` without panic, lowercase roundtrip, wrong-length reject).

Evidence: `clippy -p mneme-store --lib --tests -D warnings` clean; new tests
pass; `validation-lane determinism` OK with pinned digests
`25e3…/e14b…/b479…` unchanged (decode is byte-identical for valid hex).
