# mneme-root — module contract (§20.2)

## Responsibility

Signed root assembly (`RootPreimage` → BLAKE3 → Ed25519), append-only checkpoint log, and atomic `roots/HEAD` pointer.

## Public API

```rust
// StoredRoot: assemble, preimage, to_root, verify, to_bytes, from_bytes
// CheckpointLog: ensure_dir, append, write_head, read_head, read_checkpoint, commit
// verify_root_chain, check_replay
// ROOT_VERSION
```

## Invariants owned

- **INV-4**: single signed root; Ed25519 over `BLAKE3(ROOT ‖ preimage)`
- **INV-6**: monotonic HLC high-water mark; replay rejection via `check_replay`

## Proof obligations

| Test | Closes |
|------|--------|
| `assemble_sign_verify_roundtrip` | §5.7 signing |
| `fault_injection_rejects_tampered_*` | §18 crypto fault hook |
| `root_chain_*` | hash-chain succession |
| `check_replay_rejects_older_hlc` | INV-6 / A-REPLAY |
| `checkpoint_log_append_is_create_new` | append-only log |
| `head_write_and_read_roundtrip` | atomic HEAD |
| `pinned_root_preimage_hash_for_fixture_seed` | byte-pinned preimage hash |

## Dependencies

- `mneme-core`, `mneme-crypto`

## May start when

- Wave 0 domain tags and `RootPreimage` layout frozen.

## Forbidden

- No store object/index logic.
- No `unsafe`.
- Checkpoint files must be create-new (no overwrite).

## Handoff (§20.4)

Report: root tests + `validation-lane quick` (when wired); Appendix B `proof/vectors/roots/*` pending; RFC 9162 consistency proofs deferred to v1.
