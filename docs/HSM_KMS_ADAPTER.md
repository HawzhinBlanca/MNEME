# HSM / KMS KeyVault Adapter Guide (B6)

MNEME stores every memory payload encrypted under a **per-object key**. Those keys
live behind the [`KeyVault`] trait (`crates/mneme-crypto/src/vault.rs`). The store
kernel never names a concrete vault — it holds a `Box<dyn KeyVault + Send>` — so a
hardware security module (HSM) or cloud KMS backend is a **drop-in adapter** with no
kernel change. This document is the contract for writing one.

## Where the seam is

`Store` (`crates/mneme-store/src/lib.rs`) owns:

```rust
vault: Box<dyn KeyVault + Send>,
```

and exposes injection constructors alongside the default file-backed ones:

| Default (FileKeyVault)        | Pluggable                                            |
| ----------------------------- | ---------------------------------------------------- |
| `Store::create(path, op)`     | `Store::create_with_vault(path, op, vault)`          |
| `Store::open(path, op)`       | `Store::open_with_vault(path, op, vault)`            |
| `Store::open_pinned(...)`     | `Store::open_with_vault(...)` (no pin) / internal    |

An adapter implements `KeyVault`, then the operator wires it in:

```rust
// Envelope (32-byte master from env — offline / CI-friendly)
let vault: Box<dyn mneme_crypto::KeyVault + Send> =
    Box::new(mneme_crypto::EnvelopeKeyVault::from_env(&path)?);

// AWS KMS (operator bridge — repo pins Rust 1.86; AWS SDK needs ≥1.91 in-tree)
//   eval "$(scripts/kms/dek-from-aws.sh)"   # sets MNEME_KMS_MASTER_KEY_HEX
let vault: Box<dyn mneme_crypto::KeyVault + Send> =
    Box::new(mneme_crypto::EnvelopeKeyVault::from_env(&path)?);

let store = Store::open_with_vault(path, operator, vault)?;
```

The vault is **outside the verifier TCB** (`mneme-verify`). It decides only whether a
per-object *decryption key* is available; it never decides whether a recall verifies
against the signed root. A vault that returns the wrong bytes makes AEAD `open` fail
(`MnemeError::ObjectTampered`) and recall fails closed — it can never forge a passing
receipt.

## The trait contract

```rust
pub trait KeyVault {
    fn new_key(&mut self) -> Result<(ObjectKey, KeyId), MnemeError>;
    fn get(&self, key_id: &KeyId) -> Result<ObjectKey, MnemeError>;
    fn shred(&mut self, key_id: &KeyId) -> Result<(), MnemeError>;
    fn contains(&self, key_id: &KeyId) -> bool;
    fn import_key(&mut self, key_id: &KeyId, key: &ObjectKey) -> Result<(), MnemeError>;

    // Group-commit hooks — default no-ops; override only if your backend batches.
    fn begin_batch(&mut self) -> Result<(), MnemeError> { Ok(()) }
    fn flush_batch(&mut self) -> Result<(), MnemeError> { Ok(()) }
    fn cancel_batch(&mut self) {}
}
```

`ObjectKey` is `[u8; 32]` (XChaCha20-Poly1305 key); `KeyId` is `[u8; 16]`.

### Required methods

- **`new_key`** — mint a fresh, unique per-object key and its id. The id MUST be
  unique among live and shredded ids. Return the raw key bytes so the kernel can seal
  the payload immediately. An HSM whose keys are *non-extractable* cannot satisfy this
  contract as written (the kernel needs the key bytes to run AEAD in process); such a
  backend should instead front a derive-and-cache layer or be rejected at connect time
  with a clear error — do **not** return fabricated bytes.
- **`get`** — return the live key, or fail closed:
  - shredded id → `MnemeError::Forgotten`
  - never-stored id → `MnemeError::KeyVaultMissing`
- **`shred`** — irreversibly destroy the key. After shred, `get` MUST return
  `Forgotten` and `contains` MUST return `false`. Shredding an unknown id returns
  `MnemeError::KeyVaultMissing`. This is the cryptographic half of GDPR forget (§13):
  destroying the key renders the ciphertext permanently unrecoverable, so the backend
  delete must be durable and complete (e.g. KMS `ScheduleKeyDeletion` is **not**
  sufficient on its own — the local key material/cache must also be zeroed).
- **`contains`** — `true` iff a live (non-shredded) key with this id is held. Must
  never report `true` for a shredded id.
- **`import_key`** — accept externally-supplied key material from anti-entropy merge
  (§9.4) or a B4 sealed-key bundle (§11). Contract:
  - Idempotent: re-importing the same id with the same bytes is a no-op `Ok(())`.
  - Re-importing a **shredded** id MUST fail with `MnemeError::Forgotten` (fail-closed:
    a forgotten key never silently resurrects).
  - A backend that cannot accept raw key bytes MUST return an error, never a silent
    `Ok(())` — a false success would let a merge believe a key arrived when it did not,
    and recall would then fail confusingly instead of at import time.

### Batch (group-commit) methods — optional

`begin_batch` / `flush_batch` / `cancel_batch` exist so a durable backend can amortise
fsync/round-trip cost across a `remember_batch` (§22 group commit). They default to
no-ops; an eager vault (every `new_key` already durable) needs no override.

Semantics if you override:

- **`begin_batch`** — open a buffering window. Idempotent. `new_key`s issued during the
  window may defer their durable write until flush, but MUST be readable by `get`
  immediately (the kernel reads keys mid-transaction). Returning `Err` here aborts the
  surrounding store transaction cleanly (no leaked `.incomplete`).
- **`flush_batch`** — make every buffered write durable with a single commit, then close
  the window. No-op if no window is open.
- **`cancel_batch`** — discard buffered, un-flushed writes and close the window. Called
  on transaction rollback; the discarded keys belong to objects being thrown away, so
  losing them is correct. Must not error.

The store always pairs these correctly: `begin_batch` inside the transaction, then
exactly one of `flush_batch` (commit path) or `cancel_batch` (rollback path).

## Error handling

`MnemeError` is a **frozen, closed enum** (interface freeze, no `Other(String)`). An
adapter MUST map every backend failure onto an existing variant. Useful targets:

| Situation                                   | Variant                       |
| ------------------------------------------- | ----------------------------- |
| Key id not present                          | `KeyVaultMissing`             |
| Key was shredded / forgotten                | `Forgotten`                   |
| Stored bytes wrong length / corrupt         | `KeyVaultCorrupt`             |
| Backend I/O / network / API failure         | `IoFailed { path, kind }`     |
| Backend out of capacity                     | `StorageFull`                 |

For `IoFailed`, put a backend-identifying string in `path` (e.g. the KMS key ARN or
endpoint) and a short reason in `kind`. Do not invent new variants — adding one is a
formal interface-change request.

## Thread-safety

The kernel stores the vault as `Box<dyn KeyVault + Send>` and runs inside
`Arc<Mutex<Store>>` across `tokio::spawn` (mnemed). Your adapter therefore must be
`Send`. Interior mutability (e.g. a connection pool behind a `Mutex`) is fine; `&self`
methods (`get`, `contains`) must remain correct under the kernel's single-writer,
mutex-guarded access pattern.

## Determinism

Vault layout and key bytes are **invisible to the signed root** — the root commits over
ciphertext and index structure, not over how keys are stored. Swapping FileKeyVault for
a KMS adapter therefore changes **no determinism digest** and the foundation-gate stays
green. (Confirm with `scripts/ci/validation-lane.sh determinism` after wiring an
adapter.)

## Reference implementations & tests

- `FileKeyVault` — on-disk vault with a batched-write journal (the production default).
- `MemoryKeyVault` — in-memory `HashMap` vault for unit tests that need no disk.

`crates/mneme-crypto/tests/crypto_invariants.rs::file_and_memory_vaults_have_identical_behaviour`
runs a fixed operation sequence against both and asserts byte-for-byte identical
observable behaviour (same retrievals, same typed errors, same idempotent-import and
batch semantics). A new adapter should be held to the same parity scenario
(`run_vault_parity_scenario`) as a conformance check.

## What this is **not**

- Not an actual AWS/GCP/PKCS#11 implementation — none ships here (no credentials in
  the repo). This is the seam + contract only.
- Not a change to the honesty boundary: a vault proves key *availability*, never
  semantic truth, and never exact nearest neighbours.
