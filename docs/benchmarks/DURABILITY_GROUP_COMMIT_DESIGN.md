# Durable Group-Commit — Design + Implementation (the §22 write-path optimization)

**Status: IMPLEMENTED** (commits `71c7ac3` B3, `2bf1fbb` B5), adversarial-reviewed GO (0 blockers), CI green.

**Outcome vs the design's prediction.** The blast-radius worry below (that the vault layout would rewrite the determinism golden fixtures) turned out to be **wrong**: the foundation-gate digests the signed root / receipt / absent / semantic values, none of which include vault key-file bytes — so the journal vault is invisible to determinism (verified: foundation-gate HEAD byte-identical ×2). No fixture refresh was needed. Two O(n)-fsync bottlenecks were removed:

1. **Batched vault-key journal** (`FileKeyVault::{begin_batch,flush_batch,cancel_batch}`, `vault.journal`) — N per-key fsyncs → 1.
2. **Snapshot key-index persist** (`persist_key_index` now one `atomic_write` + journal truncate, not N fsync'd journal appends) — applied to both `bench_populate`/`remember_batch` (B3) and `commit_merge` (B5).

New API: `Store::remember_batch(drafts, cap)`. **Measured (M4 Max, fsync ON):** durable 10k ingest **105.9s → 1.17s (~90×)**, ingest ~93/s → ~8,500/s; concurrent merge 0.08 → 0.12 merges/s (~1.5×, residual ceiling = per-object content fsyncs). recall_verified unchanged.

---
*Original design (retained for the rationale + the parts not yet built):*

**Original status:** designed, not yet implemented — scoped as a reviewed change because it was thought to alter the determinism fixtures (it did not — see above).

## Why (measured)

The §22 benchmark proved every write bottleneck is **fsync durability**, not algorithm:

| Path | fsync ON | fsync OFF (CPU floor) | fsync share |
|---|---|---|---|
| populate (ingest) | 10.6 ms/entry (~93/s) | **0.217 ms/entry (~4,600/s)** | **~98 %** |
| `remember` | 47.8 ms | 11.9 ms | ~75 % |
| `forget` | 38.2 ms | 16.3 ms | ~57 % |

So a durable batched commit that pays **one fsync barrier per transaction** instead of **one per object key (+ object + checkpoint + HEAD)** has **≈49× ingest headroom**. (Floor measured with the existing `MNEME_NO_FSYNC` test knob; that knob is crash-unsafe and test-only — the design below is crash-safe.)

## Root cause

`seal_payload` mints a fresh per-object key via `FileKeyVault::new_key()`, which writes **one key file and `sync_all()`s it** (`crates/mneme-crypto/src/vault.rs:218-234`). At N objects that is N separate-file `F_FULLFSYNC`s. N separate files cannot be made durable by a single fsync — each fd needs its own barrier. The win therefore requires a **layout change**, not just deferring the call.

## Design: batched key journal + single fsync barrier

1. **Vault layout:** replace N tiny per-key files with an **append-only `keys/vault.journal`** of `record = key_id(16) ‖ key(32)` (+ a `keys/vault.shred` tombstone log). On open, replay the journal into the in-memory `live`/`shredded` maps (legacy per-file keys still read for back-compat / migration).
2. **Batch API:** `Store::remember_batch(drafts, cap)` applies all drafts inside the **one existing `.incomplete`-guarded transaction**, buffering key records in memory; `vault.flush()` appends them to the journal and issues **one `sync_all()`**; then the single `commit_root_inner` fsync (checkpoint + HEAD) closes the transaction. Total: **O(1) fsyncs per batch**, not O(N).
3. **Per-key crypto-shred preserved:** keys remain individually addressable by `key_id`; `forget`/`shred` append a tombstone record (the §13 crypto-shred semantics — delete the key, prove absence — are unchanged; only the storage container changes).

## Crash-safety argument (why this stays fail-closed)

- The batch is a **single transaction** under the existing `.incomplete` guard (`layout::begin_transaction` → … → `commit_transaction`). A crash before the journal `flush()` + commit fsync leaves `.incomplete` present ⇒ cold open returns `IncompleteTransaction` ⇒ the batch's objects are **not** in the committed signed root ⇒ losing the un-fsync'd journal tail is harmless (those objects were never committed). This is the **same** atomicity the per-entry path already relies on; we only reduce the fsync *count* within the atomic unit.
- INV-6 / A-REPLAY unaffected (root chain + checkpoint log unchanged).
- Determinism of the *signed root* unaffected (root preimage does not include vault bytes).

## Blast radius (why it needs review, not a rush)

- **Determinism golden fixtures change:** the foundation-gate pins `keys/vault/<id>` file digests (`proof/digests/`, the dual-workspace/cross-runner comparison). Moving to a journal changes those bytes ⇒ **fixtures must be regenerated** and the cross-runner ubuntu-vs-macOS proof re-pinned. This is the single biggest reason not to slip it in silently.
- **Kill/resume suite** (`kill-resume-smoke.sh`, pause checkpoints) must be re-validated against the new flush boundary — add a pause point at `vault.flush()`.
- **Migration:** existing stores have per-file keys; `load_vault_dir` must read both layouts until a migration pass.

## Recommended sequencing

1. Land `remember_batch` + journal vault behind a feature/online migration in its own PR.
2. Refresh determinism fixtures; re-run cross-runner determinism (ubuntu vs macOS) to re-pin.
3. Re-run kill/resume + the §22 ingest benchmark to confirm ~49× (target ≥3,000 entries/s durable).
4. Adversarial multi-agent review (convergence/crash-safety/determinism/fakes) → GO before merge.

## Lower-priority, independent levers (from the report)

- **Concurrent-merge fsync serialization** (0.08 merges/s under 14 threads, `sys`≫`user`): a per-store WAL or a single fsync-coalescing thread would let merges scale with cores. Larger redesign; separate effort.
- **RSS ~linear in object count** (≈2 GB @ 1M): an on-disk/mmap object store caps resident memory for very large stores. Separate effort.

## What is NOT recommended

- **Shared/derived payload key across objects** — rejected: it breaks §13 crypto-shredding (per-object key deletion is how a single entry is provably forgotten). Per-object keys must stay.
