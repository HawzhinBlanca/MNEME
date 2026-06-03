# Finding + ready fix — valid-time SEMANTIC recall was non-functional (fail-closed)

**Severity: FUNCTIONAL (safe, non-functional).** Date 2026-06-03. Ready-to-apply fix below.

## Symptom

`Store::recall_verified_at(query, semantic_proc, cap, AsOf::ValidTime(t))` always failed closed
for any `t` that actually filters out an entry — the call returned `Err` instead of the
time-bounded result. Safe (nothing leaks) but the valid-time *semantic* path was unusable.
(The valid-time *key-index* path worked: it did a verified recall then post-filtered.)

## Root cause

`recall_verified_at_valid_time` (semantic branch) called `semantic_valid_time(bound_ms)`, which
rebuilt a **valid-time-filtered sub-index**. That sub-index's `semantic_commit()` never equals the
signed `root.semantic_commit` (it's a subset), so `verify_semantic_receipt`
(`receipt.binds_to_semantic_commit(root.semantic_commit)`) rejected with `ReceiptRootMismatch`.

## Fix (sound + functional)

Valid-time is a *content attribute*, not a signed checkpoint — there is no "signed root at
valid-time t". So do a **fully verified semantic recall over the current signed root**, then
**post-filter the verified entries by valid_time** — exactly what the key-index branch already does.

```rust
// crates/mneme-store/src/recall_at.rs — recall_verified_at_valid_time, semantic branch
let previous = self.session_previous_root();
let entries =
    self.recall_semantic_at_index(query, proc, cap, &root, &self.semantic, previous.as_ref())?;
Ok(filter_entries_valid_time(entries, bound_ms))
```

Delete the now-dead `semantic_valid_time` helper. Verified: the new
`e2e_recall_verified_at_valid_time_semantic_excludes_and_is_functional` test passes (entry valid
at t=200 is excluded at bound 100, present at bound 300; both calls return Ok); fmt + clippy clean.

## Status

Implemented + tested on branch `harden/phase-i-bitemporal-and-provenance` but **not committed** —
a parallel agent was live-editing the same tree (adding `VerificationObject.leaf_indices` for the
HNSW true-index membership fix), leaving it non-compiling mid-flight. Re-apply this patch on the
settled tree and re-run the test.
