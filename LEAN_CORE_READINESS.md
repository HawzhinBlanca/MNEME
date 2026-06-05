# MNEME Lean Core Readiness

Top-line status: NOT LEAN — clean-checkout gap closed; a real O(N)
write-amplification blocker found at 1M scale.

The local code boundary is much closer to the lean product, and the trusted
verifier surface shrank. The headline new finding is a genuine scalability
blocker (see "Perf Finding (TOP BLOCKER)"): every `remember`/`forget` writes a
full, unpruned key-index snapshot, making writes O(N) in time and O(N × writes)
in disk at scale. One prior blocker is resolved; the rest remain:

- RESOLVED: The full validation lane now passes from a committed, cold,
  separate clean checkout (`git worktree` detached at `c2251db`), not just a
  dirty worktree. See "Clean-Checkout Proof" below.
- OPEN (needs infra): No real second physical host was available. Strict mode
  failed closed when `MNEME_SECOND_HOST` was unset. Closing this needs a real
  `MNEME_SECOND_HOST=user@host`.
- OPEN (needs disk): The full 1M fsync-on benchmark with 200
  write/forget/erasure samples was stopped at 99% disk usage. A bounded 1M run
  with 10 erasure samples completed and is recorded separately. Closing this
  needs ~50 GiB free, or a reduced sample count in the gate spec.

## Clean-Checkout Proof

The lean-core separation was committed as `c2251db` (62 git-verified renames,
0 orphan deletes). A fresh detached `git worktree` of that commit was created
at `/tmp/mneme-clean-checkout` and confirmed self-contained: the full
`experimental/` tree is present and `git status` is clean. From that cold
checkout:

| Lane | Result | Evidence |
|---|---:|---|
| Clean-checkout quick | PASS (exit 0) | `out/lean-core-readiness/clean-checkout-quick.log` |
| Clean-checkout full | PASS (exit 0) | `out/lean-core-readiness/clean-checkout-full.log` |

The full lane ended `validation-lane (full): OK` and included chaos
(disk-full mid-txn fail-closed, every iter `unsafe_state:false` with the
`.incomplete` guard held), storage-tamper rejection, A-injection quarantine
block, Appendix B cross-impl vectors, release recall bench, and ≥30s/target
fuzz. This proves the committed commit builds and passes every gate in
isolation — the renames carried the entire tree.

Also green on the committed state (same worktree, clean tree): `quick`,
`tamper`, and `determinism` lanes (see
`validation-{quick,tamper,determinism}-after-commit.log`).

## Boundary Decisions Made

- Public product API is exactly MCP:
  `record-with-provenance`, `recall-with-signed-chain`,
  `erase-with-receipt-and-proof-of-absence`, and `verify`.
- CLI `audit`, `init`, and `determinism` are operator-only behind
  `mneme-cli/operator_tools`.
- Store helper/tamper/bench surfaces are gated behind
  `internal_test_support` and/or `bench_support`.
- Core `ForgetProof` wire moved to `mneme-core/src/erasure_receipt.rs`.
- Broader external `ActionReceipt` signing/enforcement is deferred under
  `experimental/action-accountability/`.
- Semantic/ANN/ZK/federation/redaction/context/attestation/sync internals are
  under `experimental/` or default-off features.
- No CUT candidate was deleted.

## Commands And Evidence

| Gate | Result | Evidence |
|---|---:|---|
| Full validation lane | PASS | `out/lean-core-readiness/validation-lane-full-after-cli-helper-gates.log` |
| Tamper lane after boundary | PASS | `out/lean-core-readiness/validation-lane-tamper-after-final-boundary.log` |
| Determinism local x2 | PASS | `out/lean-core-readiness/validation-lane-determinism-after-final-boundary.log` |
| Local dual-workspace digest proxy | PASS | `out/lean-core-readiness/determinism-local-second-host-after-pinned-refresh.log` |
| Strict physical second host | FAIL-CLOSED / NOT PROVEN | `out/lean-core-readiness/determinism-two-machine-strict-after-final-boundary.log` |
| Workspace tests | PASS | `out/lean-core-readiness/cargo-test-workspace-after-cli-helper-gates.log` |
| Dedicated chaos smoke | PASS | `out/lean-core-readiness/chaos-smoke-one-each-after-final-boundary.log` |
| 1M fsync-on, 200 write samples | PARTIAL / STOPPED FOR DISK | `out/lean-core-readiness/bench-1m-fsync-after-final-boundary.log` |
| 1M fsync-on, 10 erasure samples | PASS | `out/lean-core-readiness/bench-1m-erasure-smoke-after-final-boundary.log` |

`validation-lane-full-after-cli-helper-gates.log` includes quick, crypto,
tamper, workspace tests, release recall bench, 30s/target fuzz, Appendix B
vectors, pinned foundation digest check, and MCP agent simulation. It ended
with `validation-lane (full): OK`.

## Tamper / Forgery

Tamper evidence after the final boundary:

- Store generative tamper: 606 distinct cases, exact typed variants.
- Verify tamper source-count floor: 157 cases counted from source.
- Cap tamper suite: PASS.
- Semantic tamper is intentionally skipped unless
  `MNEME_EXPERIMENTAL_SEMANTIC=1`, because semantic retrieval is deferred.

The full lane also ran verifier/store/cap tests and fuzz targets. This is a
strong local forgery/tamper result, but not a clean-checkout proof.

## Determinism Digests

Pinned local foundation digest values:

| Field | Digest |
|---|---|
| `root_preimage_hex` | `25e397fbc39058986fe7f9faa5751c8e4459b6e79b76dcb8495b596015c5516a` |
| `receipt_digest_hex` | `e14b2fc14cba06d9aca87fc1bb47c5453723a8b4cdf034fbe7820196e0d9b0d4` |
| `absent_proof_digest_hex` | `b479944e1b1c76a1628c4d8a6f3544fb690882124aeee3cf2ca2db91f5db1d88` |
| `semantic_digest_hex` | all zero bytes, because semantic is default-off |

Real second physical host: NOT PROVEN. With
`MNEME_STRICT_CROSS_HOST=1` and no `MNEME_SECOND_HOST`, the script exited
closed instead of pretending dual-workspace determinism is a physical-host
proof.

## Perf Finding (TOP BLOCKER): O(N) write amplification on every commit

Investigating the 1M write run on the committed state (`c2251db`) surfaced a
real scalability blocker, more significant than the perf sample count or the
second-host gap:

- `Store::commit_root_inner` runs on **every** `remember`/`forget` and
  unconditionally calls `layout::snapshot_key_index_at_seq(path, seq, self)`
  (`crates/mneme-store/src/lib.rs:891`).
- `snapshot_key_index_at_seq` (`crates/mneme-store/src/layout.rs:236`) writes
  `meta/snapshots/<seq>/key_index.json` containing the **entire** key index
  plus tombstones, hex-encoded, as **pretty-printed JSON**, fsync'd.
- There is **no pruning/retention** of `meta/snapshots/<seq>/`.

Consequences at 1M entries:

- Write latency is O(N): each `remember` serializes + fsyncs the full index,
  ≈4.5 s/op (the snapshot dominates, not the entry write itself).
- Disk is O(N × writes): each commit keeps a full ≈225 MiB index copy. 200
  writes grew the store from ≈7 GiB (post-populate) to ≈52 GiB used, which is
  what stopped the prior run at 99% and tripped this run's 8 GiB watchdog floor.

Root insight: the **only** consumer of these per-sequence snapshots is
historical/point-in-time recall (`layout::load_key_index_at_seq`), and the lean
public MCP `recall-with-signed-chain` exposes **no time/sequence parameter** —
point-in-time recall is not in the lean product surface. So the lean core is
paying an O(N) write+disk tax for a deferred feature.

Proposed fix (next, must go through the full determinism/tamper/validation
ladder before acceptance): gate `snapshot_key_index_at_seq` behind a
historical-recall feature (off in lean default), making lean `remember`/`forget`
O(1) on the write path and bounding disk. The signed root is assembled from
`dag.root + key_index.root + semantic_commit + hlc + prev + seq` and does **not**
include the snapshot bytes, so removing per-commit snapshots should not move the
`root_preimage`/`receipt`/`absent_proof` digests — but this must be proven, not
assumed, by re-running determinism + tamper + full after the change.

Verified implementation scope (turnkey for next increment):

- New off-by-default `mneme-store` feature, e.g. `bitemporal_recall`.
- Exactly one snapshot caller to gate: `commit_root_inner`
  (`crates/mneme-store/src/lib.rs:891`).
- Exactly one load caller / consumer: `recall_verified_at` in
  `crates/mneme-store/src/recall_at.rs` (the whole `recall_at` module + its
  `pub use` re-exports).
- `AsOf` stays in `crates/mneme-core/src/interface.rs` (frozen seam) — type is
  untouched; only the store-side impl is gated.
- `crates/mneme-store/src/certify.rs` already sits behind
  `experimental_cognition_cert`; ensure its `AsOf` use still compiles with both
  features on.
- Tests to gate with the feature: `tests/e2e/phase_i_gates.rs` (2 tests),
  `tests/e2e/mod.rs` (`e2e_bypass_adb_recall_verified_at_trusted`,
  `e2e_bypass_ainj_poison_recall_verified_at_trusted`).
- Determinism risk to verify first: confirm the foundation-gate digest does not
  hash `meta/snapshots/`. If it diffs the whole store dir, the pinned
  `root_preimage`/`receipt`/`absent_proof` digests must be re-pinned and the
  change explained as a layout (not semantic) difference.

## Performance — committed-state 1M run (`c2251db`, fsync-on, watchdog-guarded)

Authorized full 200-sample run; disk watchdog (floor 8 GiB free) hard-aborted
during the forget/erasure phase and cleaned up the store. Completed, honest
metrics:

| Operation | Samples | p50 | p99 | Status |
|---|---:|---:|---:|---|
| populate 1M | — | 117.093 s wall | — | complete |
| `recall_verified` | 2000 | 164.916 us | 205.292 us | complete |
| `recall_verified_cached` | 2000 | 37.500 us | 47.583 us | complete |
| `recall_raw` | 2000 | 64.042 us | 76.959 us | complete |
| `remember` | 200 | 4.476 s | 4.667 s | complete |
| `forget` | 200 | — | — | BLOCKED (watchdog abort; see write-amplification finding) |
| `erasure_receipt` | 200 | — | — | BLOCKED (watchdog abort) |

Read-path SLAs hold at 1M (`recall_verified` p99 ≈205 us, well under the §19
<1 ms budget). The write-path numbers are dominated by the O(N) snapshot, not
intrinsic write cost. Evidence:
`out/lean-core-readiness/bench-1m-fsync-200samples-authorized.log`. The store
was removed after the run; final free disk 7 GiB.

## Performance (prior, pre-commit runs)

The full 200-write-sample 1M run was stopped to protect the machine:

- Store path during test:
  `crates/mneme-store/out/lean-core-readiness/bench-1m-store`
- Store reached 46 GiB.
- Disk reached 99% capacity with 15 GiB free.
- Completed metrics before stop:
  - populate 1M: 115.107 s
  - `recall_verified`: p50 165.583 us, p99 225.000 us, 2000 samples
  - `recall_verified_cached`: p50 37.125 us, p99 54.833 us, 2000 samples
  - `recall_raw`: p50 64.250 us, p99 135.584 us, 2000 samples
  - `remember`: p50 4.251727 s, p99 4.417497 s, 200 samples

Bounded 1M fsync-on erasure run completed with 10 write/forget/erasure samples:

| Operation | Samples | p50 | p99 |
|---|---:|---:|---:|
| `recall_verified` | 2000 | 158.125 us | 268.416 us |
| `recall_verified_cached` | 2000 | 37.458 us | 54.209 us |
| `recall_raw` | 2000 | 64.250 us | 87.875 us |
| `remember` | 10 | 4.341381 s | 4.364324 s |
| `forget` | 10 | 4.326549 s | 4.474619 s |
| `erasure_receipt` | 10 | 4.342339 s | 4.370963 s |

The bounded run ended `ok` in 289.04 s with final disk bytes
`6063976680` before the generated store was removed.

## Soak / Chaos

Dedicated smoke passed:

- disk-full mid-write: incomplete transaction detected; open failed closed.
- corrupted blob: verifier returned typed serialization/schema error; no panic.
- stale signed root: replay detected.
- forged root: rejected.
- random kill boundaries: incomplete transaction detected.
- kill during forget/merge: incomplete transaction detected.
- injected clock skew: regression rejected; deterministic convergence retained.

Workspace tests also included `chaos_sustained_soak` from the prior full
workspace run.

## TCB Line Count

| State | Files counted | Lines |
|---|---|---:|
| Before | `lib.rs`, `proof.rs`, `recall.rs`, `root.rs`, `semantic.rs`, `store.rs` from `HEAD` | 494 |
| After | `crates/mneme-verify/src/{lib,proof,recall,root,store}.rs` | 481 |
| Delta | semantic verifier moved out of default TCB; local store verifier grew | -13 |

Current production files:

| File | Lines |
|---|---:|
| `crates/mneme-verify/src/lib.rs` | 21 |
| `crates/mneme-verify/src/proof.rs` | 30 |
| `crates/mneme-verify/src/recall.rs` | 138 |
| `crates/mneme-verify/src/root.rs` | 38 |
| `crates/mneme-verify/src/store.rs` | 254 |
| Total | 481 |

## Dependency Counts

Dependency-count evidence exists in:

- `out/lean-core-readiness/counts-after-index-cli-split.log`
- `out/lean-core-readiness/counts-after-cli-public-surface-gate.log`
- `out/lean-core-readiness/counts-after-mcp-erasure-receipt.log`

Comparable pre/post counts from the same earlier method:

| Surface | Before | After | Delta |
|---|---:|---:|---:|
| `mneme-verify` default | 75 | 67 | -8 |
| `mneme-store` default | 90 | 87 | -3 |
| Workspace normal | 238 | 234 | -4 |

Current unique normal package counts from `cargo tree`:

| Surface | Count |
|---|---:|
| `mneme-verify` | 53 |
| `mneme-store` | 64 |
| `mneme-store --features erasure_receipt` | 64 |
| `mneme-mcp` | 81 |
| `mneme-cli` | 78 |

## Anti-Fake Status

Final core anti-fake scan:

- Raw scan log:
  `out/lean-core-readiness/anti-fake-scan-final-after-readiness-refresh.log`.
- Expected hits only:
  - `tests/bench_recall.rs:21` documents the intentional ignored perf gate.
  - `scripts/ci/bench-recall-optional.sh:4` documents that the ignored bench is
    invoked explicitly.
  - `crates/mneme-verify/tests/tcb_guard.rs:100-101` contains regexes that scan
    for forbidden `todo!` / `unimplemented!` macros.
- Filtered unexpected-hit scan:
  `out/lean-core-readiness/anti-fake-scan-unexpected-final-after-readiness-refresh.log`.
- Filtered unexpected-hit result: PASS, empty log.

The intentional ignored perf target is not a hollow pass because validation
scripts invoke it explicitly with `--ignored`.

## What Is Left Exactly

1. DONE. True clean-checkout proof produced: committed `c2251db`, fresh
   detached worktree, `validation-lane full` PASS. See "Clean-Checkout Proof".
2. TOP PRIORITY. Fix the O(N) write-amplification: gate per-commit
   `snapshot_key_index_at_seq` behind a historical-recall feature (off in lean
   default), then re-run determinism + tamper + full and prove the foundation
   digests are unchanged. See "Perf Finding (TOP BLOCKER)". This both fixes
   write scalability and unblocks the 200-sample forget/erasure perf at 1M.
3. Run real second physical host determinism with
   `MNEME_SECOND_HOST=user@host`. (Blocked: no second host available here.)
4. After the write-amp fix, re-run the full 1M fsync benchmark to completion
   (forget/erasure @ 200) — it should now fit disk easily.
4. Review `CLASSIFICATION.md` before any CUT deletion.
5. Decide whether `mneme-crossref` is core assurance or deferred
   standardization.
6. Decide whether deletion propagation for v1 is single-store signed lineage or
   multi-peer CRDT propagation. This branch treats CRDT propagation as deferred.

Final status remains: NOT LEAN.
