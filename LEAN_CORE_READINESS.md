# MNEME Lean Core Readiness

Top-line status: NOT LEAN.

The local code boundary is much closer to the lean product, and the trusted
verifier surface shrank. It is still not honest to write `LEAN` because:

- No real second physical host was available. Strict mode failed closed when
  `MNEME_SECOND_HOST` was unset.
- The full validation lane passed in this dirty worktree, not from a committed
  clean checkout.
- The full 1M fsync-on benchmark with 200 write/forget/erasure samples was
  stopped at 99% disk usage. A bounded 1M run with 10 erasure samples completed
  and is recorded separately.

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

## Performance

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

1. Produce a true clean-checkout proof. This needs a committed branch or a
   separate clean checkout of the exact patch.
2. Run real second physical host determinism with
   `MNEME_SECOND_HOST=user@host`.
3. Re-run the full 1M fsync-on benchmark with enough free disk for the requested
   200 write/forget/erasure samples, or reduce the accepted sample count in the
   gate spec.
4. Review `CLASSIFICATION.md` before any CUT deletion.
5. Decide whether `mneme-crossref` is core assurance or deferred
   standardization.
6. Decide whether deletion propagation for v1 is single-store signed lineage or
   multi-peer CRDT propagation. This branch treats CRDT propagation as deferred.

Final status remains: NOT LEAN.
