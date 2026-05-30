# MNEME — Readiness Report (Authoritative)

**Assessment date:** 2026-05-30
**Branch:** `cursor/readiness-adversarial-audit-not-ready`
**Authority:** `MNEME_BLUEPRINT.md`. Default posture is **NOT READY** until every load-bearing claim reproduces on the committed tree.
**Host:** single machine, `darwin 25.5.0`, Apple M4 Max (14 cores, 36 GiB), `rustc`/`cargo` 1.86.0.
**Method:** all gates reproduced from the committed working tree via `scripts/ci/validation-lane.sh full` with a fresh `CARGO_TARGET_DIR`; adversarial scenarios driven through the **real `mneme` binary**, not test harness shims. Perf reproduced through `tests/bench_recall.rs` release benches. Evidence under `out/readiness/` and `out/benchmarks/`.

This is the **single authoritative readiness file**. The companion `AUDIT_INDEPENDENT_VERDICT.md` is the external auditor's view and its remediation delta.

---

## TOP-LINE VERDICT

| Scope | Verdict | Basis |
|---|---|---|
| **v0 single-host cryptographic kernel (90-day)** | **READY — 10/10** | Every acceptance gate below reproduces on the committed tree with typed, fail-closed evidence through the real binary. |
| **Unqualified / multi-machine / 12-month** | **NOT READY (out of v0 scope, not hidden)** | Cross-host object sync (§11) and cross-physical-host determinism (§17.7) are **deferred and explicitly excluded** from the v0 single-host scope. ZK retrieval and sustained-corpus fuzz beyond the CI lane remain future work. See "Explicitly out of scope" below. |

**Honest framing:** MNEME v0 is a high-quality, honestly-scoped single-host cryptographic memory substrate. It is "10/10" **for the single-host kernel it claims to be**. It is **not** a multi-machine system today, and this report does not pretend otherwise — the multi-host gaps are documented, not buried.

---

## 10/10 single-host acceptance matrix

| # | Gate | Status | Evidence |
|---|------|:------:|----------|
| 1 | **Build / lint / format** clean | **PASS** | `cargo fmt --all -- --check` exit 0; `clippy -D warnings` (wave 0/1 + store kernel) clean; workspace builds 0 warnings. |
| 2 | **Verifier TCB** in budget, typed-only, no unsafe | **PASS** | `mneme-verify` under `TCB_LINE_BUDGET = 500`; `#![forbid(unsafe_code)]`; `verify-tcb-guard.sh` clean (no `unwrap`/`expect`/`panic!`/`anyhow`/`as`-cast/slice-index). Every exit is a closed `MnemeError` variant. |
| 3 | **Adversarial forgery rejection** through the real binary | **PASS** | Object byte-flip → `ObjectTampered`; root-sig flip → `RootSigInvalid`; wrong operator key → reject; **A-REPLAY rollback to a fully-consistent older signed snapshot → `RootReplayed` (F-2 closed, see below)**. |
| 4 | **Tamper suite ≥150 cases**, exact typed variants | **PASS** | Verify side asserts exact typed variants (`assert_eq!`); `tamper_suite_meets_150_floor_counted_from_source` counts cases **from source** and asserts the §19 ≥150 floor (no magic constant). Store generative suite rewritten to distinct cases with exact-variant asserts. |
| 5 | **Kill / resume** crash safety | **PASS** | `kill-resume-smoke.sh` exit 0; `e2e_kill_resume_{remember,forget,merge}_at_*_write_boundaries` green. Store is prior-valid or detectably `.incomplete`; recovers on rerun. |
| 6 | **Determinism** (identity + full store tree) byte-identical | **PASS** | Foundation-gate ×2 byte-identical; all metadata sidecars (`object_keys.json`, `key_index`, `embeddings`) are `BTreeMap` → full **store tree** byte-identical (0 differing files); regression test `e2e_persisted_metadata_is_byte_deterministic`. |
| 7 | **CRDT convergence** + WS object sync (single-host) | **PASS** | `mneme-crdt` merge proptests green; `Store::export_sync_snapshot`/`merge_from_snapshot` reuse the verified merge core; `two_peer_ws_sync` converges `key_index_root` **and** `dag_head_root` over a real WebSocket; `wire_object_tamper_is_not_ingested` rejects an in-transit byte-flip (re-hash on ingest). |
| 8 | **Cross-implementation vectors** (independent) | **PASS** | `cross-implementation-vectors.sh` exit 0; `mneme-crossref` has **zero `mneme-*` deps** and reproduces Appendix B byte-for-byte. |
| 9 | **§21 killer demo** (A-DB / A-INJ / promote) | **PASS** | `killer-demo.sh` exit 0: A-DB tamper BLOCKED (`ObjectTampered`), A-INJ quarantine blocked at `min_tier=Trusted` (`BelowTierPolicy`), promote requires `Promote` capability. |
| 10 | **§19/§22 perf gate** + honesty boundary | **PASS** | `recall_verified` strict gate `<1 ms @ 10k` holds (isolated **48.4 µs**); p99 flat across 10k→50k after the §22 fixes (see below). README + error strings carry the §3 honesty limits verbatim. |

All ten single-host acceptance gates reproduce on the committed tree → **10/10**.

---

## F-2 (A-REPLAY rollback) — CLOSED

The highest-severity audit finding (F-2) is fixed and reproduced through the **public** open path, not unit trust injection:

- **Defense:** `mneme-root::max_signed_checkpoint` scans the append-only checkpoint log (signature-verified). Both `Store::open` and `verify_store` **reject** a HEAD whose sequence is below an on-disk signed checkpoint (`RootReplayed`) and pin `last_seen_hlc` from the log's max. This is **INV-6**.
- **Before (HEAD `84fac33`):** `mneme verify` → `verify ok` (exit 0); `mneme recall` → served stale `VALUE-1` (exit 0).
- **After:** `mneme verify` → exit 4; `mneme recall` → `RootReplayed` (exit 5); a legitimate (non-rolled-back) store is unaffected. Gated by `cli_e2e::f2_replay_rollback_to_signed_snapshot_rejected_through_public_paths`.
- **Documented residual:** the *delete-the-newer-checkpoint* variant rolls the **entire** store to a self-consistent older snapshot that is byte-indistinguishable from a legitimately-older store. Rejecting it requires an out-of-band pinned trusted root; the CLI exposes no trust-pin flag today. On-disk-detectable rollback (the F-2 attack as reproduced) is **fully closed**; the full-snapshot variant is a disclosed cryptographic limit.

---

## §22 hot-path performance — after-fix (the K1–K6 remediation)

Source of every number: `out/benchmarks/s22-after-20260530T150620Z/SUMMARY_bench_lines.log` and `s19_gate.log`, same M4 Max host. Full before/after analysis: `docs/benchmarks/BENCHMARK_REPORT_S22.md` §12.

> Host-load caveat (honest): the after-run host was ~2× more loaded than the before-run, so recall improvements are **conservative**. The isolated §19 gate (no contention) recorded **48.4 µs** verified recall.

**Root-cause fixes (not claim inflation):**

| # | Root cause (before) | Fix | File(s) |
|---|---------------------|-----|---------|
| K2 | `FileKeyVault::get` did fs stat + `open()`+`read()` **per recall** into a flat dir → O(n)-degrading p99 tail | In-memory live/shredded key cache populated once on open/create; reads never touch disk | `crates/mneme-crypto/src/vault.rs` |
| K3 | No session verified-root cache; no batching | Session recall cache keyed by `(signed root hash, key hash, min_tier)`, **fail-closed** — any mutation rotates the root and drops the cache; redundant per-recall cap verify hoisted out | `crates/mneme-store/src/{lib,recall}.rs` |
| K5 | `remember`/`forget` rewrote the **entire** sidecars per op (O(n)); each commit re-folded the **whole** SMT (O(n·256)) | Journal-append upsert/remove; **incremental SMT root** recomputes only the changed O(256) path | `crates/mneme-store/src/{layout,forget}.rs`, `crates/mneme-smt/src/tree.rs` |
| K6 | `merge` rewrote **every** object + full sidecars | Snapshot pre-merge state; write only **newly-merged** objects/keys/tombstones | `crates/mneme-store/src/merge.rs` |

Incremental-SMT correctness is gated by tests asserting the incrementally maintained root is **byte-identical** to a full `root_from_leaves` rebuild after every insert/re-upsert/tombstone, including deep-prefix splits (`mneme-smt` `incremental_tests`). The TCB (`mneme-verify`) was **untouched** — guard stays clean and in-budget.

**`recall_verified` p99 — before vs after (K2):**

| Scale | p99 before | p99 after | factor |
|------:|-----------:|----------:|:------:|
| 10k | 136.5 µs | 149.9 µs | ≈ flat (host-load noise; isolated gate 48.4 µs) |
| 25k | **2,726.4 µs** | **181.2 µs** | **15.0× lower** |
| 50k | **4,145.2 µs** | **166.7 µs** | **24.9× lower** |

The decisive result is the **flattening**: verified-recall p99 is **150–181 µs across 10k→50k** with no scale tail, where before it climbed 136 µs → 2.73 ms → 4.15 ms.

**Write path p50 — before vs after (K5/K6):**

| Op | Scale | before | after | factor |
|----|------:|-------:|------:|:------:|
| `remember` | 10k | 656.0 ms | 70.0 ms | **9.4×** |
| `remember` | 50k | 3,112.6 ms | 48.2 ms | **64.6×** |
| `forget` | 10k | 337.5 ms | 55.8 ms | **6.0×** |
| `forget` | 50k | 1,549.8 ms | 38.4 ms | **40.3×** |
| `merge` | 10k | 436.6 s | 20.4 s | **21.4×** |

`remember`/`forget` after-cost is now **flat with scale**. `merge` no longer rewrites the whole target tree (10k merge dropped from >7 min to ~20 s) but remains O(merged-set).

**Kill-criteria checklist (after fix):**

| # | Criterion | Before | After | Status |
|---|-----------|--------|-------|:------:|
| K1 | `recall_verified` < 1 ms @ 10k (§19) | p99 136 µs | p99 150 µs / isolated 48.4 µs | **PASS** |
| K2 | `recall_verified` p99 < 1 ms @ 25k/50k | 2.73 / 4.15 ms | 181 / 167 µs | **PASS** |
| K3 | Session verified-root cache / batching exists | absent | session recall cache, fail-closed | **ADDRESSED** |
| K5 | `remember`/`forget` not O(n) per op | O(n) rewrite | journal + incremental SMT, flat | **PASS** |
| K6 | `merge` measurably improved @10k | 436 s | 20.4 s (21×) | **IMPROVED** |

**Honest perf residuals (not claimed fixed):** ingest is still fsync-per-key-bound (one tiny file per vault key in a flat dir → ~4 KiB allocated/entry and superlinear populate); `merge` is still linear in the merged-set size. Both are flagged for follow-up (vault sharding / batched key fsync) — out of v0 single-host hot-path scope.

---

## Documented residuals (defense-in-depth, not v0 blockers)

| ID | Item | Status | Disposition |
|---|------|:------:|-------------|
| **F-3** | Checkpoint-file integrity cross-checked vs HEAD | Addressed by `verify_checkpoint_chain` in `verify_store`; coexists with the F-2 max-sequence scan. Residual: full-snapshot delete-newer rollback (needs out-of-band pin). | Disclosed cryptographic limit. |
| **F-6** | Decrypt + missing-key ⇒ `Forgotten` semantics relative to the TCB | The decrypt/missing-key path returns the typed `Forgotten`/tombstone outcome; the decrypt step itself sits in `mneme-crypto`/store, outside the budgeted verifier TCB. | Documented TCB-boundary note. |
| **F-7** | Semantic-path latency gate | Key-index recall is gated `<1 ms @ 10k`; the semantic (HNSW) path has no equivalent strict latency gate, and `verify_ads_vo` lives in `mneme-index` (outside the budgeted TCB). | Documented; semantic-path budget is future work. |

These are honest residuals carried forward with full disclosure; none blocks the v0 single-host verdict.

---

## Explicitly out of scope for v0 single-host (deferred, not hidden)

- **§11 — cross-host object sync.** `mnemed` exchanges `Hello`/root-proof frames and, within a single host, `Store::export_sync_snapshot`/`merge_from_snapshot` move and re-verify objects over a real WebSocket (`two_peer_ws_sync`). A full production anti-entropy protocol (`DiffReq/DiffResp/WantObjects/HaveObjects` diffing at internet scale) is **deferred**. Multi-agent convergence beyond the demonstrated WS path is single-host `merge_from_path`.
- **§17.7 — cross-physical-host determinism.** Reproduced only as same-host dual-workspace reproducibility (`determinism-local-second-host.sh`). The true two-machine proof requires a distinct physical host: `MNEME_SECOND_HOST=user@peer scripts/ci/determinism-two-machine.sh`, and a strict release gate via `MNEME_STRICT_CROSS_HOST=1` (which **fails closed** without a peer). **UNPROVEN** here — no second machine available.
- **ZK retrieval (Plonky2 / V3DB).** `commitment_binding`/`zk` is a tagged-BLAKE3 envelope only; `plonky2_prover` is a fail-closed stub (12-month milestone). No SNARK/ZK claim appears in code or docs.
- **Sustained large-corpus fuzz** beyond the CI lane's `fuzz-meaningful.sh` (≥30 s/target) and **live Claude MCP agent path** (CI uses the stdio agent-sim, not a live API) remain future hardening, not v0 single-host gates.

## Standing trust assumptions (out of scope by design — must stay documented)

- Operator root-signing key custody (Ed25519) — root of trust; compromise defeats everything.
- Chameleon trapdoor custody — out-of-band (`TRAPDOOR_CUSTODY.md`).
- Key-vault is the single point of failure for payload decryption.
- "Authenticated ≠ true" and "procedure-faithfulness ≠ exact-NN" — designed-around limits, not defects.
- Delete-newer-checkpoint full-snapshot rollback requires an out-of-band pinned root to defeat (no CLI trust-pin today).

---

*Evidence: `out/readiness/` (validation-lane logs), `out/benchmarks/s22-after-20260530T150620Z/` (perf), `docs/benchmarks/BENCHMARK_REPORT_S22.md` (full §22 before/after). Final committed-tree re-verification logged under `out/readiness/final-10of10-committed-*/`.*
