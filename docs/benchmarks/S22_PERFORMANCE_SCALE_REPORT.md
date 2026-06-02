# MNEME §22 Performance & Scale Report

**Concern:** §22 hot-path overhead — "every recall paying verification cost… if `recall_verified` overhead is structurally unacceptable for interactive agents at 10k–1M entries, redesign batching before scaling." Kill criterion: *recall-with-receipt overhead cannot be amortized below an interactive-latency threshold even with batching.*

**Hardware:** Apple **M4 Max**, 14 cores, 36 GiB, APFS SSD. Toolchain: rustc/cargo **1.86.0**, `--release`.
**Date:** 2026-05-31. **Method:** `tests/bench_recall.rs` (`bench_scale_ops`, `bench_concurrent_merge_contention`), each tier in its own process under `/usr/bin/time -l` for peak RSS. Every number below is copied from a `BENCH …` log line; logs in `/tmp/bench-logs/`.

> **Honesty caveats.** (1) The **1M tier was run with `MNEME_NO_FSYNC=1`** (the existing crash-unsafe test knob) purely so ingest fit in ~4.5 min instead of ~3 hr. fsync affects *write durability/latency only* — it does **not** change bytes, memory, or read latency — so the 1M **recall, disk, and RSS numbers are valid as measured**; the 1M *write* latencies are the **CPU floor** (fsync-off), and the fsync-on write cost is the O(1) ~48 ms constant proven at 10k/100k. (2) A 5k cached-vs-cold run executed *concurrently* with the 100k tier, so its **absolute populate/write times are contention-contaminated**; only its intra-process *ratio* (cached vs cold recall) is cited. 10k and 100k tiers ran in isolation.

---

## 1. Headline verdict

| Question | Answer |
|---|---|
| Is `recall_verified` under the §22/§19 `<1 ms @ 10k` gate? | **YES** — p99 **174.9 µs @ 10k** |
| Does verification cost grow with store size (10k→1M)? | **NO** — recall is **flat** (SMT-depth-bound, not entry-count-bound) |
| Does the §22 recall kill criterion trigger? | **NO** — overhead is ~89 µs cold, **0 on cache hit**, flat across scale; amortizes trivially |
| Do proof-batching / verified-root caching keep overhead under threshold? | **YES** — verified-root session cache cuts repeat recall **−73%** (137 µs → 37 µs) |
| Any real scaling concern found? | **YES, on WRITES** (not recall): ingest is fsync-bound (~93/s); `merge` is O(target) + fsync-serializes under concurrency. Optimizable; **not** a blueprint kill criterion. |

---

## 2. Recall hot path (the §22 concern) — measured, flat, fast

| Scale | `recall_verified` p50 | p99 | `recall_raw` p50 | Verify overhead (p50) | Overhead % of raw |
|---|---|---|---|---|---|
| 10,000 | 141.8 µs | **174.9 µs** | 52.7 µs | +89.1 µs | **169 %** |
| 100,000 | 153.2 µs | **193.6 µs** | 59.2 µs | +94.0 µs | **159 %** |
| **1,000,000 (measured)** | **160.0 µs** | **188.4 µs** | 64.1 µs | +96.0 µs | **150 %** |

- **Flat across a 100× scale increase** (142 → 160 µs p50, **+13 %** for 100× the entries). Verification is dominated by **constant-cost** work: one Ed25519 root-signature verify + one AEAD payload decrypt + an O(`TREE_DEPTH=256`) SMT auth-path fold — none of which depend on entry count. p99 stays **188 µs at 1M**, ~5× under the 1 ms gate. This is now a **measurement, not an extrapolation**.
- **Absolute overhead ~89–94 µs** roughly *triples* a raw (unverified) index fetch — but the *absolute* p99 stays **~175–194 µs**, i.e. ~5× under the 1 ms gate and ~500× under the ~100 ms human-interactive threshold.

### Verification-overhead composition (the +89 µs)
`verify_recall` = `verify_root` (recompute preimage hash + **Ed25519 verify** + chain + replay) → receipt↔root binding → SMT membership fold (256 hashes) → object re-hash → provenance → writer/tier → tombstone, then AEAD `decrypt_entries`. The Ed25519 verify + AEAD open are the bulk; all constant per recall.

---

## 3. Mitigations — proof-batching & verified-root caching (§22 named remedies)

| Path | p50 | vs cold verified | Notes |
|---|---|---|---|
| `recall_verified` (cold) | 137 µs | — | full verifier run |
| `recall_raw` (no verify) | 49 µs | −64 % | untrusted assembly only (not agent-facing; INV-5) |
| **`recall_verified` cached** | **37 µs** | **−73 %** | K3 verified-root session cache hit |

The K3 session cache keys on `(signed root hash, key hash, min_tier)`: the **first** recall verifies and caches; subsequent recalls against the same signed root return the verified entries via a hash-map lookup, skipping *both* the verifier and the index assembly (hence cached < raw). This **is** proof-batching in practice — one root-signature verification is amortized across every recall in a session until a mutation rotates the root (the cache is fail-closed: any `remember`/`forget`/`merge` invalidates it, proven by `e2e_session_recall_cache_invalidated_by_forget`).

### Threshold analysis — where would overhead become "interactively unacceptable"?
Because cold recall is **flat at ~155 µs regardless of scale**, store size alone never crosses an interactive threshold. The only way to accumulate is **serial recalls per agent turn**:

| Recalls per turn | Cold (155 µs each) | Cached (37 µs each) |
|---|---|---|
| 1 | 0.16 ms | 0.04 ms |
| 100 | 15.5 ms | 3.7 ms |
| 650 | **~100 ms** (human-perceptible) | 24 ms |
| 6,500 | ~1 s | 240 ms |

An agent would need **~650 cold distinct recalls in a single turn** to reach human-perceptible latency, or **~6,500** for 1 s — and the session cache pushes those thresholds ~4× further out. **The §22 recall kill criterion is NOT triggered** at any tested or extrapolated scale.

---

## 4. Write paths — fsync-bound, O(1) in store size (not the hot path)

| Op | 10k p50 / p99 | 100k p50 / p99 | Scaling |
|---|---|---|---|
| `remember` | 47.8 / 65.3 ms | **46.1 / 54.0 ms** | **O(1)** — constant vs size |
| `forget` | 38.2 / 56.1 ms | 34.9 / 41.0 ms | **O(1)** |
| `merge` (500 entries → N) | 13.8 s | **18.9 s** | grows with target — fsync count + sidecar rewrite |

### The fsync tax (measured) — and the ≈49× optimization headroom

Toggling the existing `MNEME_NO_FSYNC` knob isolates durability cost from CPU:

| Path | fsync ON | fsync OFF (CPU floor) | fsync share |
|---|---|---|---|
| populate (ingest) | 10.6 ms/entry (**~93/s**) | 0.217 ms/entry (**~4,600/s**) | **~98 %** |
| `remember` | 47.8 ms | 11.9 ms | ~75 % |
| `forget` | 38.2 ms | 16.3 ms | ~57 % |

A **durable group-commit** (one fsync barrier per transaction instead of ~5 per write / one per object key) therefore has **≈49× ingest headroom**. Correct, crash-safe design + its determinism-fixture blast radius: `DURABILITY_GROUP_COMMIT_DESIGN.md` (scoped as a reviewed change, not rushed — it rewrites the foundation-gate vault digests).

**Root cause (measured, not assumed):** `seal_payload` mints a fresh per-object key via `FileKeyVault::new_key()`, which **fsyncs** the key file. `remember` performs ~5 `F_FULLFSYNC`s (`.incomplete` guard, object write, vault key, checkpoint append, HEAD) ⇒ ~46 ms, **independent of store size** (confirmed: 48 ms @ 10k ≈ 46 ms @ 100k). This is *durability cost*, not algorithmic cost. `merge` additionally rebuilds the semantic index over the **whole** target (O(n)), the only size-dependent write cost (13.8 s @ 10k → 18.9 s @ 100k).

**Ingest throughput:** populate is exactly linear at **10.6–10.8 ms/entry ≈ ~93 entries/s**, fsync-bound (one key fsync/entry). 10k = 105.9 s; 100k = 1079.9 s. **1M ≈ 10,800 s ≈ 3.0 hrs (extrapolated, not run).**

---

## 5. Concurrent multi-agent merge under contention

14 worker threads, each: own target seeded to 2,000 entries, 3 merges of 200-entry peers (42 merges total).

| Metric | Value |
|---|---|
| Aggregate throughput | **0.08 merges/s** |
| Per-merge p50 / p99 | **38.8 s / 42.3 s** |
| `user` / `sys` CPU | 16.5 s / **221.6 s** |

**Finding:** merge throughput does **not** scale with cores — it collapses under **fsync serialization**. The 13× `sys`-over-`user` ratio is the signature: 14 threads issuing `F_FULLFSYNC` contend on the single APFS journal, so per-merge latency inflates ~3× vs isolated. This is an **operational write-path limit**, not a recall-path or correctness issue, and not a §22 kill criterion (which is recall-scoped).

---

## 6. Memory & disk growth — characterized

| Scale | Disk (after populate) | Bytes/entry | Peak RSS | Peak mem footprint |
|---|---|---|---|---|
| 10,000 | 3.17 MiB | 332.1 | 65 MiB | 51.9 MiB |
| 100,000 | 31.66 MiB | 332.0 | 233 MiB | 52.7 MiB |
| **1,000,000 (measured)** | **317.5 MiB** | **332.9** | **2.43 GiB** | 52.6 MiB |

- **Disk is exactly linear**: ~332 B/entry across all three scales (object record + per-key vault file + index/journal sidecars).
- **Peak memory footprint is constant (~52 MiB)** at every scale — transient working set is bounded. **Max RSS grows linearly with object count** (in-memory `objects`/index maps): 65 → 233 MiB → **2.43 GiB** (10k → 100k → 1M), comfortably within a 36 GiB host but a planning input for very large stores (a future on-disk/mmap object store would cap this).

---

## 7. §22 kill-criterion checklist

| Criterion | Status |
|---|---|
| `recall_verified` overhead un-amortizable below interactive latency even with batching | **NOT TRIGGERED** — overhead flat ~89 µs cold, 0 on cache hit; p99 ≤ 194 µs at 100k; cache −73 % |
| `<1 ms` verify @ 10k (M4 Max, §19) | **PASS** — p99 174.9 µs |
| Recall degrades with scale 10k→1M | **FALSE (measured)** — p50 142→160µs, p99 ≤194µs across 100× entries |
| **Operational flags (not kill criteria):** ingest ~93/s fsync-bound; `merge` O(target) + fsync-serializes under concurrency; RSS ~linear in objects | **Optimizable** — see §8 |

---

## 8. Recommended optimizations (none required to pass §22)

1. **Group-commit / batched fsync** for `remember` and ingest (amortize the ~5 fsyncs across a batch) → ingest from ~93/s toward thousands/s.
2. **Shared/derived payload keys** instead of one fsync'd vault key per object → removes the dominant per-entry ingest fsync.
3. **Incremental semantic index update** on `merge` (avoid the O(target) `rebuild_semantic_index`) → flat merge latency.
4. **Per-store fsync serialization or WAL** to make concurrent multi-agent merge scale with cores.
5. **On-disk/mmap object store** to cap RSS for >1M-entry stores.

---

## 9. Reproduce

```bash
# Per-tier scale benchmark (recall_verified / cached / raw / remember / forget / merge + disk + RSS).
# Each tier in its own process for clean peak RSS. Populate is fsync-bound (~10.8 ms/entry).
for S in 10000 100000; do
  MNEME_BENCH_SCALE=$S MNEME_BENCH_SAMPLES=2000 MNEME_BENCH_WRITE_SAMPLES=40 \
  MNEME_BENCH_STORE_DIR=/tmp/bench-store-$S MNEME_BENCH_MERGE_PEER=500 MNEME_BENCH_MERGE_ITERS=1 \
  /usr/bin/time -l cargo test --release -p mneme-store --test bench_recall \
    bench_scale_ops -- --ignored --nocapture
done

# Concurrent multi-agent merge under contention.
MNEME_BENCH_CONTENTION_THREADS=14 MNEME_BENCH_CONTENTION_BASE=2000 \
MNEME_BENCH_CONTENTION_PEER=200 MNEME_BENCH_CONTENTION_MERGES=3 \
/usr/bin/time -l cargo test --release -p mneme-store --test bench_recall \
  bench_concurrent_merge_contention -- --ignored --nocapture

# §19 strict gate (asserts recall_verified <1 ms @ 10k):
cargo test --release -p mneme-store --test bench_recall \
  bench_verify_recall_10k_entries -- --ignored --nocapture
```

Run tiers **sequentially in isolation** — concurrent tiers contend on the fsync queue and contaminate populate/write timings (verified: a 5k run overlapping the 100k tier inflated its populate ~2×).

---

## 10. Bottom line

The §22 hot-path concern is **answered and clears**: verified recall is **flat and fast — measured to 1M** (p99 188 µs @ 1M, +13 % p50 over 100× the entries), the verification tax is a **constant ~90 µs** that the verified-root cache amortizes to **37 µs (near-zero)** for repeat recalls, and **no recall kill criterion triggers**. The genuine scaling limits are on the **write/durability side** — fsync-bound ingest (measured ≈49× headroom for a durable group-commit), fsync-serialized concurrent merge — all real, measured, and optimizable (`DURABILITY_GROUP_COMMIT_DESIGN.md`), but outside the §22 recall kill criterion and not a correctness risk.
