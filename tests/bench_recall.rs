//! `mneme` recall verification benchmark (§19 v0: <1 ms @ 10k entries on M4 Max class HW).

mod e2e;

use e2e::helpers::{agent_store, semantic_draft};
use mneme_core::{Query, TrustTier};
use std::time::Instant;

const BENCH_ENTRY_COUNT: usize = 10_000;
const SIDECAR_REWRITE_ENTRY_COUNT: usize = 2_000;

#[test]
// Performance budget benchmark; run explicitly from the full validation lane.
// Kept `#[ignore]` so `cargo test --workspace` does not duplicate the isolated
// release-profile gate; use `scripts/ci/bench-recall-optional.sh`.
#[ignore = "perf budget benchmark; run via scripts/ci/bench-recall-optional.sh"]
fn bench_verify_recall_10k_entries() {
    let (mut store, cap, _dir) = agent_store();

    let populate_start = Instant::now();
    store
        .bench_populate_semantic_entries("bench", BENCH_ENTRY_COUNT, &cap)
        .expect("bench populate");
    let populate_elapsed = populate_start.elapsed();
    eprintln!(
        "bench_verify_recall_10k: populated {BENCH_ENTRY_COUNT} entries in {populate_elapsed:?}"
    );

    let mid = BENCH_ENTRY_COUNT / 2;
    let query = Query {
        logical_key: mneme_core::LogicalKey {
            namespace: "bench".into(),
            name: format!("key-{mid:05}"),
        },
        min_tier: TrustTier::Working,
        embedding: None,
    };

    // Warmup (not measured): primes the OS/object caches; the SMT node cache is
    // already built during populate (`rebuild_root_cache`), so the membership
    // `auth_path` is O(TREE_DEPTH) cache lookups — not an O(n) per-depth rehash.
    let _ = store.recall_verified_default(&query, &cap).unwrap();

    let start = Instant::now();
    let _ = store.recall_verified_default(&query, &cap).unwrap();
    let recall_elapsed = start.elapsed();

    // Blueprint §19 aspiration: <1ms @ 10k on M-series. With the cached SMT
    // auth_path (§5.6/§9.3) the verify phase is dominated by the root signature
    // check + payload decrypt + O(256) fold, all well under the budget.
    const RECALL_SLA_US: u128 = 1_000;
    eprintln!(
        "bench_verify_recall_10k: recall_verified {:?} (strict gate <{RECALL_SLA_US}µs @ 10k entries, release isolated)",
        recall_elapsed
    );

    assert!(
        recall_elapsed.as_micros() < RECALL_SLA_US,
        "verify_recall took {:?}; exceeds blueprint <1ms gate at {BENCH_ENTRY_COUNT} entries",
        recall_elapsed
    );
}

#[test]
// Documentation benchmark for single-entry ingest, not a release gate.
// Production `remember` now appends key-index mutations to `meta/key_index.journal`
// while retaining `meta/key_index.json` as the deterministic base sidecar.
#[ignore = "documents remember key-index journal ingest; run manually in release when investigating ingest perf"]
fn bench_remember_key_index_journal_append_2k_entries() {
    let (mut store, cap, _dir) = agent_store();

    let start = Instant::now();
    for i in 0..SIDECAR_REWRITE_ENTRY_COUNT {
        store
            .remember(
                semantic_draft("sidecar-rewrite", &format!("key-{i:05}"), b"x"),
                &cap,
            )
            .expect("remember bench entry");
    }
    let elapsed = start.elapsed();

    eprintln!(
        "bench_remember_key_index_journal_append: remembered {SIDECAR_REWRITE_ENTRY_COUNT} entries in {elapsed:?}"
    );
}
