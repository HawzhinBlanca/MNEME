//! Sustained chaos soak — fault injection matrix + MTBUS tracking (readiness adversarial audit).
//!
//! Emits `CHAOS_ROW|{json}` lines for `scripts/chaos/soak.sh` to aggregate into CHAOS_REPORT.md.

mod helpers;

use helpers::{
    ChaosRow, FaultStore, PostFaultVerdict, clear_readonly_tree, corrupt_random_artifact, emit_row,
    post_fault_checks, post_fault_checks_at, set_readonly_tree,
};
use mneme_cap::agent_cap;
use mneme_core::{Draft, ForgetMode, ForgetTarget, MemoryKind, MnemeError, Root};
use mneme_crypto::KeyPair;
use mneme_root::StoredRoot;
use mneme_store::{
    AFTER_APPEND_CHECKPOINT, AFTER_BEGIN_INCOMPLETE, AFTER_KEY_INDEX, AFTER_OBJECT_WRITE,
    AFTER_PERSIST_INDEX, AFTER_WRITE_HEAD, BEFORE_COMMIT_INCOMPLETE, Store, test_clear_pause,
    test_set_pause_at,
};
use mneme_verify::verify_root;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::env;
use tempfile::tempdir;

fn iterations_from_env() -> u32 {
    env::var("MNEME_CHAOS_ITERATIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(250)
}

fn finish_row(
    iter: u32,
    fault: &str,
    injection: &str,
    expected: &str,
    actual: &str,
    v: &PostFaultVerdict,
) {
    emit_row(&ChaosRow {
        iter,
        fault: fault.into(),
        injection_point: injection.into(),
        expected: expected.into(),
        actual: actual.into(),
        verify_result: v.verify_result.clone(),
        incomplete: v.incomplete,
        open_result: v.open_result.clone(),
        unsafe_state: v.unsafe_state,
        unsafe_reason: v.unsafe_reason.clone(),
    });
    if v.unsafe_state {
        eprintln!(
            "CHAOS_UNSAFE iter={iter} fault={fault} reason={}",
            v.unsafe_reason
        );
    }
}

fn mark_verify_pass_on_corrupt(v: &mut PostFaultVerdict, context: &str) {
    if v.verify_result == "Ok" {
        v.unsafe_state = true;
        v.unsafe_reason = format!("verify_store passed on corrupted store ({context})");
    }
}

fn fault_disk_full(iter: u32, seed: u64) {
    test_clear_pause();
    let fs = FaultStore::fresh(seed);
    let path = fs.path().to_path_buf();
    // Late-stage write fault: open succeeds and the transaction BEGINS (the
    // `.incomplete` sentinel is created in the writable root), then the durable
    // object write into the now-read-only `objects/` subtree fails — exercising the
    // mid-transaction `.incomplete` fail-closed guard rather than failing at
    // tx-begin. HONEST CAVEAT: this is a permission-based proxy for a genuine
    // mid-object-write `ENOSPC`; a literal ENOSPC needs a size-capped/fault
    // filesystem (tmpfs cap / fault FS) which is not available without root on the
    // macOS/Linux CI hosts. The injection stage (object write) is faithful even
    // though the errno (EACCES) is not literally ENOSPC.
    let objects_dir = path.join("objects");
    let remember_err = match Store::open(&path, fs.operator.clone()) {
        Ok(mut store) => {
            store.trust_mut().authorized_writers.push(fs.cap.subject);
            let draft = Draft {
                namespace: "disk".into(),
                logical_name: "full".into(),
                kind: MemoryKind::Semantic,
                body: b"fill".to_vec(),
                parent_ids: vec![],
                session: [0x02; 16],
                trust_tier: None,
                embedding: None,
                valid_time_ms: None,
            };
            set_readonly_tree(&objects_dir);
            let err = store.remember(draft, &fs.cap).err();
            clear_readonly_tree(&objects_dir);
            err
        }
        Err(e) => Some(e),
    };
    let v = post_fault_checks(&fs, true);
    finish_row(
        iter,
        "disk_full_mid_txn",
        "remember with read-only objects/ tree (mid-write ENOSPC proxy, EACCES not literal ENOSPC)",
        "Err during object write; .incomplete guard or fail-closed open; golden state intact",
        &format!("remember: {:?}", remember_err),
        &v,
    );
}

fn fault_corrupt_blob(iter: u32, seed: u64) {
    test_clear_pause();
    let fs = FaultStore::fresh(seed);
    let (label, _) = corrupt_random_artifact(fs.path(), seed.wrapping_add(17));
    let mut v = post_fault_checks(&fs, false);
    // B-1: the `meta/object_keys.{json,journal}` reverse-index sidecar is now inside
    // the `verify_store` walk (cross-checked against the verified object set +
    // key-index), so a byte flip there must surface a typed verify Err — no longer
    // an audit gap.
    let in_verify_tcb = label.starts_with("roots/HEAD")
        || label.contains("key_index.json")
        || label.contains("object_keys.json")
        || label.contains("object_keys.journal")
        || label.contains("objects/");
    if in_verify_tcb {
        mark_verify_pass_on_corrupt(&mut v, &label);
    }
    let expected = if in_verify_tcb {
        "verify_store Err (typed); no panic"
    } else {
        "artifact outside verify_store walk; document if verify Ok (audit gap)"
    };
    finish_row(
        iter,
        "corrupt_random_blob",
        &label,
        expected,
        "corruption applied",
        &v,
    );
}

fn fault_clock_skew_merge(iter: u32, seed: u64) {
    test_clear_pause();
    let dir = tempdir().unwrap();
    let path_a = dir.path().join("a");
    let path_b = dir.path().join("b");
    let operator = KeyPair::from_seed([(seed % 255) as u8; 32]);
    let cap = agent_cap(&operator, operator.public_key_bytes()).unwrap();

    {
        let mut a = Store::create(&path_a, operator.clone()).unwrap();
        a.trust_mut().authorized_writers.push(cap.subject);
        a.remember(
            Draft {
                namespace: "skew".into(),
                logical_name: "a".into(),
                kind: MemoryKind::Episodic,
                body: b"a".to_vec(),
                parent_ids: vec![],
                session: [0x03; 16],
                trust_tier: None,
                embedding: None,
                valid_time_ms: None,
            },
            &cap,
        )
        .unwrap();
    }
    std::thread::sleep(std::time::Duration::from_millis(2));
    {
        let mut b = Store::create(&path_b, operator.clone()).unwrap();
        b.trust_mut().authorized_writers.push(cap.subject);
        b.remember(
            Draft {
                namespace: "skew".into(),
                logical_name: "b".into(),
                kind: MemoryKind::Episodic,
                body: b"b".to_vec(),
                parent_ids: vec![],
                session: [0x04; 16],
                trust_tier: None,
                embedding: None,
                valid_time_ms: None,
            },
            &cap,
        )
        .unwrap();
    }

    let trust = {
        let s = Store::open(&path_a, operator.clone()).unwrap();
        s.trust().clone()
    };
    let merge_result = {
        let mut a = Store::open(&path_a, operator.clone()).unwrap();
        a.trust_mut().authorized_writers.push(cap.subject);
        a.merge_from_path(&path_b)
    };

    let v = post_fault_checks_at(&path_a, &operator, &cap, &trust, "skew", "a", b"a", true);
    finish_row(
        iter,
        "clock_skew_merge",
        "two-peer merge_from_path (wall clock gap 2ms)",
        "merge Ok; wall-clock-INDEPENDENT: Hlc.wall_ms is a logical counter (no SystemTime/now in mneme-store/crdt/root), so host TZ/NTP skew cannot affect convergence — real HLC injection in clock_skew_merge_injected",
        &format!("merge: {:?}", merge_result),
        &v,
    );
}

/// REAL clock-skew injection (replaces the "not injectable" limitation).
///
/// The store never reads the host wall clock; `Hlc.wall_ms` is a logical
/// counter incremented `+1` per local mutation. So skew cannot be injected by
/// sleeping. It CAN be injected where the HLC actually gates integrity:
///   1. merge LWW ordering (`mneme_crdt::lww_pick` over `(wall_ms,counter,node)`)
///   2. the signed-root replay high-water mark (`check_replay`, INV-6 / A-REPLAY)
///
/// This fault proves (a) two-peer merge converges deterministically and is
/// independent of real elapsed wall time, and (b) the verifier fails closed on
/// a validly-signed-but-clock-REGRESSED root while accepting a monotonic
/// forward-skewed one.
fn fault_clock_skew_merge_injected(iter: u32, seed: u64) {
    test_clear_pause();

    // --- (a) deterministic, order-independent convergence (independent of
    // real wall time, since no wall clock is read). Merging is a pure function
    // of object content: A<-B and B<-A must reach the same state roots. ---
    let deterministic = converges_order_independent(seed);
    std::thread::sleep(std::time::Duration::from_millis(3)); // real time passes; must not matter

    // --- (b) live pair for the root replay-gate injection. ---
    let dir = tempdir().unwrap();
    let path_a = dir.path().join("a");
    let path_b = dir.path().join("b");
    let operator = KeyPair::from_seed([((seed >> 3) % 251) as u8; 32]);
    let cap = agent_cap(&operator, operator.public_key_bytes()).unwrap();

    build_skew_peer(&path_a, &operator, &cap, "k", b"alpha");
    // Second remember on A advances the HLC high-water mark past wall_ms 0.
    {
        let mut a = Store::open(&path_a, operator.clone()).unwrap();
        a.trust_mut().authorized_writers.push(cap.subject);
        a.remember(skew_draft("k-extra", b"alpha2"), &cap).unwrap();
    }
    build_skew_peer(&path_b, &operator, &cap, "k2", b"beta");

    let trust = {
        let s = Store::open(&path_a, operator.clone()).unwrap();
        s.trust().clone()
    };
    let merge_result = {
        let mut a = Store::open(&path_a, operator.clone()).unwrap();
        a.trust_mut().authorized_writers.push(cap.subject);
        a.merge_from_path(&path_b)
    };

    // Capture the (real, signed) merged HEAD root to chain forged successors from.
    let cur = {
        let s = Store::open(&path_a, operator.clone()).unwrap();
        s.current_root().ok()
    };

    let mut replay_summary = String::from("no-current-root");
    let mut regression_rejected = false;
    let mut regressed_accept_unsafe = false;
    if let Some(cur) = &cur {
        let mut trust_seen = trust.clone();
        trust_seen.last_seen_hlc = Some(cur.hlc_max);

        // Clock REGRESSION: validly-signed successor whose HLC high-water mark
        // rolls back below last_seen. Must fail closed (INV-6 / A-REPLAY).
        let regressed = forge_successor(cur, [0u8; 14], &operator);
        let regressed_res = verify_root(&regressed, &trust_seen, Some(cur));
        regression_rejected = matches!(regressed_res, Err(MnemeError::RootReplayed));
        if regressed_res.is_ok() && cur.hlc_max > [0u8; 14] {
            regressed_accept_unsafe = true;
        }

        // FORWARD skew: monotonic future high-water mark. Benign => accepted.
        let forward = forge_successor(cur, [0xFFu8; 14], &operator);
        let forward_accepted = verify_root(&forward, &trust_seen, Some(cur)).is_ok();

        replay_summary = format!("regressed={regressed_res:?} forward_accepted={forward_accepted}");
    }

    let mut v = post_fault_checks_at(
        &path_a, &operator, &cap, &trust, "skew-inj", "k", b"alpha", true,
    );
    if !deterministic {
        v.unsafe_state = true;
        v.unsafe_reason = "merge convergence non-deterministic across repeated runs".into();
    }
    if regressed_accept_unsafe {
        v.unsafe_state = true;
        v.unsafe_reason =
            "verifier accepted a clock-regressed signed root (INV-6 / A-REPLAY bypass)".into();
    }

    finish_row(
        iter,
        "clock_skew_merge_injected",
        "HLC regression on signed root + forward skew + repeated merge",
        "merge Ok & deterministic convergence; verifier Err(RootReplayed) on regressed HLC; forward skew benign",
        &format!(
            "merge={:?} deterministic={deterministic} regression_rejected={regression_rejected} {replay_summary}",
            merge_result.is_ok()
        ),
        &v,
    );
}

fn skew_draft(name: &str, body: &[u8]) -> Draft {
    Draft {
        namespace: "skew-inj".into(),
        logical_name: name.into(),
        kind: MemoryKind::Semantic,
        body: body.to_vec(),
        parent_ids: vec![],
        session: [0x07; 16],
        trust_tier: None,
        embedding: None,
        valid_time_ms: None,
    }
}

fn build_skew_peer(
    path: &std::path::Path,
    operator: &KeyPair,
    cap: &mneme_cap::Capability,
    name: &str,
    body: &[u8],
) {
    let mut s = Store::create(path, operator.clone()).unwrap();
    s.trust_mut().authorized_writers.push(cap.subject);
    s.remember(skew_draft(name, body), cap).unwrap();
}

/// Forge a validly-signed successor root that chains from `cur` but carries the
/// supplied HLC high-water mark. Signature/preimage are genuine (operator key),
/// so the ONLY thing under test is the replay/skew gate, not signature forgery.
fn forge_successor(cur: &Root, hlc_max: [u8; 14], operator: &KeyPair) -> Root {
    StoredRoot::assemble(
        cur.dag_head_root,
        cur.key_index_root,
        cur.semantic_commit,
        hlc_max,
        cur.preimage_hash,
        cur.sequence + 1,
        operator,
    )
    .expect("assemble forged successor")
    .to_root()
}

/// Prove deterministic, order-independent convergence: build peers A and B
/// once (AEAD nonces fix the object bytes), then merge B into a copy of A and
/// A into a copy of B. Both replicas must reach IDENTICAL state roots
/// (key_index_root, dag_head_root). Real elapsed wall time is irrelevant
/// because the store reads no wall clock.
fn converges_order_independent(seed: u64) -> bool {
    let dir = tempdir().unwrap();
    let path_a = dir.path().join("a");
    let path_b = dir.path().join("b");
    let operator = KeyPair::from_seed([((seed >> 3) % 251) as u8; 32]);
    let cap = agent_cap(&operator, operator.public_key_bytes()).unwrap();
    build_skew_peer(&path_a, &operator, &cap, "k", b"alpha");
    build_skew_peer(&path_b, &operator, &cap, "k2", b"beta");

    let a_copy = dir.path().join("a_copy");
    let b_copy = dir.path().join("b_copy");
    copy_dir_recursive(&path_a, &a_copy);
    copy_dir_recursive(&path_b, &b_copy);

    let ab = merge_into(&a_copy, &path_b, &operator, &cap); // A <- B
    let ba = merge_into(&b_copy, &path_a, &operator, &cap); // B <- A
    match (ab, ba) {
        (Some(ab), Some(ba)) => {
            ab.key_index_root == ba.key_index_root && ab.dag_head_root == ba.dag_head_root
        }
        _ => false,
    }
}

fn merge_into(
    local: &std::path::Path,
    peer: &std::path::Path,
    operator: &KeyPair,
    cap: &mneme_cap::Capability,
) -> Option<Root> {
    let mut s = Store::open(local, operator.clone()).ok()?;
    s.trust_mut().authorized_writers.push(cap.subject);
    s.merge_from_path(peer).ok()
}

fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap().flatten() {
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if from.is_dir() {
            copy_dir_recursive(&from, &to);
        } else {
            std::fs::copy(&from, &to).unwrap();
        }
    }
}

fn fault_stale_root(iter: u32, seed: u64) {
    test_clear_pause();
    let fs = FaultStore::fresh(seed);
    let path = fs.path();
    let head_path = path.join("roots/HEAD");
    let kidx_path = path.join("meta/key_index.json");
    let pre_head = std::fs::read(&head_path).unwrap();
    let pre_kidx = std::fs::read(&kidx_path).unwrap();

    {
        let mut store = Store::open(path, fs.operator.clone()).unwrap();
        store.trust_mut().authorized_writers.push(fs.cap.subject);
        store
            .forget(
                ForgetTarget::LogicalKey(fs.golden_key.clone()),
                &fs.cap,
                ForgetMode::Shred,
            )
            .unwrap();
    }

    std::fs::write(&head_path, &pre_head).unwrap();
    std::fs::write(&kidx_path, &pre_kidx).unwrap();

    let mut v = post_fault_checks(&fs, false);
    if v.recall_result.starts_with("Ok") {
        v.unsafe_state = true;
        v.unsafe_reason = "stale root resurrected forgotten entry (A-REPLAY)".into();
    }
    finish_row(
        iter,
        "stale_signed_root",
        "HEAD + key_index rollback post-forget",
        "recall Err or verify Err; never Ok with secret",
        &format!("recall={}", v.recall_result),
        &v,
    );
}

fn fault_forged_root(iter: u32, seed: u64) {
    test_clear_pause();
    let fs = FaultStore::fresh(seed);
    let head_path = fs.path().join("roots/HEAD");
    let mut bytes = std::fs::read(&head_path).unwrap();
    if !bytes.is_empty() {
        let n = bytes.len();
        bytes[n - 1] ^= 0xAA;
        bytes[n / 2] ^= 0x55;
    }
    std::fs::write(&head_path, &bytes).unwrap();
    let mut v = post_fault_checks(&fs, false);
    if v.verify_result == "Ok" {
        v.unsafe_state = true;
        v.unsafe_reason = "verify_store accepted forged HEAD signature".into();
    }
    finish_row(
        iter,
        "forged_root",
        "HEAD signature byte flip",
        "verify_store Err(RootSigInvalid) or RootInconsistent",
        "forgery written",
        &v,
    );
}

fn fault_kill_random_boundary(iter: u32, seed: u64) {
    test_clear_pause();
    let mut rng = StdRng::seed_from_u64(seed);
    let boundaries = [
        AFTER_BEGIN_INCOMPLETE,
        AFTER_OBJECT_WRITE,
        AFTER_KEY_INDEX,
        AFTER_PERSIST_INDEX,
        AFTER_APPEND_CHECKPOINT,
        AFTER_WRITE_HEAD,
        BEFORE_COMMIT_INCOMPLETE,
    ];
    let boundary = boundaries[rng.gen_range(0..boundaries.len())];
    let fs = FaultStore::fresh(seed);
    test_set_pause_at(boundary);
    let err = {
        let mut store = Store::open(fs.path(), fs.operator.clone()).unwrap();
        store.trust_mut().authorized_writers.push(fs.cap.subject);
        store
            .remember(
                Draft {
                    namespace: "kill".into(),
                    logical_name: "bound".into(),
                    kind: MemoryKind::Semantic,
                    body: b"orphan".to_vec(),
                    parent_ids: vec![],
                    session: [0x05; 16],
                    trust_tier: None,
                    embedding: None,
                    valid_time_ms: None,
                },
                &fs.cap,
            )
            .err()
    };
    test_clear_pause();
    let v = post_fault_checks(&fs, true);
    finish_row(
        iter,
        "kill_random_boundary",
        &format!("remember pause boundary {boundary}"),
        "IncompleteTransaction; .incomplete blocks open; golden recall intact",
        &format!("remember: {:?}", err),
        &v,
    );
}

fn fault_kill_merge_boundary(iter: u32, _seed: u64) {
    test_clear_pause();
    let dir = tempdir().unwrap();
    let path_a = dir.path().join("a");
    let path_b = dir.path().join("b");
    let operator = KeyPair::generate();
    let cap = agent_cap(&operator, operator.public_key_bytes()).unwrap();
    for (p, name, body) in [(&path_a, "a", b"a"), (&path_b, "b", b"b")] {
        let mut s = Store::create(p, operator.clone()).unwrap();
        s.trust_mut().authorized_writers.push(cap.subject);
        s.remember(
            Draft {
                namespace: "merge-kill".into(),
                logical_name: name.into(),
                kind: MemoryKind::Semantic,
                body: body.to_vec(),
                parent_ids: vec![],
                session: [0x06; 16],
                trust_tier: None,
                embedding: None,
                valid_time_ms: None,
            },
            &cap,
        )
        .unwrap();
    }
    let trust = Store::open(&path_a, operator.clone())
        .unwrap()
        .trust()
        .clone();
    test_set_pause_at(AFTER_OBJECT_WRITE);
    let merge_err = {
        let mut a = Store::open(&path_a, operator.clone()).unwrap();
        a.trust_mut().authorized_writers.push(cap.subject);
        a.merge_from_path(&path_b).err()
    };
    test_clear_pause();
    let v = post_fault_checks_at(
        &path_a,
        &operator,
        &cap,
        &trust,
        "merge-kill",
        "a",
        b"a",
        true,
    );
    finish_row(
        iter,
        "kill_merge_boundary",
        "merge_from_path pause AFTER_OBJECT_WRITE",
        "IncompleteTransaction; golden key a intact; peer b not silently merged",
        &format!("merge: {:?}", merge_err),
        &v,
    );
}

fn fault_forget_kill(iter: u32, seed: u64) {
    test_clear_pause();
    let fs = FaultStore::fresh(seed);
    test_set_pause_at(AFTER_KEY_INDEX);
    let err = {
        let mut store = Store::open(fs.path(), fs.operator.clone()).unwrap();
        store.trust_mut().authorized_writers.push(fs.cap.subject);
        store
            .forget(
                ForgetTarget::LogicalKey(fs.golden_key.clone()),
                &fs.cap,
                ForgetMode::Shred,
            )
            .err()
    };
    test_clear_pause();
    let v = post_fault_checks(&fs, false);
    finish_row(
        iter,
        "kill_forget_boundary",
        "forget pause AFTER_KEY_INDEX",
        "IncompleteTransaction; open fail-closed or verify Err",
        &format!("forget: {:?}", err),
        &v,
    );
}

/// One iteration cycles all fault families (9 rows per iter).
fn run_chaos_iteration(iter: u32, base_seed: u64) {
    let seed = base_seed.wrapping_add(u64::from(iter).wrapping_mul(0x9E37_79B9));
    fault_disk_full(iter, seed);
    fault_corrupt_blob(iter, seed.wrapping_add(1));
    fault_clock_skew_merge(iter, seed.wrapping_add(2));
    fault_stale_root(iter, seed.wrapping_add(3));
    fault_forged_root(iter, seed.wrapping_add(4));
    fault_kill_random_boundary(iter, seed.wrapping_add(5));
    fault_kill_merge_boundary(iter, seed.wrapping_add(6));
    fault_forget_kill(iter, seed.wrapping_add(7));
    fault_clock_skew_merge_injected(iter, seed.wrapping_add(8));
}

#[test]
fn chaos_sustained_soak() {
    test_clear_pause();
    let n = iterations_from_env();
    let base_seed = env::var("MNEME_CHAOS_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0xC4A0_5EED_u64);
    eprintln!("chaos_sustained_soak: iterations={n} seed={base_seed}");
    for i in 0..n {
        run_chaos_iteration(i, base_seed);
    }
    eprintln!(
        "chaos_sustained_soak: completed {n} iterations ({} fault rows)",
        n * 9
    );
}

#[test]
fn chaos_smoke_one_each() {
    test_clear_pause();
    run_chaos_iteration(0, 42);
}
