//! Chaos harness helpers — post-fault safety checks and structured logging.

use mneme_cap::agent_cap;
use mneme_core::{Query, TrustTier};
use mneme_crypto::KeyPair;
use mneme_index::default_key_procedure;
use mneme_store::Store;
use mneme_verify::verify_store;
use serde::Serialize;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

#[derive(Debug, Clone, Serialize)]
pub struct ChaosRow {
    pub iter: u32,
    pub fault: String,
    pub injection_point: String,
    pub expected: String,
    pub actual: String,
    pub verify_result: String,
    pub incomplete: bool,
    pub open_result: String,
    pub unsafe_state: bool,
    pub unsafe_reason: String,
}

pub fn emit_row(row: &ChaosRow) {
    let json = serde_json::to_string(row).expect("chaos row json");
    println!("CHAOS_ROW|{json}");
}

pub struct FaultStore {
    pub dir: TempDir,
    pub operator: KeyPair,
    pub cap: mneme_cap::Capability,
    pub trust: mneme_crypto::TrustConfig,
    pub golden_key: mneme_core::LogicalKey,
    pub golden_body: Vec<u8>,
}

impl FaultStore {
    pub fn fresh(seed: u64) -> Self {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let dir = tempfile::tempdir().expect("tempdir");
        let operator = KeyPair::generate();
        let agent = KeyPair::generate();
        let cap = agent_cap(&operator, agent.public_key_bytes()).expect("cap");
        let mut store = Store::create(dir.path(), operator.clone()).expect("create");
        store.trust_mut().authorized_writers.push(cap.subject);
        let trust = store.trust().clone();
        let ns = format!("chaos-{}", seed % 10_000);
        let name = format!("key-{}", rng.gen_range(0..u16::MAX));
        let golden_key = mneme_core::LogicalKey {
            namespace: ns.clone(),
            name: name.clone(),
        };
        let golden_body = b"golden-chaos-payload".to_vec();
        let draft = mneme_core::Draft {
            namespace: ns,
            logical_name: name,
            kind: mneme_core::MemoryKind::Semantic,
            body: golden_body.clone(),
            parent_ids: vec![],
            session: [0x01; 16],
            trust_tier: None,
            embedding: None,
        };
        store.remember(draft, &cap).expect("seed remember");
        drop(store);
        Self {
            dir,
            operator,
            cap,
            trust,
            golden_key,
            golden_body,
        }
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }
}

#[derive(Debug, Default)]
pub struct PostFaultVerdict {
    pub verify_result: String,
    pub incomplete: bool,
    pub open_result: String,
    pub recall_result: String,
    pub verify_panicked: bool,
    pub open_panicked: bool,
    pub recall_panicked: bool,
    pub recall_plaintext: Option<Vec<u8>>,
    pub unsafe_state: bool,
    pub unsafe_reason: String,
}

pub struct ChaosTarget<'a> {
    pub path: &'a Path,
    pub operator: &'a KeyPair,
    pub cap: &'a mneme_cap::Capability,
    pub trust: &'a mneme_crypto::TrustConfig,
    pub golden_key: mneme_core::LogicalKey,
    pub golden_body: Vec<u8>,
}

#[allow(clippy::too_many_arguments)] // test helper: explicit golden-recall fixture params
pub fn post_fault_checks_at(
    path: &Path,
    operator: &KeyPair,
    cap: &mneme_cap::Capability,
    trust: &mneme_crypto::TrustConfig,
    golden_ns: &str,
    golden_name: &str,
    golden_body: &[u8],
    expect_golden_recall: bool,
) -> PostFaultVerdict {
    let target = ChaosTarget {
        path,
        operator,
        cap,
        trust,
        golden_key: mneme_core::LogicalKey {
            namespace: golden_ns.into(),
            name: golden_name.into(),
        },
        golden_body: golden_body.to_vec(),
    };
    post_fault_checks_inner(&target, expect_golden_recall)
}

pub fn post_fault_checks(fs: &FaultStore, expect_golden_recall: bool) -> PostFaultVerdict {
    let target = ChaosTarget {
        path: fs.path(),
        operator: &fs.operator,
        cap: &fs.cap,
        trust: &fs.trust,
        golden_key: fs.golden_key.clone(),
        golden_body: fs.golden_body.clone(),
    };
    post_fault_checks_inner(&target, expect_golden_recall)
}

fn post_fault_checks_inner(
    target: &ChaosTarget<'_>,
    expect_golden_recall: bool,
) -> PostFaultVerdict {
    let mut v = PostFaultVerdict {
        incomplete: target.path.join(".incomplete").exists(),
        ..Default::default()
    };

    let trust = target.trust;
    let verify_out = catch_unwind(AssertUnwindSafe(|| verify_store(target.path, trust)));
    match verify_out {
        Err(_) => {
            v.verify_panicked = true;
            v.verify_result = "PANIC".into();
        }
        Ok(Ok(_)) => v.verify_result = "Ok".into(),
        Ok(Err(e)) => v.verify_result = format!("Err({e})"),
    }

    let op = target.operator.clone();
    let open_out = catch_unwind(AssertUnwindSafe(|| Store::open(target.path, op)));
    match open_out {
        Err(_) => {
            v.open_panicked = true;
            v.open_result = "PANIC".into();
        }
        Ok(Ok(mut store)) => {
            v.open_result = "Ok".into();
            store
                .trust_mut()
                .authorized_writers
                .push(target.cap.subject);
            let query = Query {
                logical_key: target.golden_key.clone(),
                min_tier: TrustTier::Working,
                embedding: None,
            };
            let recall_out = catch_unwind(AssertUnwindSafe(|| {
                store.recall_verified(&query, &default_key_procedure(), target.cap)
            }));
            match recall_out {
                Err(_) => {
                    v.recall_panicked = true;
                    v.recall_result = "PANIC".into();
                }
                Ok(Ok(entries)) => {
                    v.recall_result = "Ok".into();
                    v.recall_plaintext = entries.first().map(|e| e.plaintext.clone());
                }
                Ok(Err(e)) => v.recall_result = format!("Err({e})"),
            }
        }
        Ok(Err(e)) => v.open_result = format!("Err({e})"),
    }

    if v.verify_panicked || v.open_panicked || v.recall_panicked {
        v.unsafe_state = true;
        v.unsafe_reason = "verifier or store path panicked (TCB violation)".into();
    }

    if expect_golden_recall {
        match &v.recall_plaintext {
            Some(p) if p != &target.golden_body => {
                v.unsafe_state = true;
                v.unsafe_reason = "recall_verified returned wrong plaintext".into();
            }
            None if v.recall_result.starts_with("Ok") => {
                v.unsafe_state = true;
                v.unsafe_reason = "recall_verified Ok with empty entries".into();
            }
            _ => {}
        }
    }

    v
}

pub fn corrupt_random_artifact(store_path: &Path, seed: u64) -> (String, PathBuf) {
    use rand::{Rng, SeedableRng};
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let candidates = collect_artifacts(store_path);
    if candidates.is_empty() {
        let p = store_path.join("roots/HEAD");
        flip_byte(&p, 0);
        return ("roots/HEAD (fallback)".into(), p);
    }
    let idx = rng.gen_range(0..candidates.len());
    let p = candidates[idx].clone();
    let off = rng.gen_range(0..8);
    flip_byte(&p, off);
    (
        p.strip_prefix(store_path)
            .unwrap_or(&p)
            .display()
            .to_string(),
        p,
    )
}

fn collect_artifacts(store_path: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for rel in ["roots/HEAD", "meta/key_index.json", "meta/object_keys.json"] {
        let p = store_path.join(rel);
        if p.is_file() {
            out.push(p);
        }
    }
    if let Ok(entries) = std::fs::read_dir(store_path.join("objects")) {
        for prefix in entries.flatten() {
            if let Ok(shard) = std::fs::read_dir(prefix.path()) {
                for obj in shard.flatten() {
                    let p = obj.path();
                    if p.is_file() {
                        out.push(p);
                    }
                }
            }
        }
    }
    out
}

fn flip_byte(path: &Path, offset: usize) {
    let mut data = std::fs::read(path).expect("read artifact");
    if data.is_empty() {
        data.push(0xff);
    } else {
        let len = data.len();
        data[offset % len] ^= 0x55;
    }
    std::fs::write(path, data).expect("write corrupt");
}

pub fn set_readonly_tree(path: &Path) {
    readonly_dir(path);
}

pub fn clear_readonly_tree(path: &Path) {
    writable_dir(path);
}

fn readonly_dir(dir: &Path) {
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            readonly_dir(&entry.path());
        }
    }
    let mut perms = std::fs::metadata(dir).expect("meta").permissions();
    perms.set_readonly(true);
    let _ = std::fs::set_permissions(dir, perms);
}

// Test-only: deliberately restore writability so the readonly fault tree can be
// cleaned up by the tempdir guard. World-writability inside a throwaway temp dir
// is acceptable here; the lint guards production code, not chaos fixtures.
#[allow(clippy::permissions_set_readonly_false)]
fn writable_dir(dir: &Path) {
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            writable_dir(&entry.path());
        }
    }
    let mut perms = std::fs::metadata(dir).expect("meta").permissions();
    perms.set_readonly(false);
    let _ = std::fs::set_permissions(dir, perms);
}
