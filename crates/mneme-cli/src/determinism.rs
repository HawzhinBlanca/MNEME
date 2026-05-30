//! Determinism foundation gate (blueprint §17.7): byte-identical roots/receipts across runs.

use mneme_cap::agent_cap;
use mneme_core::{
    Draft, ForgetMode, ForgetTarget, LogicalKey, MemoryKind, MnemeError, Query, Receipt, TrustTier,
};
use mneme_crypto::KeyPair;
use mneme_smt::NonMembershipProof;
use mneme_store::Store;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

const DEFAULT_FIXTURE_OPERATOR_SEED: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunDigest {
    pub head_bytes_hex: String,
    pub root_preimage_hex: String,
    pub receipt_digest_hex: String,
    pub absent_proof_digest_hex: String,
    pub semantic_digest_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundationReport {
    pub timestamp: String,
    pub run_a: RunDigest,
    pub run_b: RunDigest,
    pub byte_identical: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundationVerify {
    pub report_path: String,
    pub verified: bool,
    pub mismatches: Vec<String>,
}

pub fn foundation_gate(
    out: &Path,
    timestamp: &str,
    operator_seed: Option<[u8; 32]>,
) -> Result<FoundationReport, MnemeError> {
    fs::create_dir_all(out).map_err(|e| io_err(out, e))?;
    let operator_seed = operator_seed.unwrap_or(DEFAULT_FIXTURE_OPERATOR_SEED);

    let run_a = build_fixture_run(&out.join("run-a"), operator_seed)?;
    let run_b = build_fixture_run(&out.join("run-b"), operator_seed)?;

    let byte_identical = run_a == run_b;
    let report = FoundationReport {
        timestamp: timestamp.to_string(),
        run_a,
        run_b,
        byte_identical,
    };

    let report_path = out.join("foundation.report.json");
    fs::write(
        &report_path,
        serde_json::to_string_pretty(&report).map_err(|e| io_err(&report_path, e))?,
    )
    .map_err(|e| io_err(&report_path, e))?;

    if !byte_identical {
        return Err(MnemeError::SerializationNonCanonical);
    }
    Ok(report)
}

pub fn foundation_verify(
    report_path: &Path,
    output: &Path,
) -> Result<FoundationVerify, MnemeError> {
    let raw = fs::read_to_string(report_path).map_err(|e| io_err(report_path, e))?;
    let report: FoundationReport =
        serde_json::from_str(&raw).map_err(|e| io_err(report_path, e))?;

    let mut mismatches = Vec::new();
    if report.run_a.head_bytes_hex != report.run_b.head_bytes_hex {
        mismatches.push("head_bytes".into());
    }
    if report.run_a.root_preimage_hex != report.run_b.root_preimage_hex {
        mismatches.push("root_preimage".into());
    }
    if report.run_a.receipt_digest_hex != report.run_b.receipt_digest_hex {
        mismatches.push("receipt".into());
    }
    if report.run_a.absent_proof_digest_hex != report.run_b.absent_proof_digest_hex {
        mismatches.push("absent_proof".into());
    }
    if report.run_a.semantic_digest_hex != report.run_b.semantic_digest_hex {
        mismatches.push("semantic_digest".into());
    }

    let verified = report.byte_identical && mismatches.is_empty();
    let result = FoundationVerify {
        report_path: report_path.display().to_string(),
        verified,
        mismatches,
    };

    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|e| io_err(parent, e))?;
    }
    fs::write(
        output,
        serde_json::to_string_pretty(&result).map_err(|e| io_err(output, e))?,
    )
    .map_err(|e| io_err(output, e))?;

    if !verified {
        return Err(MnemeError::SerializationNonCanonical);
    }
    Ok(result)
}

fn build_fixture_run(dir: &Path, operator_seed: [u8; 32]) -> Result<RunDigest, MnemeError> {
    if dir.exists() {
        fs::remove_dir_all(dir).map_err(|e| io_err(dir, e))?;
    }
    fs::create_dir_all(dir).map_err(|e| io_err(dir, e))?;

    mneme_crypto::enable_fixture_crypto(derive_fixture_seed(
        "mneme.foundation-gate.crypto",
        &operator_seed,
    ));
    let result = build_fixture_run_inner(dir, operator_seed);
    mneme_crypto::disable_fixture_crypto();
    result
}

fn build_fixture_run_inner(dir: &Path, operator_seed: [u8; 32]) -> Result<RunDigest, MnemeError> {
    let operator = KeyPair::from_seed(operator_seed);
    let agent = KeyPair::from_seed(derive_fixture_seed(
        "mneme.foundation-gate.agent",
        &operator_seed,
    ));
    let cap = agent_cap(&operator, agent.public_key_bytes())?;

    let mut store = Store::create(dir, operator.clone())?;
    store
        .trust_mut()
        .authorized_writers
        .push(agent.public_key_bytes());

    let keys: [(&str, &str, &[u8]); 3] = [
        ("fixture", "alpha", b"first entry"),
        ("fixture", "beta", b"second entry"),
        ("fixture", "gamma", b"third entry"),
    ];

    for (ns, name, body) in keys {
        let draft = Draft {
            namespace: ns.into(),
            logical_name: name.into(),
            kind: MemoryKind::Semantic,
            body: body.to_vec(),
            parent_ids: vec![],
            session: [0x42; 16],
            trust_tier: Some(TrustTier::Working),
            embedding: None,
        };
        store.remember(draft, &cap)?;
    }

    let recall_key = LogicalKey {
        namespace: "fixture".into(),
        name: "alpha".into(),
    };
    let query = Query {
        logical_key: recall_key.clone(),
        min_tier: TrustTier::Working,
        embedding: None,
    };
    let recall = store.recall_key_default(&query, &cap)?;
    let receipt_digest = digest_receipt(recall.receipt.as_ref().expect("key receipt"));

    store.forget(
        ForgetTarget::LogicalKey(LogicalKey {
            namespace: "fixture".into(),
            name: "gamma".into(),
        }),
        &cap,
        ForgetMode::Shred,
    )?;

    let absent = store.prove_absent(&LogicalKey {
        namespace: "fixture".into(),
        name: "gamma".into(),
    })?;
    let absent_digest = digest_absent_proof(&absent);

    let (root, _) = store.head()?;
    let head_path = dir.join("roots/HEAD");
    let head_bytes = fs::read(&head_path).map_err(|e| io_err(&head_path, e))?;

    Ok(RunDigest {
        head_bytes_hex: hex::encode(&head_bytes),
        root_preimage_hex: hex::encode(root.preimage_hash),
        receipt_digest_hex: hex::encode(receipt_digest),
        absent_proof_digest_hex: hex::encode(absent_digest),
        semantic_digest_hex: hex::encode(root.semantic_commit),
    })
}

fn digest_receipt(receipt: &Receipt) -> [u8; 32] {
    use blake3::Hasher;
    let mut h = Hasher::new();
    h.update(&receipt.root_bound);
    h.update(&receipt.logical_key);
    h.update(&receipt.object_id);
    h.update(&receipt.key_index_root);
    h.update(&(receipt.leaf_index as u64).to_le_bytes());
    for node in &receipt.membership_proof {
        h.update(node);
    }
    *h.finalize().as_bytes()
}

fn digest_absent_proof(proof: &NonMembershipProof) -> [u8; 32] {
    use blake3::Hasher;
    let mut h = Hasher::new();
    h.update(&proof.key);
    h.update(&proof.root);
    for node in &proof.path {
        h.update(node);
    }
    if let Some((k, v)) = proof.conflicting_leaf {
        h.update(&k);
        h.update(&v);
    }
    *h.finalize().as_bytes()
}

fn derive_fixture_seed(domain: &str, operator_seed: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain.as_bytes());
    hasher.update(operator_seed);
    *hasher.finalize().as_bytes()
}

fn io_err(path: &Path, err: impl std::fmt::Display) -> MnemeError {
    MnemeError::IoFailed {
        path: path.display().to_string(),
        kind: err.to_string(),
    }
}
