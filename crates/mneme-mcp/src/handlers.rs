//! Tool handlers — testable without MCP transport (blueprint §14.1).

use mneme_cap::Capability;
use mneme_core::{
    Draft, Entry, ForgetMode, ForgetProof, ForgetTarget, LogicalKey, MemoryKind, MnemeError, Query,
    TrustTier, encode_forget_proof,
};
use mneme_store::Store;
use mneme_verify::RootReport;
use std::sync::{Arc, Mutex};

/// Tool-channel writes must live under `tools/` (§13.4 NamespacePrefix caveat).
pub fn normalize_tool_namespace(namespace: &str) -> String {
    let ns = namespace.trim();
    if ns.is_empty() || ns == "tools" {
        return "tools/mcp".into();
    }
    if ns.starts_with("tools/") {
        return ns.to_string();
    }
    format!("tools/{ns}")
}

/// Maximum bytes for an agent-supplied logical-key field (namespace / name).
/// The logical key is stored verbatim in the `object_keys` sidecar, so an
/// unbounded field would bloat it; 4 KiB is far above any realistic key while
/// still bounding a single malformed/abusive `record` call. Fails closed
/// (`SchemaDrift`) rather than silently storing a multi-megabyte key.
const MAX_LOGICAL_KEY_FIELD_BYTES: usize = 4096;

fn validate_logical_key_field(value: &str) -> Result<(), MnemeError> {
    if value.len() > MAX_LOGICAL_KEY_FIELD_BYTES {
        return Err(MnemeError::SchemaDrift);
    }
    Ok(())
}

/// MCP memory tool backend: tool-channel writes, verified reads only.
pub struct MemoryHandlers {
    store: Arc<Mutex<Store>>,
    /// Tool channel (§13.4): quarantine default, no Promote.
    write_cap: Capability,
    /// Recall/forget gate: permits reads at declared min_tier.
    read_cap: Capability,
}

impl MemoryHandlers {
    pub fn new(store: Arc<Mutex<Store>>, write_cap: Capability, read_cap: Capability) -> Self {
        Self {
            store,
            write_cap,
            read_cap,
        }
    }

    pub fn store(&self) -> &Arc<Mutex<Store>> {
        &self.store
    }

    pub fn write_cap(&self) -> &Capability {
        &self.write_cap
    }

    pub fn read_cap(&self) -> &Capability {
        &self.read_cap
    }

    /// `record-with-provenance` — always via tool-channel capability (quarantine tier).
    pub fn record_with_provenance(
        &self,
        content: &[u8],
        kind: MemoryKind,
        namespace: &str,
        name: &str,
        session: [u8; 16],
    ) -> Result<RecordWithProvenanceResult, MnemeError> {
        if name.trim().is_empty() {
            return Err(MnemeError::SchemaDrift);
        }
        validate_logical_key_field(namespace)?;
        validate_logical_key_field(name)?;
        let namespace = normalize_tool_namespace(namespace);
        let draft = Draft {
            namespace,
            logical_name: name.to_string(),
            kind,
            body: content.to_vec(),
            parent_ids: vec![],
            session,
            trust_tier: None,
            embedding: None,
            valid_time_ms: None,
        };
        let mut store = self.store.lock().map_err(|_| MnemeError::CapDenied)?;
        #[cfg(feature = "phase_iii_bind")]
        let (id, root) = {
            let action_receipt =
                Self::optional_action_receipt_for_remember(&store, &draft, &self.write_cap)?;
            store.remember_with_action(draft, &self.write_cap, action_receipt.as_ref())?
        };
        #[cfg(not(feature = "phase_iii_bind"))]
        let (id, root) = store.remember(draft, &self.write_cap)?;
        Ok(RecordWithProvenanceResult {
            object_id_hex: hex::encode(id.as_bytes()),
            root_hash_hex: hex::encode(root.preimage_hash),
            root: RootEvidence::from_root(&root),
            trust_tier: self.write_cap.default_tier().as_u8(),
        })
    }

    /// `recall-with-signed-chain` — **only** `recall_verified` (INV-5); never returns unverified bytes.
    pub fn recall_with_signed_chain(
        &self,
        namespace: &str,
        name: &str,
        min_tier: TrustTier,
    ) -> Result<RecallWithSignedChainResult, MnemeError> {
        validate_logical_key_field(namespace)?;
        validate_logical_key_field(name)?;
        let query = Query {
            logical_key: LogicalKey {
                namespace: normalize_tool_namespace(namespace),
                name: name.to_string(),
            },
            min_tier,
            embedding: None,
        };
        let store = self.store.lock().map_err(|_| MnemeError::CapDenied)?;
        let entries = store.recall_verified_default(&query, &self.read_cap)?;
        let root = store.current_root()?;
        Ok(RecallWithSignedChainResult {
            root_hash_hex: hex::encode(root.preimage_hash),
            root: RootEvidence::from_root(&root),
            entries: entries.into_iter().map(RecallEntry::from_entry).collect(),
        })
    }

    /// `erase-with-receipt-and-proof-of-absence` — shred + tombstone + ForgetProof + SMT absence proof.
    pub fn erase_with_receipt_and_proof_of_absence(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<EraseWithReceiptAndProofOfAbsenceResult, MnemeError> {
        let logical_key = LogicalKey {
            namespace: normalize_tool_namespace(namespace),
            name: name.to_string(),
        };
        let target = ForgetTarget::LogicalKey(logical_key.clone());
        let mut store = self.store.lock().map_err(|_| MnemeError::CapDenied)?;
        let action_receipt = Self::optional_action_receipt_for_forget(
            &store,
            &target,
            ForgetMode::Shred,
            &self.read_cap,
        )?;
        let proven = store.forget_with_proof(
            target,
            &self.read_cap,
            ForgetMode::Shred,
            action_receipt.as_ref(),
        )?;
        let absence_proof = store.prove_absent(&logical_key)?;
        Ok(EraseWithReceiptAndProofOfAbsenceResult {
            root_hash_hex: hex::encode(proven.root.preimage_hash),
            root: RootEvidence::from_root(&proven.root),
            forget_proof: ForgetProofEvidence::from_proof(&proven.proof)?,
            absence_proof: AbsenceProofEvidence::from_proof(&absence_proof),
        })
    }

    /// `verify` — run the fail-closed store verifier and return the verified root.
    pub fn verify(&self) -> Result<VerifyResult, MnemeError> {
        let store = self.store.lock().map_err(|_| MnemeError::CapDenied)?;
        let report = store.verify_current()?;
        Ok(VerifyResult::from_report(report))
    }

    #[cfg(feature = "phase_iii_bind")]
    fn optional_action_receipt_for_remember(
        store: &Store,
        draft: &Draft,
        cap: &Capability,
    ) -> Result<Option<mneme_core::ActionReceipt>, MnemeError> {
        let commit = mneme_store::action_commit_remember(draft);
        let receipt = store.bind_external_action(commit, cap, store.operator_keypair(), None)?;
        Ok(Some(receipt))
    }

    #[cfg(feature = "phase_iii_bind")]
    fn optional_action_receipt_for_forget(
        store: &Store,
        target: &ForgetTarget,
        mode: ForgetMode,
        cap: &Capability,
    ) -> Result<Option<mneme_core::ActionReceipt>, MnemeError> {
        let commit = mneme_store::action_commit_forget(target, mode);
        let receipt = store.bind_external_action(commit, cap, store.operator_keypair(), None)?;
        Ok(Some(receipt))
    }

    #[cfg(not(feature = "phase_iii_bind"))]
    fn optional_action_receipt_for_forget(
        _store: &Store,
        _target: &ForgetTarget,
        _mode: ForgetMode,
        _cap: &Capability,
    ) -> Result<Option<mneme_core::ActionReceipt>, MnemeError> {
        Ok(None)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RootEvidence {
    pub root_hash_hex: String,
    pub root_signature_hex: String,
    pub sequence: u64,
    pub key_index_root_hex: String,
    pub dag_head_root_hex: String,
    pub prev_root_hex: String,
}

impl RootEvidence {
    fn from_root(root: &mneme_core::Root) -> Self {
        Self {
            root_hash_hex: hex::encode(root.preimage_hash),
            root_signature_hex: hex::encode(&root.signature),
            sequence: root.sequence,
            key_index_root_hex: hex::encode(root.key_index_root),
            dag_head_root_hex: hex::encode(root.dag_head_root),
            prev_root_hex: hex::encode(root.prev_root),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RecordWithProvenanceResult {
    pub object_id_hex: String,
    pub root_hash_hex: String,
    pub root: RootEvidence,
    pub trust_tier: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RecallWithSignedChainResult {
    pub entries: Vec<RecallEntry>,
    pub root_hash_hex: String,
    pub root: RootEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RecallEntry {
    pub object_id_hex: String,
    pub body: String,
    pub trust_tier: u8,
}

impl RecallEntry {
    fn from_entry(e: Entry) -> Self {
        Self {
            object_id_hex: hex::encode(e.id.as_bytes()),
            body: String::from_utf8_lossy(&e.plaintext).into_owned(),
            trust_tier: e.record.trust_tier,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AbsenceProofEvidence {
    pub key_hash_hex: String,
    pub root_hex: String,
    pub path_len: usize,
    pub conflicting_leaf_key_hex: Option<String>,
    pub conflicting_leaf_value_hex: Option<String>,
}

impl AbsenceProofEvidence {
    fn from_proof(proof: &mneme_smt::NonMembershipProof) -> Self {
        let (conflicting_leaf_key_hex, conflicting_leaf_value_hex) = proof
            .conflicting_leaf
            .map(|(key, value)| (hex::encode(key), hex::encode(value)))
            .map_or((None, None), |(key, value)| (Some(key), Some(value)));
        Self {
            key_hash_hex: hex::encode(proof.key),
            root_hex: hex::encode(proof.root),
            path_len: proof.path.len(),
            conflicting_leaf_key_hex,
            conflicting_leaf_value_hex,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ForgetProofEvidence {
    pub version: u16,
    pub target_commit_hex: String,
    pub mode: &'static str,
    pub shred_commit_hex: String,
    pub root_bound_hex: String,
    pub absence_path_len: usize,
    pub cognition_cert_commit_hex: Option<String>,
    pub wire_hex: String,
}

impl ForgetProofEvidence {
    fn from_proof(proof: &ForgetProof) -> Result<Self, MnemeError> {
        let wire = encode_forget_proof(proof)?;
        Ok(Self {
            version: proof.version,
            target_commit_hex: hex::encode(proof.target_commit),
            mode: match proof.mode {
                ForgetMode::Shred => "shred",
                ForgetMode::Redact => "redact",
            },
            shred_commit_hex: hex::encode(proof.shred_commit),
            root_bound_hex: hex::encode(proof.root_bound),
            absence_path_len: proof.absence_path.len(),
            cognition_cert_commit_hex: proof.cognition_cert_commit.map(hex::encode),
            wire_hex: hex::encode(wire),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct EraseWithReceiptAndProofOfAbsenceResult {
    pub root_hash_hex: String,
    pub root: RootEvidence,
    pub forget_proof: ForgetProofEvidence,
    pub absence_proof: AbsenceProofEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct VerifyResult {
    pub root_hash_hex: String,
    pub root: RootEvidence,
    pub object_count: usize,
}

impl VerifyResult {
    fn from_report(report: RootReport) -> Self {
        Self {
            root_hash_hex: hex::encode(report.root.preimage_hash),
            root: RootEvidence::from_root(&report.root),
            object_count: report.object_count,
        }
    }
}

pub fn parse_kind(s: &str) -> Result<MemoryKind, MnemeError> {
    match s.to_ascii_lowercase().as_str() {
        "episodic" => Ok(MemoryKind::Episodic),
        "semantic" => Ok(MemoryKind::Semantic),
        "procedural" => Ok(MemoryKind::Procedural),
        "working" => Ok(MemoryKind::Working),
        "identity" => Ok(MemoryKind::Identity),
        _ => Err(MnemeError::SchemaDrift),
    }
}

pub fn parse_min_tier(s: &str) -> Result<TrustTier, MnemeError> {
    match s.to_ascii_lowercase().as_str() {
        "quarantine" => Ok(TrustTier::Quarantine),
        "working" => Ok(TrustTier::Working),
        "trusted" => Ok(TrustTier::Trusted),
        "identity" => Ok(TrustTier::Identity),
        _ => Err(MnemeError::SchemaDrift),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logical_key_field_within_limit_ok() {
        assert!(validate_logical_key_field("agent/instruction").is_ok());
        assert!(validate_logical_key_field(&"x".repeat(MAX_LOGICAL_KEY_FIELD_BYTES)).is_ok());
    }

    #[test]
    fn logical_key_field_over_limit_fails_closed() {
        let too_long = "x".repeat(MAX_LOGICAL_KEY_FIELD_BYTES + 1);
        assert_eq!(
            validate_logical_key_field(&too_long).unwrap_err(),
            MnemeError::SchemaDrift
        );
    }
}
