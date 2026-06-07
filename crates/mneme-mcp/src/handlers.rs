//! Tool handlers — testable without MCP transport (blueprint §14.1).

use mneme_cap::Capability;
use mneme_core::{
    Draft, Entry, ForgetMode, ForgetTarget, LogicalKey, MemoryKind, MnemeError, Query, TrustTier,
};
use mneme_store::Store;
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum McpHandlerFailure {
    EmptyLogicalName,
    UnknownMemoryKind,
    UnknownTrustTier,
}

fn mcp_handler_failure_to_mneme(failure: McpHandlerFailure) -> MnemeError {
    match failure {
        McpHandlerFailure::EmptyLogicalName
        | McpHandlerFailure::UnknownMemoryKind
        | McpHandlerFailure::UnknownTrustTier => MnemeError::SchemaDrift,
    }
}

fn empty_logical_name_error() -> MnemeError {
    mcp_handler_failure_to_mneme(McpHandlerFailure::EmptyLogicalName)
}

fn unknown_memory_kind_error() -> MnemeError {
    mcp_handler_failure_to_mneme(McpHandlerFailure::UnknownMemoryKind)
}

fn unknown_trust_tier_error() -> MnemeError {
    mcp_handler_failure_to_mneme(McpHandlerFailure::UnknownTrustTier)
}

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

    /// `memory.remember` — always via tool-channel capability (quarantine tier).
    pub fn remember(
        &self,
        content: &[u8],
        kind: MemoryKind,
        namespace: &str,
        name: &str,
        session: [u8; 16],
    ) -> Result<RememberResult, MnemeError> {
        if name.trim().is_empty() {
            return Err(empty_logical_name_error());
        }
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
        let action_receipt =
            Self::optional_action_receipt_for_remember(&store, &draft, &self.write_cap)?;
        let (id, root) =
            store.remember_with_action(draft, &self.write_cap, action_receipt.as_ref())?;
        Ok(RememberResult {
            object_id_hex: hex::encode(id.as_bytes()),
            root_hash_hex: hex::encode(root.preimage_hash),
            trust_tier: self.write_cap.default_tier().as_u8(),
        })
    }

    /// `memory.recall` — **only** `recall_verified` (INV-5); never returns unverified bytes.
    pub fn recall(
        &self,
        namespace: &str,
        name: &str,
        min_tier: TrustTier,
    ) -> Result<Vec<RecallEntry>, MnemeError> {
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
        Ok(entries.into_iter().map(RecallEntry::from_entry).collect())
    }

    /// `memory.forget` — shred + tombstone.
    pub fn forget(&self, namespace: &str, name: &str) -> Result<ForgetResult, MnemeError> {
        let target = ForgetTarget::LogicalKey(LogicalKey {
            namespace: normalize_tool_namespace(namespace),
            name: name.to_string(),
        });
        let mut store = self.store.lock().map_err(|_| MnemeError::CapDenied)?;
        let action_receipt = Self::optional_action_receipt_for_forget(
            &store,
            &target,
            ForgetMode::Shred,
            &self.read_cap,
        )?;
        let (_, root) = store.forget_with_action(
            target,
            &self.read_cap,
            ForgetMode::Shred,
            action_receipt.as_ref(),
        )?;
        Ok(ForgetResult {
            root_hash_hex: hex::encode(root.preimage_hash),
        })
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

    #[cfg(not(feature = "phase_iii_bind"))]
    fn optional_action_receipt_for_remember(
        _store: &Store,
        _draft: &Draft,
        _cap: &Capability,
    ) -> Result<Option<mneme_core::ActionReceipt>, MnemeError> {
        Ok(None)
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
pub struct RememberResult {
    pub object_id_hex: String,
    pub root_hash_hex: String,
    pub trust_tier: u8,
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
pub struct ForgetResult {
    pub root_hash_hex: String,
}

pub fn parse_kind(s: &str) -> Result<MemoryKind, MnemeError> {
    match s.to_ascii_lowercase().as_str() {
        "episodic" => Ok(MemoryKind::Episodic),
        "semantic" => Ok(MemoryKind::Semantic),
        "procedural" => Ok(MemoryKind::Procedural),
        "working" => Ok(MemoryKind::Working),
        "identity" => Ok(MemoryKind::Identity),
        _ => Err(unknown_memory_kind_error()),
    }
}

pub fn parse_min_tier(s: &str) -> Result<TrustTier, MnemeError> {
    match s.to_ascii_lowercase().as_str() {
        "quarantine" => Ok(TrustTier::Quarantine),
        "working" => Ok(TrustTier::Working),
        "trusted" => Ok(TrustTier::Trusted),
        "identity" => Ok(TrustTier::Identity),
        _ => Err(unknown_trust_tier_error()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handlers_production_source() -> &'static str {
        include_str!("handlers.rs")
            .split_once("#[cfg(test)]")
            .map(|(production, _tests)| production)
            .expect("handlers.rs should keep tests after production code")
    }

    #[test]
    fn mcp_handler_failures_are_classified_not_schema_drift_collapsed() {
        let production = handlers_production_source();

        for forbidden in [
            "return Err(MnemeError::SchemaDrift)",
            "_ => Err(MnemeError::SchemaDrift)",
            "map_err(|_| MnemeError::SchemaDrift)",
            "ok_or(MnemeError::SchemaDrift)",
        ] {
            assert!(
                !production.contains(forbidden),
                "MCP handler production code still collapses directly through {forbidden}"
            );
        }

        for required in [
            "enum McpHandlerFailure",
            "fn mcp_handler_failure_to_mneme(",
            "fn empty_logical_name_error(",
            "fn unknown_memory_kind_error(",
            "fn unknown_trust_tier_error(",
            "McpHandlerFailure::EmptyLogicalName",
            "McpHandlerFailure::UnknownMemoryKind",
            "McpHandlerFailure::UnknownTrustTier",
        ] {
            assert!(
                production.contains(required),
                "MCP handler production code is missing typed classifier marker {required}"
            );
        }
    }

    #[test]
    fn mcp_handler_failure_classifier_preserves_public_schema_drift() {
        for failure in [
            McpHandlerFailure::EmptyLogicalName,
            McpHandlerFailure::UnknownMemoryKind,
            McpHandlerFailure::UnknownTrustTier,
        ] {
            assert_eq!(
                mcp_handler_failure_to_mneme(failure),
                MnemeError::SchemaDrift
            );
        }
        assert_eq!(empty_logical_name_error(), MnemeError::SchemaDrift);
        assert_eq!(unknown_memory_kind_error(), MnemeError::SchemaDrift);
        assert_eq!(unknown_trust_tier_error(), MnemeError::SchemaDrift);
    }

    #[test]
    fn mcp_handler_parsers_reject_unknown_values_fail_closed() {
        assert_eq!(parse_kind("archive").err(), Some(MnemeError::SchemaDrift));
        assert_eq!(
            parse_min_tier("superuser").err(),
            Some(MnemeError::SchemaDrift)
        );
    }
}
