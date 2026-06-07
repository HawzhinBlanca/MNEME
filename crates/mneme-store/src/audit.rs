//! Structured audit events for L3 observability (WO-20).

use mneme_core::{ForgetMode, MnemeError};

pub fn emit_verify_recall_rejection(err: &MnemeError, procedure: &str) {
    tracing::warn!(
        target: "mneme.audit",
        event = "verify_recall.rejected",
        error = %err,
        procedure,
        "verified recall rejected (fail-closed)"
    );
}

pub fn emit_promote(root_seq: u64, object_id: &[u8; 32], to_tier: u8) {
    tracing::info!(
        target: "mneme.audit",
        event = "promote.committed",
        root_seq,
        object_id = hex::encode(object_id),
        to_tier,
        "object promoted"
    );
}

pub fn emit_forget(mode: ForgetMode, key_hash: &[u8; 32], root_seq: u64) {
    tracing::info!(
        target: "mneme.audit",
        event = "forget.committed",
        mode = ?mode,
        key_hash = hex::encode(key_hash),
        root_seq,
        "cryptographic forget committed"
    );
}

#[allow(dead_code)]
pub fn emit_sync_peer_dropped(peer: &str, reason: &str) {
    tracing::warn!(
        target: "mneme.audit",
        event = "sync.peer_dropped",
        peer,
        reason,
        "sync peer dropped"
    );
}
