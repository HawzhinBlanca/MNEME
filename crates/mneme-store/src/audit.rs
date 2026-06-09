//! Structured audit events for L3 observability (WO-20, blueprint §15.4).
//!
//! Events use the shared `mneme.audit` tracing target with stable `event` field
//! names so operators can filter or export them to OpenTelemetry collectors.

use mneme_core::{ForgetMode, MnemeError};

/// Tracing target for all L3 audit events; consumed by mnemed OTLP export.
pub const AUDIT_TARGET: &str = "mneme.audit";

pub fn emit_verify_recall_rejection(err: &MnemeError, procedure: &str) {
    tracing::event!(
        target: AUDIT_TARGET,
        tracing::Level::WARN,
        event = "verify_recall.rejected",
        error = %err,
        procedure,
        "verified recall rejected (fail-closed)"
    );
}

pub fn emit_promote(root_seq: u64, object_id: &[u8; 32], to_tier: u8) {
    tracing::event!(
        target: AUDIT_TARGET,
        tracing::Level::INFO,
        event = "promote.committed",
        root_seq,
        object_id = hex::encode(object_id),
        to_tier,
        "object promoted"
    );
}

pub fn emit_forget(mode: ForgetMode, key_hash: &[u8; 32], root_seq: u64) {
    tracing::event!(
        target: AUDIT_TARGET,
        tracing::Level::INFO,
        event = "forget.committed",
        mode = ?mode,
        key_hash = hex::encode(key_hash),
        root_seq,
        "cryptographic forget committed"
    );
}
