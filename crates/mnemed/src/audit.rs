//! Daemon-local structured audit events for L3 observability (WO-20).

use mneme_store::AUDIT_TARGET;

pub(crate) const SYNC_WEBSOCKET_SERVER_PEER: &str = "sync-websocket-client";

pub(crate) fn emit_sync_peer_dropped(peer: &str, reason: &str) {
    tracing::event!(
        target: AUDIT_TARGET,
        tracing::Level::WARN,
        event = "sync.peer_dropped",
        peer,
        reason,
        "sync peer dropped"
    );
}
