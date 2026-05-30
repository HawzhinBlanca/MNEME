//! Shared fixtures for store-level e2e tests.
#![allow(dead_code)]

use mneme_cap::{Capability, agent_cap, tool_channel_cap};
use mneme_core::{Draft, LogicalKey, MemoryKind};
use mneme_crypto::KeyPair;
use mneme_store::{Store, test_clear_pause};
use tempfile::TempDir;

pub fn theme_key(namespace: &str, name: &str) -> LogicalKey {
    LogicalKey {
        namespace: namespace.into(),
        name: name.into(),
    }
}

pub fn semantic_draft(namespace: &str, name: &str, body: &[u8]) -> Draft {
    Draft {
        namespace: namespace.into(),
        logical_name: name.into(),
        kind: MemoryKind::Semantic,
        body: body.to_vec(),
        parent_ids: vec![],
        session: [0x42; 16],
        trust_tier: None,
        embedding: None,
    }
}

pub fn semantic_draft_with_embedding(
    namespace: &str,
    name: &str,
    body: &[u8],
    embedding: mneme_core::FixedPointEmbedding,
) -> Draft {
    Draft {
        namespace: namespace.into(),
        logical_name: name.into(),
        kind: MemoryKind::Semantic,
        body: body.to_vec(),
        parent_ids: vec![],
        session: [0x42; 16],
        trust_tier: None,
        embedding: Some(embedding),
    }
}

pub fn agent_store() -> (Store, Capability, TempDir) {
    test_clear_pause();
    let dir = tempfile::tempdir().expect("tempdir");
    let operator = KeyPair::generate();
    let agent = KeyPair::generate();
    let cap = agent_cap(&operator, agent.public_key_bytes()).expect("agent cap");
    let mut store = Store::create(dir.path(), operator).expect("create");
    store.trust_mut().authorized_writers.push(cap.subject);
    (store, cap, dir)
}

pub fn tool_store() -> (Store, Capability, TempDir) {
    test_clear_pause();
    let dir = tempfile::tempdir().expect("tempdir");
    let operator = KeyPair::generate();
    let tool_agent = KeyPair::generate();
    let cap = tool_channel_cap(&operator, tool_agent.public_key_bytes()).expect("tool cap");
    let mut store = Store::create(dir.path(), operator).expect("create");
    store.trust_mut().authorized_writers.push(cap.subject);
    (store, cap, dir)
}
