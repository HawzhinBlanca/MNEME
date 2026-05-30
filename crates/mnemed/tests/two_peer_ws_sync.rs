//! F-G: two `mnemed` daemons converge their authenticated memory state by
//! exchanging §11 object snapshots over a REAL WebSocket (not a same-host file
//! path). Each peer fetches the other's `SyncSnapshot`, re-hashes every object on
//! ingest (A-NET defense), and merges via the verified CRDT path. Convergence is
//! asserted on the authenticated content roots (`key_index_root`, `dag_head_root`)
//! — the signed `preimage_hash` legitimately differs because each peer keeps its
//! own operator key, HLC, and checkpoint chain.

use futures_util::{SinkExt, StreamExt};
use mneme_cap::{Capability, agent_cap};
use mneme_core::{Draft, LogicalKey, MemoryKind};
use mneme_crypto::KeyPair;
use mnemed::state::RateLimiter;
use mnemed::{AppState, RunningServer, ServerConfig, start_with_state};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

fn remember(state: &AppState, ns: &str, name: &str, body: &[u8], cap: &Capability) {
    let mut store = state.store.lock().expect("lock");
    store
        .remember(
            Draft {
                namespace: ns.into(),
                logical_name: name.into(),
                kind: MemoryKind::Episodic,
                body: body.to_vec(),
                parent_ids: vec![],
                session: [0x01; 16],
                trust_tier: None,
                embedding: None,
            },
            cap,
        )
        .expect("remember");
}

fn build_peer(operator: &KeyPair, cap: &Capability) -> (AppState, TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = mneme_store::Store::create(dir.path(), operator.clone()).expect("create");
    store.trust_mut().authorized_writers.push(cap.subject);
    let state = AppState {
        store: Arc::new(Mutex::new(store)),
        operator: Arc::new(operator.clone()),
        rate_limit: Arc::new(Mutex::new(RateLimiter::new(1000))),
    };
    (state, dir)
}

async fn serve(state: AppState) -> RunningServer {
    let config = ServerConfig {
        http_addr: "127.0.0.1:0".parse().unwrap(),
        grpc_addr: None,
        rate_limit_per_minute: 1000,
    };
    start_with_state(config, state).await.expect("start")
}

/// Pull the peer daemon's snapshot over WebSocket and merge it into `local`.
async fn pull_and_merge(local: &AppState, peer: &RunningServer) {
    let url = format!("ws://{}/v1/sync", peer.http_addr);
    let (mut ws, _) = connect_async(&url).await.expect("ws connect");
    ws.send(Message::Binary(
        mnemed::sync::encode_snapshot_request().into(),
    ))
    .await
    .expect("send req");
    let frame = loop {
        match ws.next().await.expect("frame").expect("ok") {
            Message::Binary(data) => break data,
            _ => continue,
        }
    };
    let snapshot = mnemed::sync::decode_snapshot(&frame).expect("decode snapshot");
    let mut store = local.store.lock().expect("lock");
    store
        .merge_from_snapshot(&snapshot)
        .expect("merge snapshot");
}

#[tokio::test]
async fn two_daemons_converge_over_websocket() {
    let operator = KeyPair::from_seed([0x42; 32]);
    let cap = agent_cap(&operator, operator.public_key_bytes()).expect("cap");

    let (state_a, _da) = build_peer(&operator, &cap);
    let (state_b, _db) = build_peer(&operator, &cap);
    remember(&state_a, "peer", "only-a", b"alpha", &cap);
    remember(&state_b, "peer", "only-b", b"beta", &cap);

    let server_a = serve(state_a.clone()).await;
    let server_b = serve(state_b.clone()).await;

    // A pulls B (now holds the union); then B pulls the updated A.
    pull_and_merge(&state_a, &server_b).await;
    pull_and_merge(&state_b, &server_a).await;

    let key_a = LogicalKey {
        namespace: "peer".into(),
        name: "only-a".into(),
    };
    let key_b = LogicalKey {
        namespace: "peer".into(),
        name: "only-b".into(),
    };

    let (root_a, root_b) = {
        let sa = state_a.store.lock().unwrap();
        let sb = state_b.store.lock().unwrap();
        // Each peer can prove membership of BOTH keys after wire sync.
        assert!(sa.prove_membership(&key_a).is_ok(), "A has only-a");
        assert!(
            sa.prove_membership(&key_b).is_ok(),
            "A received only-b over the wire"
        );
        assert!(
            sb.prove_membership(&key_a).is_ok(),
            "B received only-a over the wire"
        );
        assert!(sb.prove_membership(&key_b).is_ok(), "B has only-b");
        (sa.current_root().unwrap(), sb.current_root().unwrap())
    };

    assert_eq!(
        root_a.key_index_root, root_b.key_index_root,
        "key-index roots converge after WebSocket anti-entropy"
    );
    assert_eq!(
        root_a.dag_head_root, root_b.dag_head_root,
        "DAG head roots converge after WebSocket anti-entropy"
    );

    server_a.shutdown().await;
    server_b.shutdown().await;
}

/// A-NET: a snapshot whose object bytes were mutated in transit must NOT be
/// ingested — the recomputed content hash no longer matches the MST leaf id, so
/// the merge silently drops the forged object and the forged key never appears.
#[tokio::test]
async fn wire_object_tamper_is_not_ingested() {
    let operator = KeyPair::from_seed([0x42; 32]);
    let cap = agent_cap(&operator, operator.public_key_bytes()).expect("cap");
    let (state_a, _da) = build_peer(&operator, &cap);
    let (state_b, _db) = build_peer(&operator, &cap);
    remember(&state_b, "peer", "only-b", b"beta", &cap);

    let mut snapshot = state_b.store.lock().unwrap().export_sync_snapshot();
    // Tamper a transferred object blob (A-NET): flip a byte in the only object.
    assert!(!snapshot.objects.is_empty());
    let mid = snapshot.objects[0].len() / 2;
    snapshot.objects[0][mid] ^= 0xff;

    state_a
        .store
        .lock()
        .unwrap()
        .merge_from_snapshot(&snapshot)
        .expect("merge must not error, just drop the forged object");

    let key_b = LogicalKey {
        namespace: "peer".into(),
        name: "only-b".into(),
    };
    assert!(
        state_a
            .store
            .lock()
            .unwrap()
            .prove_membership(&key_b)
            .is_err(),
        "tampered wire object must NOT be ingested under its claimed key"
    );
}
