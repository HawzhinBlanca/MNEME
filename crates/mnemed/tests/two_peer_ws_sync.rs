//! F-G: two `mnemed` daemons converge their authenticated memory state by
//! exchanging §11 object snapshots over a REAL WebSocket (not a same-host file
//! path). Each peer fetches the other's `SyncSnapshot`, re-hashes every object on
//! ingest (A-NET defense), and merges via the verified CRDT path. Convergence is
//! asserted on the authenticated content roots (`key_index_root`, `dag_head_root`)
//! — the signed `preimage_hash` legitimately differs because each peer keeps its
//! own operator key, HLC, and checkpoint chain.

use futures_util::{SinkExt, StreamExt};
use mneme_cap::{Capability, agent_cap};
use mneme_core::{Draft, LogicalKey, MemoryKind, Query, TrustTier};
use mneme_crypto::KeyPair;
use mnemed::state::RateLimiter;
use mnemed::{AppState, RunningServer, ServerConfig, cap_to_b64, start_with_state};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;

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
                valid_time_ms: None,
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

fn authed_ws_request(
    peer: &RunningServer,
    cap: &Capability,
) -> tokio_tungstenite::tungstenite::http::Request<()> {
    let url = format!("ws://{}/v1/sync", peer.http_addr);
    let mut req = url.into_client_request().expect("ws request");
    let auth = format!("Bearer {}", cap_to_b64(cap).expect("cap b64"));
    req.headers_mut().insert(
        "Authorization",
        HeaderValue::from_str(&auth).expect("auth header"),
    );
    req
}

/// Pull the peer daemon's snapshot over WebSocket and merge it into `local`.
async fn pull_and_merge(local: &AppState, peer: &RunningServer, cap: &Capability) {
    let (mut ws, _) = connect_async(authed_ws_request(peer, cap))
        .await
        .expect("ws connect");
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
    pull_and_merge(&state_a, &server_b, &cap).await;
    pull_and_merge(&state_b, &server_a, &cap).await;

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

/// B4 end-to-end over a REAL WebSocket: the daemon serves a *sealed* snapshot (vault
/// keys AEAD-encrypted under the operator channel key). A same-operator peer that
/// pulls and merges it decrypts the keys and recalls the sender's entry as PLAINTEXT
/// — proving the full §11 path delivers confidential recall, not just ciphertext
/// convergence.
#[tokio::test]
async fn plaintext_recall_after_websocket_sync() {
    let operator = KeyPair::from_seed([0x42; 32]);
    let cap = agent_cap(&operator, operator.public_key_bytes()).expect("cap");
    let (state_a, _da) = build_peer(&operator, &cap);
    let (state_b, _db) = build_peer(&operator, &cap);
    remember(&state_a, "peer", "only-a", b"alpha-secret", &cap);

    let server_a = serve(state_a.clone()).await;
    pull_and_merge(&state_b, &server_a, &cap).await; // sealed snapshot over the wire

    let query = Query {
        logical_key: LogicalKey {
            namespace: "peer".into(),
            name: "only-a".into(),
        },
        min_tier: TrustTier::Working,
        embedding: None,
    };
    let plaintext = {
        let sb = state_b.store.lock().unwrap();
        sb.recall_verified_default(&query, &cap)
            .expect("same-operator peer recalls plaintext after sealed WebSocket sync")[0]
            .plaintext
            .clone()
    };
    assert_eq!(plaintext, b"alpha-secret");

    server_a.shutdown().await;
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

/// Phase 2a: incremental anti-entropy over a real WebSocket — pull the peer's
/// manifest, then fetch ONLY the missing object delta, then merge. Converges the
/// content roots while transferring just the delta (not the full snapshot).
async fn pull_incremental(local: &AppState, peer: &RunningServer, cap: &Capability) -> usize {
    let (mut ws, _) = connect_async(authed_ws_request(peer, cap))
        .await
        .expect("ws connect");

    // 1) manifest (structure only, no object bytes)
    ws.send(Message::Binary(
        mnemed::sync::encode_manifest_request().into(),
    ))
    .await
    .expect("send manifest req");
    let manifest_frame = loop {
        match ws.next().await.expect("frame").expect("ok") {
            Message::Binary(d) => break d,
            _ => continue,
        }
    };
    let manifest = mnemed::sync::decode_manifest(&manifest_frame).expect("decode manifest");

    // 2) compute the missing delta locally, fetch only those object bytes
    let missing = {
        let store = local.store.lock().expect("lock");
        store.missing_object_ids(&manifest)
    };
    let delta = if missing.is_empty() {
        Vec::new()
    } else {
        ws.send(Message::Binary(
            mnemed::sync::encode_want_objects(&missing)
                .expect("want")
                .into(),
        ))
        .await
        .expect("send want");
        let have_frame = loop {
            match ws.next().await.expect("frame").expect("ok") {
                Message::Binary(d) => break d,
                _ => continue,
            }
        };
        mnemed::sync::decode_have_objects(&have_frame).expect("decode have")
    };
    let fetched = delta.len();

    // 3) merge manifest + delta
    {
        let mut store = local.store.lock().expect("lock");
        store
            .merge_from_manifest(&manifest, delta)
            .expect("merge manifest");
    }
    fetched
}

#[tokio::test]
async fn two_daemons_converge_incrementally_over_websocket() {
    let operator = KeyPair::from_seed([0x77; 32]);
    let cap = agent_cap(&operator, operator.public_key_bytes()).expect("cap");
    let (state_a, _da) = build_peer(&operator, &cap);
    let (state_b, _db) = build_peer(&operator, &cap);
    remember(&state_a, "peer", "only-a", b"alpha", &cap);
    remember(&state_b, "peer", "only-b", b"beta", &cap);

    let server_a = serve(state_a.clone()).await;
    let server_b = serve(state_b.clone()).await;

    let fetched_b = pull_incremental(&state_a, &server_b, &cap).await;
    assert_eq!(fetched_b, 1, "A fetched only B's single missing object");
    let fetched_a = pull_incremental(&state_b, &server_a, &cap).await;
    assert_eq!(fetched_a, 1, "B fetched only A's single missing object");

    // Re-pull is a no-op delta (idempotent).
    assert_eq!(
        pull_incremental(&state_a, &server_b, &cap).await,
        0,
        "converged: empty delta"
    );

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
        assert!(
            sa.prove_membership(&key_b).is_ok(),
            "A got only-b via incremental wire"
        );
        assert!(
            sb.prove_membership(&key_a).is_ok(),
            "B got only-a via incremental wire"
        );
        (sa.current_root().unwrap(), sb.current_root().unwrap())
    };
    assert_eq!(
        root_a.key_index_root, root_b.key_index_root,
        "incremental key-index converges"
    );
    assert_eq!(
        root_a.dag_head_root, root_b.dag_head_root,
        "incremental DAG converges"
    );

    server_a.shutdown().await;
    server_b.shutdown().await;
}
