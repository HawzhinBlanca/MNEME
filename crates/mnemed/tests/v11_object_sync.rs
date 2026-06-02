//! §11 cross-host object sync over the **canonical [`SyncMessage`] protocol** (blueprint
//! tags `0x03 DiffReq` / `0x04 DiffResp` / `0x05 WantObjects` / `0x06 HaveObjects`),
//! framed by the shared `mneme-crdt` codec. Two `mnemed` daemons exchange an MST diff
//! and the resulting object delta over a REAL WebSocket, re-hash every received object
//! (INV-1 / A-NET) and merge through the verified CRDT path. Convergence is asserted on
//! the authenticated content roots (`key_index_root`, `dag_head_root`); the signed
//! `preimage_hash` legitimately differs per peer (own operator key, HLC, checkpoint chain).

use futures_util::{SinkExt, StreamExt};
use mneme_cap::{Capability, agent_cap};
use mneme_core::{Draft, LogicalKey, MemoryKind, MnemeError};
use mneme_crypto::KeyPair;
use mnemed::state::RateLimiter;
use mnemed::{AppState, RunningServer, ServerConfig, start_with_state};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

async fn recv_binary(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Vec<u8> {
    loop {
        match ws.next().await.expect("frame").expect("ok") {
            Message::Binary(data) => return data.to_vec(),
            _ => continue,
        }
    }
}

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

// The production client (`sync_client::pull_canonical`, CLI `mneme sync pull`) owns the
// `Store` directly and holds no lock across `.await`. This single-task test wraps the
// store in `AppState`'s `std::sync::Mutex`, so the guard is held across the WebSocket
// round-trip — safe here (no other task contends the lock during the pull), but it trips
// `clippy::await_holding_lock`. Allowed with justification rather than forcing an async
// mutex into `AppState` for a property only this test needs.
#[allow(clippy::await_holding_lock)]
async fn pull_canonical(local: &AppState, peer: &RunningServer) -> usize {
    let url = format!("ws://{}/v1/sync", peer.http_addr);
    let mut store = local.store.lock().expect("lock");
    mnemed::sync_client::pull_canonical(&mut store, &url)
        .await
        .expect("pull")
}

#[tokio::test]
async fn two_peers_converge_via_canonical_v11_protocol() {
    let operator = KeyPair::from_seed([0x42; 32]);
    let cap = agent_cap(&operator, operator.public_key_bytes()).expect("cap");

    let (state_a, _da) = build_peer(&operator, &cap);
    let (state_b, _db) = build_peer(&operator, &cap);
    remember(&state_a, "peer", "only-a", b"alpha-payload", &cap);
    remember(&state_b, "peer", "only-b", b"beta-payload", &cap);

    let server_a = serve(state_a.clone()).await;
    let server_b = serve(state_b.clone()).await;

    // A pulls B's delta, then B pulls A's (now-larger) delta.
    assert_eq!(
        pull_canonical(&state_a, &server_b).await,
        1,
        "A fetched B's single missing object over the canonical wire"
    );
    assert_eq!(
        pull_canonical(&state_b, &server_a).await,
        1,
        "B fetched A's single missing object over the canonical wire"
    );
    // Converged: a re-pull diffs to an empty delta (idempotent).
    assert_eq!(
        pull_canonical(&state_a, &server_b).await,
        0,
        "converged: DiffReq yields an empty want set"
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
        assert!(sa.prove_membership(&key_a).is_ok(), "A has only-a");
        assert!(
            sa.prove_membership(&key_b).is_ok(),
            "A received only-b via canonical §11 wire"
        );
        assert!(
            sb.prove_membership(&key_a).is_ok(),
            "B received only-a via canonical §11 wire"
        );
        assert!(sb.prove_membership(&key_b).is_ok(), "B has only-b");
        (sa.current_root().unwrap(), sb.current_root().unwrap())
    };

    assert_eq!(
        root_a.key_index_root, root_b.key_index_root,
        "key-index roots converge after canonical §11 anti-entropy"
    );
    assert_eq!(
        root_a.dag_head_root, root_b.dag_head_root,
        "DAG head roots converge after canonical §11 anti-entropy"
    );

    server_a.shutdown().await;
    server_b.shutdown().await;
}

/// A-NET fail-closed: a `HaveObjects` frame whose object bytes were mutated in transit is
/// rejected with a typed [`MnemeError::ObjectTampered`] before it can reach the merge —
/// the recomputed content hash no longer matches the bundle's claimed object id.
#[tokio::test]
async fn canonical_tampered_have_objects_rejected_with_typed_error() {
    let operator = KeyPair::from_seed([0x99; 32]);
    let cap = agent_cap(&operator, operator.public_key_bytes()).expect("cap");
    let (state_b, _db) = build_peer(&operator, &cap);
    remember(
        &state_b,
        "peer",
        "only-b",
        b"beta-payload-bytes-long-enough",
        &cap,
    );
    let server_b = serve(state_b.clone()).await;

    let url = format!("ws://{}/v1/sync", server_b.http_addr);
    let (mut ws, _) = connect_async(&url).await.expect("ws connect");
    ws.send(Message::Binary(
        mnemed::sync::encode_diff_request([0u8; 32])
            .expect("diff req")
            .into(),
    ))
    .await
    .expect("send diff req");
    let summaries =
        mnemed::sync::decode_diff_response(&recv_binary(&mut ws).await).expect("diff resp");
    assert_eq!(summaries.len(), 1, "B advertises its single live leaf");

    ws.send(Message::Binary(
        mnemed::sync::encode_want_objects_canonical(&summaries)
            .expect("want")
            .into(),
    ))
    .await
    .expect("send want");
    let have_frame = recv_binary(&mut ws).await;

    // Sanity: the untampered frame decodes to a valid snapshot, and gives us the real
    // leaf parts (claimed key_hash/object_id, logical key, and the ciphertext object).
    let snapshot = mnemed::sync::decode_have_objects_canonical(&have_frame)
        .expect("untampered HaveObjects frame decodes cleanly");
    assert_eq!(snapshot.objects.len(), 1, "B served its single live object");
    let object = snapshot.objects[0].clone();
    let (key_hash, object_id) = snapshot.leaves[0];
    let (_, namespace, name) = snapshot.object_keys[0].clone();

    // Positive control: faithfully re-encoding the exact parts still decodes — proves the
    // test-support encoder is structurally indistinguishable from the server's wire output.
    let faithful = mnemed::sync::encode_have_objects_canonical_for_test(
        key_hash, object_id, &namespace, &name, &object,
    )
    .expect("encode faithful bundle");
    mnemed::sync::decode_have_objects_canonical(&faithful)
        .expect("faithfully re-encoded bundle decodes");

    // Forgery: keep the claimed `object_id` but serve mutated object bytes. The bundle is
    // structurally valid CBOR, so decode reaches the A-NET re-hash gate, where
    // `hash_obj(object) != object_id` must fail closed with the typed `ObjectTampered`.
    let mut tampered = object.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xff;
    assert_ne!(tampered, object, "tamper actually changed the object bytes");
    let forged = mnemed::sync::encode_have_objects_canonical_for_test(
        key_hash, object_id, &namespace, &name, &tampered,
    )
    .expect("encode forged bundle");

    let err = mnemed::sync::decode_have_objects_canonical(&forged)
        .expect_err("tampered HaveObjects must be rejected");
    assert!(
        matches!(err, MnemeError::ObjectTampered),
        "expected typed ObjectTampered, got {err:?}"
    );

    server_b.shutdown().await;
}
