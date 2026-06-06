//! §11 cross-host object sync over the **canonical [`SyncMessage`] protocol** (blueprint
//! tags `0x03 DiffReq` / `0x04 DiffResp` / `0x05 WantObjects` / `0x06 HaveObjects`),
//! framed by the shared `mneme-crdt` codec. Two `mnemed` daemons exchange an MST diff
//! and the resulting object delta over a REAL WebSocket, re-hash every received object
//! (INV-1 / A-NET) and merge through the verified CRDT path. Convergence is asserted on
//! the authenticated content roots (`key_index_root`, `dag_head_root`); the signed
//! `preimage_hash` legitimately differs per peer (own operator key, HLC, checkpoint chain).

use futures_util::{SinkExt, Stream, StreamExt};
use mneme_cap::{Capability, agent_cap};
use mneme_core::{Draft, LogicalKey, MemoryKind, MnemeError, SyncMessage, hash_obj};
use mneme_crdt::{decode_sync_message, encode_sync_message};
use mneme_crypto::KeyPair;
use mnemed::state::RateLimiter;
use mnemed::{AppState, RunningServer, ServerConfig, cap_to_b64, start_with_state};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Error as WebSocketError;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;

type ClientWebSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
type WebSocketMessageResult = Result<Message, WebSocketError>;

const V11_BINARY_FRAME_TIMEOUT: Duration = Duration::from_secs(1);
const V11_PULL_CANONICAL_STALLED_PEER_TIMEOUT: Duration = Duration::from_millis(50);
const V11_PULL_CANONICAL_TEST_TIMEOUT: Duration = Duration::from_secs(1);

async fn recv_client_binary_frame(
    ws: &mut ClientWebSocket,
    context: &str,
) -> Result<Vec<u8>, String> {
    recv_ws_binary_frame_with_timeout(ws, context).await
}

async fn recv_ws_binary_frame_with_timeout<S>(ws: &mut S, context: &str) -> Result<Vec<u8>, String>
where
    S: Stream<Item = WebSocketMessageResult> + Unpin,
{
    loop {
        match tokio::time::timeout(V11_BINARY_FRAME_TIMEOUT, ws.next()).await {
            Ok(Some(Ok(Message::Binary(data)))) => return Ok(data.to_vec()),
            Ok(Some(Ok(Message::Ping(_)))) | Ok(Some(Ok(Message::Pong(_)))) => continue,
            Ok(Some(Ok(other))) => {
                return Err(format!("{context} expected binary frame, got {other:?}"));
            }
            Ok(Some(Err(err))) => return Err(format!("{context} websocket read failed: {err}")),
            Ok(None) => return Err(format!("{context} websocket closed before binary frame")),
            Err(_) => return Err(format!("{context} timed out waiting for binary frame")),
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
                valid_time_ms: None,
            },
            cap,
        )
        .expect("remember");
}

fn remember_in_store(
    store: &mut mneme_store::Store,
    ns: &str,
    name: &str,
    body: &[u8],
    cap: &Capability,
) -> [u8; 32] {
    let (id, _) = store
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
        .expect("remember in store");
    *id.as_bytes()
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
        unix_socket: None,
        rate_limit_per_minute: 1000,
    };
    start_with_state(config, state).await.expect("start")
}

type FakePeerResult = Result<(), String>;
type FakePeerWantedIds = Result<Vec<[u8; 32]>, String>;
type FakePeerWebSocket = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

const FAKE_PEER_ACCEPT_TIMEOUT: Duration = Duration::from_secs(1);
const FAKE_PEER_JOIN_TIMEOUT: Duration = Duration::from_secs(1);
const FAKE_PEER_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OversizedPeerSendOutcome {
    Sent,
    Closed,
}

async fn join_fake_peer_result<T>(
    handle: tokio::task::JoinHandle<Result<T, String>>,
    context: &str,
) -> T {
    tokio::time::timeout(FAKE_PEER_JOIN_TIMEOUT, handle)
        .await
        .unwrap_or_else(|_| panic!("{context} timed out waiting for fake peer task"))
        .unwrap_or_else(|err| panic!("{context} task panicked: {err}"))
        .unwrap_or_else(|err| panic!("{context} task failed: {err}"))
}

async fn expect_fake_peer(handle: tokio::task::JoinHandle<FakePeerResult>, context: &str) {
    join_fake_peer_result(handle, context).await;
}

async fn expect_fake_peer_wanted_ids(
    handle: tokio::task::JoinHandle<FakePeerWantedIds>,
    context: &str,
) -> Vec<[u8; 32]> {
    join_fake_peer_result(handle, context).await
}

async fn accept_fake_websocket_peer(
    listener: TcpListener,
    context: &str,
) -> Result<FakePeerWebSocket, String> {
    let (stream, _) = tokio::time::timeout(FAKE_PEER_ACCEPT_TIMEOUT, listener.accept())
        .await
        .map_err(|_| format!("{context} timed out waiting for client connection"))?
        .map_err(|err| format!("{context} accept failed: {err}"))?;
    tokio::time::timeout(
        FAKE_PEER_ACCEPT_TIMEOUT,
        tokio_tungstenite::accept_async(stream),
    )
    .await
    .map_err(|_| format!("{context} timed out waiting for websocket handshake"))?
    .map_err(|err| format!("{context} websocket accept failed: {err}"))
}

async fn send_oversized_fake_peer_frame(
    ws: &mut FakePeerWebSocket,
    tag: u8,
) -> OversizedPeerSendOutcome {
    match ws
        .send(Message::Binary(
            vec![tag; mnemed::sync::SYNC_MAX_FRAME + 1].into(),
        ))
        .await
    {
        Ok(()) => OversizedPeerSendOutcome::Sent,
        Err(_) => OversizedPeerSendOutcome::Closed,
    }
}

async fn stalled_websocket_peer() -> (String, tokio::task::JoinHandle<FakePeerResult>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stalled peer");
    let url = format!("ws://{}", listener.local_addr().expect("local addr"));
    let handle = tokio::spawn(async move {
        let mut ws = accept_fake_websocket_peer(listener, "stalled diff peer").await?;
        let _diff_req = recv_recorded_binary_result(&mut ws, "stalled diff peer").await?;
        expect_fake_peer_close(&mut ws, "stalled diff peer").await
    });
    (url, handle)
}

async fn oversized_diff_response_peer() -> (String, tokio::task::JoinHandle<FakePeerResult>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind oversized peer");
    let url = format!("ws://{}", listener.local_addr().expect("local addr"));
    let handle = tokio::spawn(async move {
        let mut ws = accept_fake_websocket_peer(listener, "oversized diff peer").await?;
        let _diff_req = recv_recorded_binary_result(&mut ws, "oversized diff peer").await?;
        match send_oversized_fake_peer_frame(&mut ws, 0x04).await {
            OversizedPeerSendOutcome::Sent => {
                expect_fake_peer_close(&mut ws, "oversized diff peer").await?;
            }
            OversizedPeerSendOutcome::Closed => {}
        }
        Ok(())
    });
    (url, handle)
}

async fn oversized_have_objects_response_peer(
    object_id: [u8; 32],
) -> (String, tokio::task::JoinHandle<FakePeerWantedIds>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind oversized have-objects peer");
    let url = format!("ws://{}", listener.local_addr().expect("local addr"));
    let handle = tokio::spawn(async move {
        let mut ws = accept_fake_websocket_peer(listener, "oversized have-objects peer").await?;

        let diff_frame =
            recv_recorded_binary_result(&mut ws, "oversized have-objects diff request").await?;
        match decode_sync_message(&diff_frame)
            .map_err(|err| format!("decode oversized have-objects diff request: {err}"))?
        {
            SyncMessage::DiffReq { .. } => {}
            other => {
                return Err(format!(
                    "oversized have-objects peer expected DiffReq, got {other:?}"
                ));
            }
        }

        let diff_resp = encode_sync_message(&SyncMessage::DiffResp {
            divergent_subtree_summaries: vec![object_id],
        })
        .map_err(|err| format!("encode oversized have-objects diff response: {err}"))?;
        ws.send(Message::Binary(diff_resp.into()))
            .await
            .map_err(|err| format!("send oversized have-objects diff response: {err}"))?;

        let want_frame =
            recv_recorded_binary_result(&mut ws, "oversized have-objects want request").await?;
        let wanted = match decode_sync_message(&want_frame)
            .map_err(|err| format!("decode oversized have-objects want request: {err}"))?
        {
            SyncMessage::WantObjects { ids } => ids,
            other => {
                return Err(format!(
                    "oversized have-objects peer expected WantObjects, got {other:?}"
                ));
            }
        };
        match send_oversized_fake_peer_frame(&mut ws, 0x06).await {
            OversizedPeerSendOutcome::Sent => {
                expect_fake_peer_close(&mut ws, "oversized have-objects peer")
                    .await
                    .map_err(|err| {
                        format!("oversized have-objects peer close observation: {err}")
                    })?;
            }
            OversizedPeerSendOutcome::Closed => {}
        }
        Ok(wanted)
    });
    (url, handle)
}

async fn recording_delta_peer(
    summaries: Vec<[u8; 32]>,
    have_frame: Vec<u8>,
) -> (String, tokio::task::JoinHandle<FakePeerWantedIds>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind recording peer");
    let url = format!("ws://{}", listener.local_addr().expect("local addr"));
    let handle = tokio::spawn(async move {
        let mut ws = accept_fake_websocket_peer(listener, "recording peer").await?;

        let diff_frame =
            recv_recorded_binary_result(&mut ws, "recording peer diff request").await?;
        match decode_sync_message(&diff_frame)
            .map_err(|err| format!("decode recording peer diff request: {err}"))?
        {
            SyncMessage::DiffReq { .. } => {}
            other => return Err(format!("recording peer expected DiffReq, got {other:?}")),
        }

        let diff_resp = encode_sync_message(&SyncMessage::DiffResp {
            divergent_subtree_summaries: summaries,
        })
        .map_err(|err| format!("encode recording peer diff response: {err}"))?;
        ws.send(Message::Binary(diff_resp.into()))
            .await
            .map_err(|err| format!("send recording peer diff response: {err}"))?;

        let want_frame =
            recv_recorded_binary_result(&mut ws, "recording peer want request").await?;
        let wanted = match decode_sync_message(&want_frame)
            .map_err(|err| format!("decode recording peer want request: {err}"))?
        {
            SyncMessage::WantObjects { ids } => ids,
            other => {
                return Err(format!(
                    "recording peer expected WantObjects, got {other:?}"
                ));
            }
        };
        ws.send(Message::Binary(have_frame.into()))
            .await
            .map_err(|err| format!("send recording peer have objects: {err}"))?;
        expect_fake_peer_close(&mut ws, "recording delta peer")
            .await
            .map_err(|err| format!("recording delta peer close observation: {err}"))?;
        Ok(wanted)
    });
    (url, handle)
}

async fn expect_fake_peer_close(ws: &mut FakePeerWebSocket, context: &str) -> FakePeerResult {
    let mut saw_bye = false;
    loop {
        match tokio::time::timeout(FAKE_PEER_CLOSE_TIMEOUT, ws.next()).await {
            Ok(Some(Ok(Message::Close(_)))) | Ok(Some(Err(_))) | Ok(None) => return Ok(()),
            Ok(Some(Ok(Message::Binary(data)))) if !saw_bye && data.as_ref() == [0x07] => {
                saw_bye = true;
            }
            Ok(Some(Ok(other))) => {
                return Err(format!(
                    "{context} received unexpected message before close: {other:?}"
                ));
            }
            Err(_) if saw_bye => {
                return Err(format!("{context} sent Bye but did not close or EOF"));
            }
            Err(_) => return Err(format!("{context} did not observe client close or EOF")),
        }
    }
}

async fn recv_recorded_binary_result(
    ws: &mut FakePeerWebSocket,
    context: &str,
) -> Result<Vec<u8>, String> {
    recv_ws_binary_frame_with_timeout(ws, context).await
}

fn have_objects_frame_for(store: &mneme_store::Store, object_id: [u8; 32]) -> Vec<u8> {
    let snapshot = store.export_sync_snapshot();
    let (key_hash, _) = snapshot
        .leaves
        .iter()
        .find(|(_, id)| *id == object_id)
        .copied()
        .expect("snapshot leaf for object");
    let (_, namespace, name) = snapshot
        .object_keys
        .iter()
        .find(|(id, _, _)| *id == object_id)
        .cloned()
        .expect("snapshot logical key for object");
    let object = snapshot
        .objects
        .iter()
        .find(|bytes| hash_obj(bytes) == object_id)
        .expect("snapshot object bytes for object");

    mnemed::sync::encode_have_objects_canonical_for_test(
        key_hash, object_id, &namespace, &name, object,
    )
    .expect("encode have objects frame")
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

#[tokio::test]
async fn pull_canonical_rejects_oversized_peer_have_objects_response() {
    let operator = KeyPair::from_seed([0x34; 32]);
    let cap = agent_cap(&operator, operator.public_key_bytes()).expect("cap");
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = mneme_store::Store::create(dir.path(), operator).expect("create");
    store.trust_mut().authorized_writers.push(cap.subject);
    let cap_b64 = cap_to_b64(&cap).expect("cap b64");
    let missing_id = [0x34; 32];
    let (url, peer) = oversized_have_objects_response_peer(missing_id).await;

    let err = mnemed::sync_client::pull_canonical_with_cap_and_timeout(
        &mut store,
        &url,
        &cap_b64,
        V11_PULL_CANONICAL_TEST_TIMEOUT,
    )
    .await
    .expect_err("oversized peer HaveObjects response must fail closed before decode");

    match err {
        MnemeError::IoFailed { path, kind } => {
            assert_eq!(path, url);
            assert!(
                !kind.contains("timed out"),
                "oversized peer HaveObjects response should be rejected by frame limit, not timeout: {kind}"
            );
        }
        other => panic!("expected sync client I/O failure, got {other:?}"),
    }

    let wanted = expect_fake_peer_wanted_ids(peer, "oversized have-objects peer").await;
    assert_eq!(
        wanted,
        vec![missing_id],
        "client must request the advertised missing object before oversized HaveObjects rejection"
    );
}

#[tokio::test]
async fn pull_canonical_rejects_oversized_peer_diff_response() {
    let operator = KeyPair::from_seed([0x33; 32]);
    let cap = agent_cap(&operator, operator.public_key_bytes()).expect("cap");
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = mneme_store::Store::create(dir.path(), operator).expect("create");
    store.trust_mut().authorized_writers.push(cap.subject);
    let cap_b64 = cap_to_b64(&cap).expect("cap b64");
    let (url, peer) = oversized_diff_response_peer().await;

    let err = mnemed::sync_client::pull_canonical_with_cap_and_timeout(
        &mut store,
        &url,
        &cap_b64,
        V11_PULL_CANONICAL_TEST_TIMEOUT,
    )
    .await
    .expect_err("oversized peer diff response must fail closed before decode");

    match err {
        MnemeError::IoFailed { path, kind } => {
            assert_eq!(path, url);
            assert!(
                !kind.contains("timed out"),
                "oversized peer response should be rejected by frame limit, not timeout: {kind}"
            );
        }
        other => panic!("expected sync client I/O failure, got {other:?}"),
    }

    expect_fake_peer(peer, "oversized diff peer").await;
}

#[tokio::test]
async fn pull_canonical_times_out_when_peer_stalls_diff_response() {
    let operator = KeyPair::from_seed([0x31; 32]);
    let cap = agent_cap(&operator, operator.public_key_bytes()).expect("cap");
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = mneme_store::Store::create(dir.path(), operator).expect("create");
    store.trust_mut().authorized_writers.push(cap.subject);
    let cap_b64 = cap_to_b64(&cap).expect("cap b64");
    let (url, peer) = stalled_websocket_peer().await;

    let err = mnemed::sync_client::pull_canonical_with_cap_and_timeout(
        &mut store,
        &url,
        &cap_b64,
        V11_PULL_CANONICAL_STALLED_PEER_TIMEOUT,
    )
    .await
    .expect_err("stalled peer must trip the sync client deadline");

    match err {
        MnemeError::IoFailed { path, kind } => {
            assert_eq!(path, url);
            assert!(
                kind.contains("timed out"),
                "unexpected sync client I/O error: {kind}"
            );
        }
        other => panic!("expected sync client timeout I/O error, got {other:?}"),
    }

    expect_fake_peer(peer, "stalled peer").await;
}

#[tokio::test]
async fn pull_canonical_requests_only_missing_object_ids() {
    let operator = KeyPair::from_seed([0x32; 32]);
    let cap = agent_cap(&operator, operator.public_key_bytes()).expect("cap");
    let cap_b64 = cap_to_b64(&cap).expect("cap b64");

    let local_dir = tempfile::tempdir().expect("local tempdir");
    let mut local_store =
        mneme_store::Store::create(local_dir.path(), operator.clone()).expect("create local");
    local_store.trust_mut().authorized_writers.push(cap.subject);
    let local_id = remember_in_store(
        &mut local_store,
        "peer",
        "already-local",
        b"already-local-payload",
        &cap,
    );

    let peer_dir = tempfile::tempdir().expect("peer tempdir");
    let mut peer_store =
        mneme_store::Store::create(peer_dir.path(), operator.clone()).expect("create peer");
    peer_store.trust_mut().authorized_writers.push(cap.subject);
    let missing_id =
        remember_in_store(&mut peer_store, "peer", "missing", b"missing-payload", &cap);
    let have_frame = have_objects_frame_for(&peer_store, missing_id);
    let (url, peer) = recording_delta_peer(vec![local_id, missing_id], have_frame).await;

    let fetched = mnemed::sync_client::pull_canonical_with_cap_and_timeout(
        &mut local_store,
        &url,
        &cap_b64,
        V11_PULL_CANONICAL_TEST_TIMEOUT,
    )
    .await
    .expect("pull from recording peer");

    assert_eq!(fetched, 1, "client fetched only the missing object bytes");
    let wanted = expect_fake_peer_wanted_ids(peer, "recording peer").await;
    assert_eq!(
        wanted,
        vec![missing_id],
        "canonical client must not request object ids it already holds"
    );
}

// The production client (`sync_client::pull_canonical`, CLI `mneme sync pull`) owns the
// `Store` directly and holds no lock across `.await`. This single-task test wraps the
// store in `AppState`'s `std::sync::Mutex`, so the guard is held across the WebSocket
// round-trip — safe here (no other task contends the lock during the pull), but it trips
// `clippy::await_holding_lock`. Allowed with justification rather than forcing an async
// mutex into `AppState` for a property only this test needs.
#[allow(clippy::await_holding_lock)]
async fn pull_canonical(local: &AppState, peer: &RunningServer, cap: &Capability) -> usize {
    let url = format!("ws://{}/v1/sync", peer.http_addr);
    let mut store = local.store.lock().expect("lock");
    let cap_b64 = cap_to_b64(cap).expect("cap b64");
    mnemed::sync_client::pull_canonical_with_cap(&mut store, &url, &cap_b64)
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
        pull_canonical(&state_a, &server_b, &cap).await,
        1,
        "A fetched B's single missing object over the canonical wire"
    );
    assert_eq!(
        pull_canonical(&state_b, &server_a, &cap).await,
        1,
        "B fetched A's single missing object over the canonical wire"
    );
    // Converged: a re-pull diffs to an empty delta (idempotent).
    assert_eq!(
        pull_canonical(&state_a, &server_b, &cap).await,
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
async fn canonical_tampered_have_objects_rejected_with_typed_error() -> Result<(), String> {
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

    let (mut ws, _) = connect_async(authed_ws_request(&server_b, &cap))
        .await
        .map_err(|err| format!("canonical tamper websocket connect failed: {err}"))?;
    ws.send(Message::Binary(
        mnemed::sync::encode_diff_request([0u8; 32])
            .ok_or_else(|| "canonical tamper diff request encode failed".to_string())?
            .into(),
    ))
    .await
    .map_err(|err| format!("canonical tamper diff request send failed: {err}"))?;
    let diff_frame = recv_client_binary_frame(&mut ws, "canonical tamper diff response").await?;
    let summaries = mnemed::sync::decode_diff_response(&diff_frame)
        .ok_or_else(|| "canonical tamper diff response decode failed".to_string())?;
    assert_eq!(summaries.len(), 1, "B advertises its single live leaf");

    ws.send(Message::Binary(
        mnemed::sync::encode_want_objects_canonical(&summaries)
            .ok_or_else(|| "canonical tamper want-objects encode failed".to_string())?
            .into(),
    ))
    .await
    .map_err(|err| format!("canonical tamper want-objects send failed: {err}"))?;
    let have_frame =
        recv_client_binary_frame(&mut ws, "canonical tamper HaveObjects response").await?;

    // Sanity: the untampered frame decodes to a valid snapshot, and gives us the real
    // leaf parts (claimed key_hash/object_id, logical key, and the ciphertext object).
    let snapshot = mnemed::sync::decode_have_objects_canonical(&have_frame)
        .map_err(|err| format!("untampered HaveObjects frame decode failed: {err:?}"))?;
    assert_eq!(snapshot.objects.len(), 1, "B served its single live object");
    let object = snapshot.objects[0].clone();
    let (key_hash, object_id) = snapshot.leaves[0];
    let (_, namespace, name) = snapshot.object_keys[0].clone();

    // Positive control: faithfully re-encoding the exact parts still decodes — proves the
    // test-support encoder is structurally indistinguishable from the server's wire output.
    let faithful = mnemed::sync::encode_have_objects_canonical_for_test(
        key_hash, object_id, &namespace, &name, &object,
    )
    .ok_or_else(|| "faithful HaveObjects encode failed".to_string())?;
    mnemed::sync::decode_have_objects_canonical(&faithful)
        .map_err(|err| format!("faithfully re-encoded bundle decode failed: {err:?}"))?;

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
    .ok_or_else(|| "forged HaveObjects encode failed".to_string())?;

    let err = match mnemed::sync::decode_have_objects_canonical(&forged) {
        Ok(_) => return Err("tampered HaveObjects unexpectedly decoded".to_string()),
        Err(err) => err,
    };
    assert!(
        matches!(err, MnemeError::ObjectTampered),
        "expected typed ObjectTampered, got {err:?}"
    );

    server_b.shutdown().await;
    Ok(())
}
