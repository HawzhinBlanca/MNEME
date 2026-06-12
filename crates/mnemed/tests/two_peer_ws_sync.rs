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
use std::future::Future;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Error as WebSocketError;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::http::Request;

type WsTestResult<T> = Result<T, String>;
type ClientWebSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
type TwoPeerWsNextMessage = Option<Result<Message, WebSocketError>>;
type TwoPeerWsRequest = Request<()>;
type TwoPeerWsTimedRead = Result<TwoPeerWsNextMessage, tokio::time::error::Elapsed>;

enum TwoPeerWsBinaryFrameOutcome {
    Binary(Vec<u8>),
    KeepAlive,
    Unexpected(Message),
    ReadFailed(WebSocketError),
    Closed,
    TimedOut,
}

const TWO_PEER_WS_BINARY_FRAME_TIMEOUT: Duration = Duration::from_secs(1);
const WS_SYNC_TEST_RATE_LIMIT_PER_MINUTE: u32 = 1000;

fn assert_membership_proof<T, E: std::fmt::Debug>(proof: Result<T, E>, context: &str) {
    proof.unwrap_or_else(|err| panic!("{context}: membership proof failed: {err:?}"));
}

fn expect_store_lock<T, E: std::fmt::Debug>(lock: Result<T, E>, context: &str) -> T {
    lock.unwrap_or_else(|err| panic!("{context}: store lock failed: {err:?}"))
}

fn expect_current_root<T, E: std::fmt::Debug>(root: Result<T, E>, context: &str) -> T {
    root.unwrap_or_else(|err| panic!("{context}: current root failed: {err:?}"))
}

fn test_loopback_addr() -> std::net::SocketAddr {
    std::net::SocketAddr::from(([127, 0, 0, 1], 0))
}

fn expect_two_peer_cap(operator: &KeyPair, context: &str) -> Capability {
    agent_cap(operator, operator.public_key_bytes())
        .unwrap_or_else(|err| panic!("{context}: two-peer capability creation failed: {err:?}"))
}

fn expect_two_peer_cap_b64(cap: &Capability, context: &str) -> String {
    cap_to_b64(cap)
        .unwrap_or_else(|err| panic!("{context}: two-peer capability encoding failed: {err:?}"))
}

fn expect_two_peer_tempdir(context: &str) -> TempDir {
    tempfile::tempdir().unwrap_or_else(|err| panic!("{context}: two-peer tempdir failed: {err}"))
}

fn expect_two_peer_store(dir: &Path, operator: &KeyPair, context: &str) -> mneme_store::Store {
    mneme_store::Store::create(dir, operator.clone())
        .unwrap_or_else(|err| panic!("{context}: two-peer store create failed: {err:?}"))
}

fn expect_two_peer_remember<T, E: std::fmt::Debug>(remembered: Result<T, E>, context: &str) -> T {
    remembered.unwrap_or_else(|err| panic!("{context}: two-peer remember failed: {err:?}"))
}

fn expect_two_peer_ws_request(ws_url: String, context: &str) -> TwoPeerWsRequest {
    ws_url
        .into_client_request()
        .unwrap_or_else(|err| panic!("{context}: two-peer WebSocket request build failed: {err}"))
}

fn expect_two_peer_ws_header_value(header: &str, context: &str) -> HeaderValue {
    HeaderValue::from_str(header)
        .unwrap_or_else(|err| panic!("{context}: two-peer WebSocket header build failed: {err}"))
}

async fn connect_two_peer_ws(
    peer: &RunningServer,
    cap: &Capability,
    context: &str,
) -> WsTestResult<ClientWebSocket> {
    connect_async(authed_ws_request(peer, cap, context))
        .await
        .map(|(ws, _)| ws)
        .map_err(|err| format!("{context}: two-peer WebSocket connect failed: {err}"))
}

async fn expect_two_peer_pull<T, E, F>(pull: F, context: &str) -> T
where
    E: std::fmt::Debug,
    F: Future<Output = Result<T, E>>,
{
    pull.await
        .unwrap_or_else(|err| panic!("{context}: two-peer pull failed: {err:?}"))
}

fn expect_two_peer_recall_entry<T, E: std::fmt::Debug>(
    recall: Result<Vec<T>, E>,
    context: &str,
) -> T {
    let mut entries =
        recall.unwrap_or_else(|err| panic!("{context}: two-peer recall failed: {err:?}"));
    if entries.is_empty() {
        panic!("{context}: two-peer recall failed: no entries returned");
    }
    entries.remove(0)
}

fn expect_two_peer_merge_result<T, E: std::fmt::Debug>(merge: Result<T, E>, context: &str) -> T {
    merge.unwrap_or_else(|err| panic!("{context}: two-peer merge failed: {err:?}"))
}

fn remember(state: &AppState, ns: &str, name: &str, body: &[u8], cap: &Capability) {
    let remember_context = format!("remembering {ns}/{name}");
    let lock_context = format!("store lock while remembering {ns}/{name}");
    let mut store = expect_store_lock(state.store.lock(), &lock_context);
    expect_two_peer_remember(
        store.remember(
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
                embargo_round: None,
            },
            cap,
        ),
        &remember_context,
    );
}

fn build_peer(operator: &KeyPair, cap: &Capability, label: &str) -> (AppState, TempDir) {
    let tempdir_context = format!("{label} tempdir");
    let store_context = format!("{label} store");
    let dir = expect_two_peer_tempdir(&tempdir_context);
    let mut store = expect_two_peer_store(dir.path(), operator, &store_context);
    store.trust_mut().authorized_writers.push(cap.subject);
    let state = AppState {
        store: Arc::new(Mutex::new(store)),
        operator: Arc::new(operator.clone()),
        rate_limit: Arc::new(Mutex::new(RateLimiter::new(
            WS_SYNC_TEST_RATE_LIMIT_PER_MINUTE,
        ))),
    };
    (state, dir)
}

async fn start_two_peer_server(state: AppState, context: &str) -> RunningServer {
    let config = ServerConfig {
        http_addr: test_loopback_addr(),
        grpc_addr: None,
        unix_socket: None,
        rate_limit_per_minute: WS_SYNC_TEST_RATE_LIMIT_PER_MINUTE,
    };
    start_with_state(config, state)
        .await
        .unwrap_or_else(|err| panic!("{context}: two-peer server start failed: {err:?}"))
}

fn authed_ws_request(peer: &RunningServer, cap: &Capability, context: &str) -> TwoPeerWsRequest {
    let ws_url = format!("ws://{}/v1/sync", peer.http_addr);
    let mut req = expect_two_peer_ws_request(ws_url, context);
    let auth = format!("Bearer {}", expect_two_peer_cap_b64(cap, context));
    req.headers_mut().insert(
        "Authorization",
        expect_two_peer_ws_header_value(&auth, context),
    );
    req
}

async fn recv_two_peer_ws_binary_message_with_timeout(
    ws: &mut ClientWebSocket,
) -> TwoPeerWsBinaryFrameOutcome {
    classify_two_peer_ws_binary_read(
        tokio::time::timeout(TWO_PEER_WS_BINARY_FRAME_TIMEOUT, ws.next()).await,
    )
}

async fn recv_ws_binary_frame(ws: &mut ClientWebSocket, context: &str) -> WsTestResult<Vec<u8>> {
    loop {
        match recv_two_peer_ws_binary_message_with_timeout(ws).await {
            TwoPeerWsBinaryFrameOutcome::Binary(data) => return Ok(data),
            TwoPeerWsBinaryFrameOutcome::KeepAlive => continue,
            TwoPeerWsBinaryFrameOutcome::Unexpected(frame) => {
                return Err(format!("{context} expected binary frame, got {frame:?}"));
            }
            TwoPeerWsBinaryFrameOutcome::ReadFailed(err) => {
                return Err(format!("{context} websocket read failed: {err}"));
            }
            TwoPeerWsBinaryFrameOutcome::Closed => {
                return Err(format!("{context} websocket closed before binary frame"));
            }
            TwoPeerWsBinaryFrameOutcome::TimedOut => {
                return Err(format!("{context} timed out waiting for binary frame"));
            }
        }
    }
}

fn classify_two_peer_ws_binary_read(
    read_result: TwoPeerWsTimedRead,
) -> TwoPeerWsBinaryFrameOutcome {
    match read_result {
        Ok(Some(Ok(Message::Binary(data)))) => TwoPeerWsBinaryFrameOutcome::Binary(data.to_vec()),
        Ok(Some(Ok(Message::Ping(_)))) | Ok(Some(Ok(Message::Pong(_)))) => {
            TwoPeerWsBinaryFrameOutcome::KeepAlive
        }
        Ok(Some(Ok(frame))) => TwoPeerWsBinaryFrameOutcome::Unexpected(frame),
        Ok(Some(Err(err))) => TwoPeerWsBinaryFrameOutcome::ReadFailed(err),
        Ok(None) => TwoPeerWsBinaryFrameOutcome::Closed,
        Err(_) => TwoPeerWsBinaryFrameOutcome::TimedOut,
    }
}

/// Pull the peer daemon's snapshot over WebSocket and merge it into `local`.
async fn pull_and_merge(
    local: &AppState,
    peer: &RunningServer,
    cap: &Capability,
) -> WsTestResult<()> {
    let mut ws = connect_two_peer_ws(peer, cap, "snapshot pull websocket").await?;
    ws.send(Message::Binary(
        mnemed::sync::encode_snapshot_request().into(),
    ))
    .await
    .map_err(|err| format!("snapshot pull request send failed: {err}"))?;
    let frame = recv_ws_binary_frame(&mut ws, "snapshot pull response").await?;
    let snapshot = mnemed::sync::decode_snapshot(&frame)
        .map_err(|err| format!("snapshot pull decode failed: {err}"))?;
    let mut store = local
        .store
        .lock()
        .map_err(|_| "snapshot pull local store lock poisoned".to_string())?;
    store
        .merge_from_snapshot(&snapshot)
        .map_err(|err| format!("snapshot pull merge failed: {err:?}"))?;
    Ok(())
}

#[tokio::test]
async fn two_daemons_converge_over_websocket() {
    let operator = KeyPair::from_seed([0x42; 32]);
    let cap = expect_two_peer_cap(&operator, "two-daemon WebSocket convergence capability");

    let (state_a, _da) = build_peer(&operator, &cap, "state A");
    let (state_b, _db) = build_peer(&operator, &cap, "state B");
    remember(&state_a, "peer", "only-a", b"alpha", &cap);
    remember(&state_b, "peer", "only-b", b"beta", &cap);

    let server_a = start_two_peer_server(state_a.clone(), "state A WebSocket server").await;
    let server_b = start_two_peer_server(state_b.clone(), "state B WebSocket server").await;

    // A pulls B (now holds the union); then B pulls the updated A.
    expect_two_peer_pull(
        pull_and_merge(&state_a, &server_b, &cap),
        "A pulls B snapshot",
    )
    .await;
    expect_two_peer_pull(
        pull_and_merge(&state_b, &server_a, &cap),
        "B pulls A snapshot",
    )
    .await;

    let key_a = LogicalKey {
        namespace: "peer".into(),
        name: "only-a".into(),
    };
    let key_b = LogicalKey {
        namespace: "peer".into(),
        name: "only-b".into(),
    };

    let (root_a, root_b) = {
        let sa = expect_store_lock(
            state_a.store.lock(),
            "state A store after WebSocket anti-entropy",
        );
        let sb = expect_store_lock(
            state_b.store.lock(),
            "state B store after WebSocket anti-entropy",
        );
        // Each peer can prove membership of BOTH keys after wire sync.
        assert_membership_proof(sa.prove_membership(&key_a), "A has only-a");
        assert_membership_proof(
            sa.prove_membership(&key_b),
            "A received only-b over the wire",
        );
        assert_membership_proof(
            sb.prove_membership(&key_a),
            "B received only-a over the wire",
        );
        assert_membership_proof(sb.prove_membership(&key_b), "B has only-b");
        (
            expect_current_root(
                sa.current_root(),
                "state A current root after WebSocket anti-entropy",
            ),
            expect_current_root(
                sb.current_root(),
                "state B current root after WebSocket anti-entropy",
            ),
        )
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
    let cap = expect_two_peer_cap(&operator, "plaintext WebSocket sync capability");
    let (state_a, _da) = build_peer(&operator, &cap, "state A");
    let (state_b, _db) = build_peer(&operator, &cap, "state B");
    remember(&state_a, "peer", "only-a", b"alpha-secret", &cap);

    let server_a = start_two_peer_server(state_a.clone(), "state A sealed WebSocket server").await;
    expect_two_peer_pull(
        pull_and_merge(&state_b, &server_a, &cap),
        "B pulls sealed snapshot from A",
    )
    .await; // sealed snapshot over the wire

    let query = Query {
        logical_key: LogicalKey {
            namespace: "peer".into(),
            name: "only-a".into(),
        },
        min_tier: TrustTier::Working,
        embedding: None,
        drand_signature: None,
    };
    let plaintext = {
        let sb = expect_store_lock(
            state_b.store.lock(),
            "state B store before plaintext recall after WebSocket sync",
        );
        expect_two_peer_recall_entry(
            sb.recall_verified_default(&query, &cap),
            "same-operator peer recalls plaintext after sealed WebSocket sync",
        )
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
    let cap = expect_two_peer_cap(&operator, "tampered WebSocket snapshot capability");
    let (state_a, _da) = build_peer(&operator, &cap, "state A");
    let (state_b, _db) = build_peer(&operator, &cap, "state B");
    remember(&state_b, "peer", "only-b", b"beta", &cap);

    let mut snapshot = expect_store_lock(
        state_b.store.lock(),
        "state B store before exporting tampered wire snapshot",
    )
    .export_sync_snapshot();
    // Tamper a transferred object blob (A-NET): flip a byte in the only object.
    assert!(
        !snapshot.objects.is_empty(),
        "tamper fixture should export at least one object before mutating wire bytes"
    );
    let mid = snapshot.objects[0].len() / 2;
    snapshot.objects[0][mid] ^= 0xff;

    {
        let mut state_a_store = expect_store_lock(
            state_a.store.lock(),
            "state A store before tampered snapshot merge",
        );
        expect_two_peer_merge_result(
            state_a_store.merge_from_snapshot(&snapshot),
            "tampered snapshot merge must drop forged object without error",
        );
    }

    let key_b = LogicalKey {
        namespace: "peer".into(),
        name: "only-b".into(),
    };
    assert!(
        expect_store_lock(
            state_a.store.lock(),
            "state A store after tampered snapshot merge",
        )
        .prove_membership(&key_b)
        .is_err(),
        "tampered wire object must NOT be ingested under its claimed key"
    );
}

/// Phase 2a: incremental anti-entropy over a real WebSocket — pull the peer's
/// manifest, then fetch ONLY the missing object delta, then merge. Converges the
/// content roots while transferring just the delta (not the full snapshot).
async fn pull_incremental(
    local: &AppState,
    peer: &RunningServer,
    cap: &Capability,
) -> WsTestResult<usize> {
    let mut ws = connect_two_peer_ws(peer, cap, "incremental pull websocket").await?;

    // 1) manifest (structure only, no object bytes)
    ws.send(Message::Binary(
        mnemed::sync::encode_manifest_request().into(),
    ))
    .await
    .map_err(|err| format!("incremental manifest request send failed: {err}"))?;
    let manifest_frame = recv_ws_binary_frame(&mut ws, "incremental manifest response").await?;
    let manifest = mnemed::sync::decode_manifest(&manifest_frame)
        .map_err(|err| format!("incremental manifest decode failed: {err}"))?;

    // 2) compute the missing delta locally, fetch only those object bytes
    let missing = {
        let store = local
            .store
            .lock()
            .map_err(|_| "incremental local store lock poisoned".to_string())?;
        store.missing_object_ids(&manifest)
    };
    let delta = if missing.is_empty() {
        Vec::new()
    } else {
        ws.send(Message::Binary(
            mnemed::sync::encode_want_objects(&missing)
                .map_err(|err| format!("incremental want-objects encode failed: {err}"))?
                .into(),
        ))
        .await
        .map_err(|err| format!("incremental want-objects request send failed: {err}"))?;
        let have_frame = recv_ws_binary_frame(&mut ws, "incremental have-objects response").await?;
        mnemed::sync::decode_have_objects(&have_frame)
            .map_err(|err| format!("incremental have-objects decode failed: {err}"))?
    };
    let fetched = delta.len();

    // 3) merge manifest + delta
    {
        let mut store = local
            .store
            .lock()
            .map_err(|_| "incremental merge store lock poisoned".to_string())?;
        store
            .merge_from_manifest(&manifest, delta)
            .map_err(|err| format!("incremental manifest merge failed: {err:?}"))?;
    }
    Ok(fetched)
}

#[tokio::test]
async fn two_daemons_converge_incrementally_over_websocket() {
    let operator = KeyPair::from_seed([0x77; 32]);
    let cap = expect_two_peer_cap(&operator, "incremental WebSocket convergence capability");
    let (state_a, _da) = build_peer(&operator, &cap, "state A");
    let (state_b, _db) = build_peer(&operator, &cap, "state B");
    remember(&state_a, "peer", "only-a", b"alpha", &cap);
    remember(&state_b, "peer", "only-b", b"beta", &cap);

    let server_a =
        start_two_peer_server(state_a.clone(), "state A incremental WebSocket server").await;
    let server_b =
        start_two_peer_server(state_b.clone(), "state B incremental WebSocket server").await;

    let fetched_b = expect_two_peer_pull(
        pull_incremental(&state_a, &server_b, &cap),
        "A pulls B incrementally",
    )
    .await;
    assert_eq!(fetched_b, 1, "A fetched only B's single missing object");
    let fetched_a = expect_two_peer_pull(
        pull_incremental(&state_b, &server_a, &cap),
        "B pulls A incrementally",
    )
    .await;
    assert_eq!(fetched_a, 1, "B fetched only A's single missing object");

    // Re-pull is a no-op delta (idempotent).
    let refetched_b = expect_two_peer_pull(
        pull_incremental(&state_a, &server_b, &cap),
        "A re-pulls B incrementally",
    )
    .await;
    assert_eq!(refetched_b, 0, "converged: empty delta");

    let key_a = LogicalKey {
        namespace: "peer".into(),
        name: "only-a".into(),
    };
    let key_b = LogicalKey {
        namespace: "peer".into(),
        name: "only-b".into(),
    };
    let (root_a, root_b) = {
        let sa = expect_store_lock(
            state_a.store.lock(),
            "state A store after incremental WebSocket anti-entropy",
        );
        let sb = expect_store_lock(
            state_b.store.lock(),
            "state B store after incremental WebSocket anti-entropy",
        );
        assert_membership_proof(
            sa.prove_membership(&key_b),
            "A got only-b via incremental wire",
        );
        assert_membership_proof(
            sb.prove_membership(&key_a),
            "B got only-a via incremental wire",
        );
        (
            expect_current_root(
                sa.current_root(),
                "state A current root after incremental WebSocket anti-entropy",
            ),
            expect_current_root(
                sb.current_root(),
                "state B current root after incremental WebSocket anti-entropy",
            ),
        )
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
