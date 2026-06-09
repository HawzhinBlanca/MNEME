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
use mneme_store::SyncSnapshot;
use mnemed::state::RateLimiter;
use mnemed::{AppState, RunningServer, ServerConfig, cap_to_b64, start_with_state};
use std::future::Future;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Error as WebSocketError;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::http::Request;

type ClientWebSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
type WebSocketMessageResult = Result<Message, WebSocketError>;
type TimedV11BinaryRead = Result<Option<WebSocketMessageResult>, tokio::time::error::Elapsed>;
type PullCanonicalIoFailureCheck = Result<String, String>;
type V11WsRequest = Request<()>;

enum V11BinaryFrameOutcome {
    Binary(Vec<u8>),
    KeepAlive,
    Unexpected(Message),
    ReadFailed(WebSocketError),
    Closed,
    TimedOut,
}

const V11_BINARY_FRAME_TIMEOUT: Duration = Duration::from_secs(1);
const V11_PULL_CANONICAL_STALLED_PEER_TIMEOUT: Duration = Duration::from_millis(50);
const V11_PULL_CANONICAL_TEST_TIMEOUT: Duration = Duration::from_secs(1);
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

fn expect_v11_agent_cap(operator: &KeyPair, context: &str) -> Capability {
    agent_cap(operator, operator.public_key_bytes())
        .unwrap_or_else(|err| panic!("{context}: v11 capability creation failed: {err:?}"))
}

fn expect_v11_cap_b64(cap: &Capability, context: &str) -> String {
    cap_to_b64(cap)
        .unwrap_or_else(|err| panic!("{context}: v11 capability encoding failed: {err:?}"))
}

fn expect_v11_tempdir(context: &str) -> TempDir {
    tempfile::tempdir().unwrap_or_else(|err| panic!("{context}: v11 tempdir failed: {err}"))
}

fn expect_v11_store(dir: &Path, operator: &KeyPair, context: &str) -> mneme_store::Store {
    mneme_store::Store::create(dir, operator.clone())
        .unwrap_or_else(|err| panic!("{context}: v11 store create failed: {err:?}"))
}

fn build_v11_store(
    operator: &KeyPair,
    cap: &Capability,
    label: &str,
) -> (mneme_store::Store, TempDir) {
    let tempdir_context = format!("{label} tempdir");
    let store_context = format!("{label} store");
    let dir = expect_v11_tempdir(&tempdir_context);
    let mut store = expect_v11_store(dir.path(), operator, &store_context);
    store.trust_mut().authorized_writers.push(cap.subject);

    (store, dir)
}

fn expect_v11_remember<T, E: std::fmt::Debug>(remembered: Result<T, E>, context: &str) -> T {
    remembered.unwrap_or_else(|err| panic!("{context}: v11 remember failed: {err:?}"))
}

async fn start_v11_server(state: AppState, context: &str) -> RunningServer {
    let config = ServerConfig {
        http_addr: test_loopback_addr(),
        grpc_addr: None,
        unix_socket: None,
        rate_limit_per_minute: WS_SYNC_TEST_RATE_LIMIT_PER_MINUTE,
    };
    start_with_state(config, state)
        .await
        .unwrap_or_else(|err| panic!("{context}: v11 server start failed: {err:?}"))
}

async fn expect_v11_fake_peer_listener(context: &str) -> TcpListener {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|err| panic!("{context}: v11 fake peer bind failed: {err}"))
}

fn expect_v11_fake_peer_url(listener: &TcpListener, context: &str) -> String {
    let addr = listener
        .local_addr()
        .unwrap_or_else(|err| panic!("{context}: v11 fake peer local address failed: {err}"));

    format!("ws://{addr}")
}

fn expect_v11_snapshot_leaf(
    snapshot: &SyncSnapshot,
    object_id: [u8; 32],
    context: &str,
) -> ([u8; 32], [u8; 32]) {
    snapshot
        .leaves
        .iter()
        .find(|(_, id)| *id == object_id)
        .copied()
        .unwrap_or_else(|| panic!("{context}: v11 snapshot leaf missing for {object_id:?}"))
}

fn expect_v11_snapshot_logical_key(
    snapshot: &SyncSnapshot,
    object_id: [u8; 32],
    context: &str,
) -> (String, String) {
    snapshot
        .object_keys
        .iter()
        .find(|(id, _, _)| *id == object_id)
        .map(|(_, namespace, name)| (namespace.clone(), name.clone()))
        .unwrap_or_else(|| panic!("{context}: v11 snapshot logical key missing for {object_id:?}"))
}

fn expect_v11_snapshot_object_bytes(
    snapshot: &SyncSnapshot,
    object_id: [u8; 32],
    context: &str,
) -> Vec<u8> {
    snapshot
        .objects
        .iter()
        .find(|bytes| hash_obj(bytes) == object_id)
        .cloned()
        .unwrap_or_else(|| panic!("{context}: v11 snapshot object bytes missing for {object_id:?}"))
}

fn expect_v11_have_objects_frame(
    frame: Result<Vec<u8>, mnemed::sync::SyncFrameError>,
    context: &str,
) -> Vec<u8> {
    frame.unwrap_or_else(|err| panic!("{context}: v11 HaveObjects frame encode failed: {err}"))
}

fn expect_v11_ws_request(ws_url: String, context: &str) -> V11WsRequest {
    ws_url
        .into_client_request()
        .unwrap_or_else(|err| panic!("{context}: v11 WebSocket request build failed: {err}"))
}

fn expect_v11_ws_header_value(header: &str, context: &str) -> HeaderValue {
    HeaderValue::from_str(header)
        .unwrap_or_else(|err| panic!("{context}: v11 WebSocket header build failed: {err}"))
}

async fn connect_v11_ws(
    peer: &RunningServer,
    cap: &Capability,
    context: &str,
) -> Result<ClientWebSocket, String> {
    connect_async(authed_ws_request(peer, cap, context))
        .await
        .map(|(ws, _)| ws)
        .map_err(|err| format!("{context}: v11 WebSocket connect failed: {err}"))
}

async fn expect_v11_pull_success<T, E, F>(pull: F, context: &str) -> T
where
    E: std::fmt::Debug,
    F: Future<Output = Result<T, E>>,
{
    pull.await
        .unwrap_or_else(|err| panic!("{context}: v11 canonical pull failed: {err:?}"))
}

async fn expect_v11_pull_failure<T, E, F>(pull: F, context: &str) -> E
where
    T: std::fmt::Debug,
    F: Future<Output = Result<T, E>>,
{
    match pull.await {
        Ok(value) => {
            panic!("{context}: expected v11 canonical pull failure, got success: {value:?}");
        }
        Err(err) => err,
    }
}

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
        match recv_v11_binary_message_with_timeout(ws).await {
            V11BinaryFrameOutcome::Binary(data) => return Ok(data),
            V11BinaryFrameOutcome::KeepAlive => continue,
            V11BinaryFrameOutcome::Unexpected(frame) => {
                return Err(format!("{context} expected binary frame, got {frame:?}"));
            }
            V11BinaryFrameOutcome::ReadFailed(err) => {
                return Err(format!("{context} websocket read failed: {err}"));
            }
            V11BinaryFrameOutcome::Closed => {
                return Err(format!("{context} websocket closed before binary frame"));
            }
            V11BinaryFrameOutcome::TimedOut => {
                return Err(format!("{context} timed out waiting for binary frame"));
            }
        }
    }
}

fn classify_v11_binary_read(read_result: TimedV11BinaryRead) -> V11BinaryFrameOutcome {
    match read_result {
        Ok(Some(Ok(Message::Binary(data)))) => V11BinaryFrameOutcome::Binary(data.to_vec()),
        Ok(Some(Ok(Message::Ping(_)))) | Ok(Some(Ok(Message::Pong(_)))) => {
            V11BinaryFrameOutcome::KeepAlive
        }
        Ok(Some(Ok(frame))) => V11BinaryFrameOutcome::Unexpected(frame),
        Ok(Some(Err(err))) => V11BinaryFrameOutcome::ReadFailed(err),
        Ok(None) => V11BinaryFrameOutcome::Closed,
        Err(_) => V11BinaryFrameOutcome::TimedOut,
    }
}

async fn recv_v11_binary_message_with_timeout<S>(ws: &mut S) -> V11BinaryFrameOutcome
where
    S: Stream<Item = WebSocketMessageResult> + Unpin,
{
    classify_v11_binary_read(tokio::time::timeout(V11_BINARY_FRAME_TIMEOUT, ws.next()).await)
}

fn remember(state: &AppState, ns: &str, name: &str, body: &[u8], cap: &Capability) {
    let remember_context = format!("remembering {ns}/{name}");
    let lock_context = format!("store lock while remembering {ns}/{name}");
    let mut store = expect_store_lock(state.store.lock(), &lock_context);
    expect_v11_remember(
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
            },
            cap,
        ),
        &remember_context,
    );
}

fn remember_in_store(
    store: &mut mneme_store::Store,
    ns: &str,
    name: &str,
    body: &[u8],
    cap: &Capability,
) -> [u8; 32] {
    let remember_context = format!("remembering {ns}/{name} in store");
    let (id, _) = expect_v11_remember(
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
            },
            cap,
        ),
        &remember_context,
    );
    *id.as_bytes()
}

fn build_peer(operator: &KeyPair, cap: &Capability, label: &str) -> (AppState, TempDir) {
    let (store, dir) = build_v11_store(operator, cap, label);
    let state = AppState {
        store: Arc::new(Mutex::new(store)),
        operator: Arc::new(operator.clone()),
        rate_limit: Arc::new(Mutex::new(RateLimiter::new(
            WS_SYNC_TEST_RATE_LIMIT_PER_MINUTE,
        ))),
    };
    (state, dir)
}

type FakePeerResult = Result<(), String>;
type FakePeerWantedIds = Result<Vec<[u8; 32]>, String>;
type FakePeerWebSocket = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;
type FakePeerJoin<T> = Result<Result<T, String>, tokio::task::JoinError>;
type TimedFakePeerJoin<T> = Result<FakePeerJoin<T>, tokio::time::error::Elapsed>;
type FakePeerTcpAccept = Result<(tokio::net::TcpStream, std::net::SocketAddr), std::io::Error>;
type TimedFakePeerTcpAccept = Result<FakePeerTcpAccept, tokio::time::error::Elapsed>;
type FakePeerWebSocketAccept = Result<FakePeerWebSocket, WebSocketError>;
type TimedFakePeerWebSocketAccept = Result<FakePeerWebSocketAccept, tokio::time::error::Elapsed>;
type TimedFakePeerCloseRead = Result<Option<WebSocketMessageResult>, tokio::time::error::Elapsed>;

const FAKE_PEER_ACCEPT_TIMEOUT: Duration = Duration::from_secs(1);
const FAKE_PEER_JOIN_TIMEOUT: Duration = Duration::from_secs(1);
const FAKE_PEER_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OversizedPeerSendOutcome {
    Sent,
    Closed,
}

enum V11FakePeerCloseReadOutcome {
    CloseFrame,
    ReadFailed,
    Eof,
    ByeFrame(Message),
    Unexpected(Message),
    TimedOut,
}

enum V11FakePeerTcpAcceptOutcome {
    Accepted(tokio::net::TcpStream),
    Failed(std::io::Error),
    TimedOut(tokio::time::error::Elapsed),
}

enum V11FakePeerWebSocketAcceptOutcome {
    Accepted(FakePeerWebSocket),
    Failed(WebSocketError),
    TimedOut(tokio::time::error::Elapsed),
}

async fn join_fake_peer_result<T>(
    handle: tokio::task::JoinHandle<Result<T, String>>,
    context: &str,
) -> T {
    let joined = observe_fake_peer_join(handle, context).await;
    let task_result = expect_joined_fake_peer_task(joined, context);

    expect_successful_fake_peer_result(task_result, context)
}

async fn observe_fake_peer_join<T>(
    handle: tokio::task::JoinHandle<Result<T, String>>,
    context: &str,
) -> FakePeerJoin<T> {
    let observed = tokio::time::timeout(FAKE_PEER_JOIN_TIMEOUT, handle).await;

    expect_observed_fake_peer_join(observed, context)
}

fn expect_observed_fake_peer_join<T>(
    observed: TimedFakePeerJoin<T>,
    context: &str,
) -> FakePeerJoin<T> {
    match observed {
        Ok(joined) => joined,
        Err(_) => panic!("{context} timed out waiting for fake peer task"),
    }
}

fn expect_joined_fake_peer_task<T>(joined: FakePeerJoin<T>, context: &str) -> Result<T, String> {
    match joined {
        Ok(task_result) => task_result,
        Err(err) => panic!("{context} task panicked: {err}"),
    }
}

fn expect_successful_fake_peer_result<T>(task_result: Result<T, String>, context: &str) -> T {
    match task_result {
        Ok(value) => value,
        Err(err) => panic!("{context} task failed: {err}"),
    }
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
    let stream = match accept_fake_peer_tcp_stream_with_timeout(listener).await {
        V11FakePeerTcpAcceptOutcome::Accepted(stream) => stream,
        V11FakePeerTcpAcceptOutcome::Failed(err) => {
            return Err(format!("{context} accept failed: {err}"));
        }
        V11FakePeerTcpAcceptOutcome::TimedOut(_) => {
            return Err(format!("{context} timed out waiting for client connection"));
        }
    };
    match accept_fake_peer_websocket_with_timeout(stream).await {
        V11FakePeerWebSocketAcceptOutcome::Accepted(ws) => Ok(ws),
        V11FakePeerWebSocketAcceptOutcome::Failed(err) => {
            Err(format!("{context} websocket accept failed: {err}"))
        }
        V11FakePeerWebSocketAcceptOutcome::TimedOut(_) => Err(format!(
            "{context} timed out waiting for websocket handshake"
        )),
    }
}

async fn accept_fake_peer_tcp_stream_with_timeout(
    listener: TcpListener,
) -> V11FakePeerTcpAcceptOutcome {
    classify_v11_fake_peer_tcp_accept(
        tokio::time::timeout(FAKE_PEER_ACCEPT_TIMEOUT, listener.accept()).await,
    )
}

fn classify_v11_fake_peer_tcp_accept(
    accept_result: TimedFakePeerTcpAccept,
) -> V11FakePeerTcpAcceptOutcome {
    match accept_result {
        Ok(Ok((stream, _))) => V11FakePeerTcpAcceptOutcome::Accepted(stream),
        Ok(Err(err)) => V11FakePeerTcpAcceptOutcome::Failed(err),
        Err(err) => V11FakePeerTcpAcceptOutcome::TimedOut(err),
    }
}

async fn accept_fake_peer_websocket_with_timeout(
    stream: tokio::net::TcpStream,
) -> V11FakePeerWebSocketAcceptOutcome {
    classify_v11_fake_peer_websocket_accept(
        tokio::time::timeout(
            FAKE_PEER_ACCEPT_TIMEOUT,
            tokio_tungstenite::accept_async(stream),
        )
        .await,
    )
}

fn classify_v11_fake_peer_websocket_accept(
    accept_result: TimedFakePeerWebSocketAccept,
) -> V11FakePeerWebSocketAcceptOutcome {
    match accept_result {
        Ok(Ok(ws)) => V11FakePeerWebSocketAcceptOutcome::Accepted(ws),
        Ok(Err(err)) => V11FakePeerWebSocketAcceptOutcome::Failed(err),
        Err(err) => V11FakePeerWebSocketAcceptOutcome::TimedOut(err),
    }
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

async fn recv_fake_peer_close_message_with_timeout(
    ws: &mut FakePeerWebSocket,
) -> V11FakePeerCloseReadOutcome {
    classify_v11_fake_peer_close_read(
        tokio::time::timeout(FAKE_PEER_CLOSE_TIMEOUT, ws.next()).await,
    )
}

async fn stalled_websocket_peer() -> (String, tokio::task::JoinHandle<FakePeerResult>) {
    let listener = expect_v11_fake_peer_listener("stalled diff peer listener").await;
    let url = expect_v11_fake_peer_url(&listener, "stalled diff peer listener");
    let handle = tokio::spawn(async move {
        let mut ws = accept_fake_websocket_peer(listener, "stalled diff peer").await?;
        let _diff_req = recv_recorded_binary_result(&mut ws, "stalled diff peer").await?;
        expect_fake_peer_close(&mut ws, "stalled diff peer").await
    });
    (url, handle)
}

async fn oversized_diff_response_peer() -> (String, tokio::task::JoinHandle<FakePeerResult>) {
    let listener = expect_v11_fake_peer_listener("oversized diff peer listener").await;
    let url = expect_v11_fake_peer_url(&listener, "oversized diff peer listener");
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
    let listener = expect_v11_fake_peer_listener("oversized have-objects peer listener").await;
    let url = expect_v11_fake_peer_url(&listener, "oversized have-objects peer listener");
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
    let listener = expect_v11_fake_peer_listener("recording peer listener").await;
    let url = expect_v11_fake_peer_url(&listener, "recording peer listener");
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
        match recv_fake_peer_close_message_with_timeout(ws).await {
            V11FakePeerCloseReadOutcome::CloseFrame
            | V11FakePeerCloseReadOutcome::ReadFailed
            | V11FakePeerCloseReadOutcome::Eof => return Ok(()),
            V11FakePeerCloseReadOutcome::ByeFrame(_) if !saw_bye => {
                saw_bye = true;
            }
            V11FakePeerCloseReadOutcome::ByeFrame(frame)
            | V11FakePeerCloseReadOutcome::Unexpected(frame) => {
                return Err(format!(
                    "{context} received unexpected message before close: {frame:?}"
                ));
            }
            V11FakePeerCloseReadOutcome::TimedOut if saw_bye => {
                return Err(format!("{context} sent Bye but did not close or EOF"));
            }
            V11FakePeerCloseReadOutcome::TimedOut => {
                return Err(format!("{context} did not observe client close or EOF"));
            }
        }
    }
}

fn classify_v11_fake_peer_close_read(
    read_result: TimedFakePeerCloseRead,
) -> V11FakePeerCloseReadOutcome {
    match read_result {
        Ok(Some(Ok(Message::Close(_)))) => V11FakePeerCloseReadOutcome::CloseFrame,
        Ok(Some(Err(_))) => V11FakePeerCloseReadOutcome::ReadFailed,
        Ok(None) => V11FakePeerCloseReadOutcome::Eof,
        Ok(Some(Ok(Message::Binary(data)))) if data.as_ref() == [0x07] => {
            V11FakePeerCloseReadOutcome::ByeFrame(Message::Binary(data))
        }
        Ok(Some(Ok(frame))) => V11FakePeerCloseReadOutcome::Unexpected(frame),
        Err(_) => V11FakePeerCloseReadOutcome::TimedOut,
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
    let fixture_context = "canonical HaveObjects fixture";
    let (key_hash, _) = expect_v11_snapshot_leaf(&snapshot, object_id, fixture_context);
    let (namespace, name) = expect_v11_snapshot_logical_key(&snapshot, object_id, fixture_context);
    let object = expect_v11_snapshot_object_bytes(&snapshot, object_id, fixture_context);

    expect_v11_have_objects_frame(
        mnemed::sync::encode_have_objects_canonical_for_test(
            key_hash, object_id, &namespace, &name, &object,
        ),
        fixture_context,
    )
}

fn authed_ws_request(peer: &RunningServer, cap: &Capability, context: &str) -> V11WsRequest {
    let url = format!("ws://{}/v1/sync", peer.http_addr);
    let mut req = expect_v11_ws_request(url, context);
    let auth = format!("Bearer {}", expect_v11_cap_b64(cap, context));
    req.headers_mut()
        .insert("Authorization", expect_v11_ws_header_value(&auth, context));
    req
}

fn assert_pull_canonical_frame_limit_io_failure(
    err: MnemeError,
    expected_path: &str,
    context: &str,
) {
    let kind = assert_pull_canonical_io_failure_check_passed(expect_pull_canonical_io_failure(
        err,
        expected_path,
        context,
    ));
    assert!(
        !kind.contains("timed out"),
        "{context} should be rejected by frame limit, not timeout: {kind}"
    );
}

fn assert_pull_canonical_timeout_io_failure(err: MnemeError, expected_path: &str, context: &str) {
    let kind = assert_pull_canonical_io_failure_check_passed(expect_pull_canonical_io_failure(
        err,
        expected_path,
        context,
    ));
    assert!(
        kind.contains("timed out"),
        "{context} should fail with sync client timeout I/O error, got {kind}"
    );
}

fn expect_pull_canonical_io_failure(
    err: MnemeError,
    expected_path: &str,
    context: &str,
) -> PullCanonicalIoFailureCheck {
    match err {
        MnemeError::IoFailed { path, kind } if path == expected_path => Ok(kind),
        MnemeError::IoFailed { path, kind } => Err(format!(
            "{context}: expected sync client I/O failure path {expected_path}, got {path}: {kind}"
        )),
        other => Err(format!(
            "{context}: expected sync client I/O failure, got {other:?}"
        )),
    }
}

fn assert_pull_canonical_io_failure_check_passed(failure: PullCanonicalIoFailureCheck) -> String {
    match failure {
        Ok(kind) => kind,
        Err(message) => panic!("{message}"),
    }
}

#[tokio::test]
async fn pull_canonical_rejects_oversized_peer_have_objects_response() {
    let operator = KeyPair::from_seed([0x34; 32]);
    let cap = expect_v11_agent_cap(&operator, "oversized HaveObjects capability");
    let (mut store, _dir) = build_v11_store(&operator, &cap, "oversized HaveObjects local");
    let cap_b64 = expect_v11_cap_b64(&cap, "oversized HaveObjects capability");
    let missing_id = [0x34; 32];
    let (url, peer) = oversized_have_objects_response_peer(missing_id).await;

    let err = expect_v11_pull_failure(
        mnemed::sync_client::pull_canonical_with_cap_and_timeout(
            &mut store,
            &url,
            &cap_b64,
            V11_PULL_CANONICAL_TEST_TIMEOUT,
        ),
        "oversized peer HaveObjects response",
    )
    .await;

    assert_pull_canonical_frame_limit_io_failure(err, &url, "oversized peer HaveObjects response");

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
    let cap = expect_v11_agent_cap(&operator, "oversized DiffResp capability");
    let (mut store, _dir) = build_v11_store(&operator, &cap, "oversized DiffResp local");
    let cap_b64 = expect_v11_cap_b64(&cap, "oversized DiffResp capability");
    let (url, peer) = oversized_diff_response_peer().await;

    let err = expect_v11_pull_failure(
        mnemed::sync_client::pull_canonical_with_cap_and_timeout(
            &mut store,
            &url,
            &cap_b64,
            V11_PULL_CANONICAL_TEST_TIMEOUT,
        ),
        "oversized peer diff response",
    )
    .await;

    assert_pull_canonical_frame_limit_io_failure(err, &url, "oversized peer response");

    expect_fake_peer(peer, "oversized diff peer").await;
}

#[tokio::test]
async fn pull_canonical_times_out_when_peer_stalls_diff_response() {
    let operator = KeyPair::from_seed([0x31; 32]);
    let cap = expect_v11_agent_cap(&operator, "stalled peer capability");
    let (mut store, _dir) = build_v11_store(&operator, &cap, "stalled peer local");
    let cap_b64 = expect_v11_cap_b64(&cap, "stalled peer capability");
    let (url, peer) = stalled_websocket_peer().await;

    let err = expect_v11_pull_failure(
        mnemed::sync_client::pull_canonical_with_cap_and_timeout(
            &mut store,
            &url,
            &cap_b64,
            V11_PULL_CANONICAL_STALLED_PEER_TIMEOUT,
        ),
        "stalled peer",
    )
    .await;

    assert_pull_canonical_timeout_io_failure(err, &url, "stalled peer");

    expect_fake_peer(peer, "stalled peer").await;
}

#[tokio::test]
async fn pull_canonical_requests_only_missing_object_ids() {
    let operator = KeyPair::from_seed([0x32; 32]);
    let cap = expect_v11_agent_cap(&operator, "recording peer capability");
    let cap_b64 = expect_v11_cap_b64(&cap, "recording peer capability");

    let (mut local_store, _local_dir) = build_v11_store(&operator, &cap, "recording peer local");
    let local_id = remember_in_store(
        &mut local_store,
        "peer",
        "already-local",
        b"already-local-payload",
        &cap,
    );

    let (mut peer_store, _peer_dir) = build_v11_store(&operator, &cap, "recording peer remote");
    let missing_id =
        remember_in_store(&mut peer_store, "peer", "missing", b"missing-payload", &cap);
    let have_frame = have_objects_frame_for(&peer_store, missing_id);
    let (url, peer) = recording_delta_peer(vec![local_id, missing_id], have_frame).await;

    let fetched = expect_v11_pull_success(
        mnemed::sync_client::pull_canonical_with_cap_and_timeout(
            &mut local_store,
            &url,
            &cap_b64,
            V11_PULL_CANONICAL_TEST_TIMEOUT,
        ),
        "recording peer canonical pull",
    )
    .await;

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
    let mut store = expect_store_lock(local.store.lock(), "local store during canonical v11 pull");
    let cap_b64 = expect_v11_cap_b64(cap, "canonical v11 pull capability");
    expect_v11_pull_success(
        mnemed::sync_client::pull_canonical_with_cap(&mut store, &url, &cap_b64),
        "canonical v11 pull",
    )
    .await
}

#[tokio::test]
async fn two_peers_converge_via_canonical_v11_protocol() {
    let operator = KeyPair::from_seed([0x42; 32]);
    let cap = expect_v11_agent_cap(&operator, "canonical v11 convergence capability");

    let (state_a, _da) = build_peer(&operator, &cap, "state A");
    let (state_b, _db) = build_peer(&operator, &cap, "state B");
    remember(&state_a, "peer", "only-a", b"alpha-payload", &cap);
    remember(&state_b, "peer", "only-b", b"beta-payload", &cap);

    let server_a = start_v11_server(state_a.clone(), "state A canonical v11 server").await;
    let server_b = start_v11_server(state_b.clone(), "state B canonical v11 server").await;

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
        let sa = expect_store_lock(
            state_a.store.lock(),
            "state A store after canonical v11 wire convergence",
        );
        let sb = expect_store_lock(
            state_b.store.lock(),
            "state B store after canonical v11 wire convergence",
        );
        assert_membership_proof(sa.prove_membership(&key_a), "A has only-a");
        assert_membership_proof(
            sa.prove_membership(&key_b),
            "A received only-b via canonical §11 wire",
        );
        assert_membership_proof(
            sb.prove_membership(&key_a),
            "B received only-a via canonical §11 wire",
        );
        assert_membership_proof(sb.prove_membership(&key_b), "B has only-b");
        (
            expect_current_root(
                sa.current_root(),
                "state A current root after canonical v11 wire convergence",
            ),
            expect_current_root(
                sb.current_root(),
                "state B current root after canonical v11 wire convergence",
            ),
        )
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
/// rejected with typed sync tamper before it can reach the merge —
/// the recomputed content hash no longer matches the bundle's claimed object id.
#[tokio::test]
async fn canonical_tampered_have_objects_rejected_with_typed_error() -> Result<(), String> {
    let operator = KeyPair::from_seed([0x99; 32]);
    let cap = expect_v11_agent_cap(&operator, "canonical tamper capability");
    let (state_b, _db) = build_peer(&operator, &cap, "state B tamper");
    remember(
        &state_b,
        "peer",
        "only-b",
        b"beta-payload-bytes-long-enough",
        &cap,
    );
    let server_b = start_v11_server(state_b.clone(), "state B canonical tamper server").await;

    let mut ws = connect_v11_ws(&server_b, &cap, "canonical tamper websocket").await?;
    ws.send(Message::Binary(
        mnemed::sync::encode_diff_request([0u8; 32])
            .map_err(|err| format!("canonical tamper diff request encode failed: {err}"))?
            .into(),
    ))
    .await
    .map_err(|err| format!("canonical tamper diff request send failed: {err}"))?;
    let diff_frame = recv_client_binary_frame(&mut ws, "canonical tamper diff response").await?;
    let summaries = mnemed::sync::decode_diff_response(&diff_frame)
        .map_err(|err| format!("canonical tamper diff response decode failed: {err}"))?;
    assert_eq!(summaries.len(), 1, "B advertises its single live leaf");

    ws.send(Message::Binary(
        mnemed::sync::encode_want_objects_canonical(&summaries)
            .map_err(|err| format!("canonical tamper want-objects encode failed: {err}"))?
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
    let faithful = expect_v11_have_objects_frame(
        mnemed::sync::encode_have_objects_canonical_for_test(
            key_hash, object_id, &namespace, &name, &object,
        ),
        "faithful HaveObjects positive control",
    );
    mnemed::sync::decode_have_objects_canonical(&faithful)
        .map_err(|err| format!("faithfully re-encoded bundle decode failed: {err:?}"))?;

    // Forgery: keep the claimed `object_id` but serve mutated object bytes. The bundle is
    // structurally valid CBOR, so decode reaches the A-NET re-hash gate, where
    // `hash_obj(object) != object_id` must fail closed with the typed `ObjectTampered`.
    let mut tampered = object.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xff;
    assert_ne!(tampered, object, "tamper actually changed the object bytes");
    let forged = expect_v11_have_objects_frame(
        mnemed::sync::encode_have_objects_canonical_for_test(
            key_hash, object_id, &namespace, &name, &tampered,
        ),
        "forged HaveObjects tamper fixture",
    );

    let err = match mnemed::sync::decode_have_objects_canonical(&forged) {
        Ok(_) => return Err("tampered HaveObjects unexpectedly decoded".to_string()),
        Err(err) => err,
    };
    assert!(
        matches!(err, mnemed::sync::SyncFrameError::ObjectTampered),
        "expected typed sync ObjectTampered, got {err:?}"
    );

    server_b.shutdown().await;
    Ok(())
}
