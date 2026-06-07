use super::common::TestHarness;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Error as WebSocketError;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::http::Request;

type ClientWebSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
type SyncWsNextMessage = Option<Result<Message, WebSocketError>>;
type SyncWsRequest = Request<()>;
type SyncWsTimedRead = Result<SyncWsNextMessage, tokio::time::error::Elapsed>;

const SYNC_WS_BINARY_FRAME_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);
const SYNC_WS_CLOSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OversizedSyncSendOutcome {
    Sent,
    Closed,
}

enum SyncWsBinaryFrameOutcome {
    Binary(Vec<u8>),
    KeepAlive,
    Unexpected(Message),
    ReadFailed(WebSocketError),
    Closed,
    TimedOut,
}

enum SyncWsCloseReadOutcome {
    CloseFrame,
    ReadFailed,
    Eof,
    Unexpected(Message),
    TimedOut,
}

async fn recv_sync_ws_binary_message_with_timeout(
    ws: &mut ClientWebSocket,
) -> SyncWsBinaryFrameOutcome {
    classify_sync_ws_binary_read(
        tokio::time::timeout(SYNC_WS_BINARY_FRAME_TIMEOUT, ws.next()).await,
    )
}

async fn recv_sync_ws_close_message_with_timeout(
    ws: &mut ClientWebSocket,
) -> SyncWsCloseReadOutcome {
    classify_sync_ws_close_read(tokio::time::timeout(SYNC_WS_CLOSE_TIMEOUT, ws.next()).await)
}

async fn recv_sync_ws_binary_frame(
    ws: &mut ClientWebSocket,
    context: &str,
) -> Result<Vec<u8>, String> {
    loop {
        match recv_sync_ws_binary_message_with_timeout(ws).await {
            SyncWsBinaryFrameOutcome::Binary(data) => return Ok(data),
            SyncWsBinaryFrameOutcome::KeepAlive => continue,
            SyncWsBinaryFrameOutcome::Unexpected(frame) => {
                return Err(format!("{context} expected binary frame, got {frame:?}"));
            }
            SyncWsBinaryFrameOutcome::ReadFailed(err) => {
                return Err(format!("{context} websocket read failed: {err}"));
            }
            SyncWsBinaryFrameOutcome::Closed => {
                return Err(format!("{context} websocket closed before response"));
            }
            SyncWsBinaryFrameOutcome::TimedOut => {
                return Err(format!("{context} timed out waiting for binary response"));
            }
        }
    }
}

fn classify_sync_ws_binary_read(read_result: SyncWsTimedRead) -> SyncWsBinaryFrameOutcome {
    match read_result {
        Ok(Some(Ok(Message::Binary(data)))) => SyncWsBinaryFrameOutcome::Binary(data.to_vec()),
        Ok(Some(Ok(Message::Ping(_)))) | Ok(Some(Ok(Message::Pong(_)))) => {
            SyncWsBinaryFrameOutcome::KeepAlive
        }
        Ok(Some(Ok(frame))) => SyncWsBinaryFrameOutcome::Unexpected(frame),
        Ok(Some(Err(err))) => SyncWsBinaryFrameOutcome::ReadFailed(err),
        Ok(None) => SyncWsBinaryFrameOutcome::Closed,
        Err(_) => SyncWsBinaryFrameOutcome::TimedOut,
    }
}

async fn send_oversized_sync_frame(ws: &mut ClientWebSocket) -> OversizedSyncSendOutcome {
    match ws
        .send(Message::Binary(
            vec![0x03; mnemed::sync::SYNC_MAX_FRAME + 1].into(),
        ))
        .await
    {
        Ok(()) => OversizedSyncSendOutcome::Sent,
        Err(_) => OversizedSyncSendOutcome::Closed,
    }
}

async fn expect_sync_ws_close_or_eof(
    ws: &mut ClientWebSocket,
    context: &str,
) -> Result<(), String> {
    match recv_sync_ws_close_message_with_timeout(ws).await {
        SyncWsCloseReadOutcome::CloseFrame
        | SyncWsCloseReadOutcome::ReadFailed
        | SyncWsCloseReadOutcome::Eof => Ok(()),
        SyncWsCloseReadOutcome::Unexpected(frame) => {
            Err(format!("{context} produced unexpected response: {frame:?}"))
        }
        SyncWsCloseReadOutcome::TimedOut => Err(format!(
            "{context} left sync websocket open without close or EOF"
        )),
    }
}

fn classify_sync_ws_close_read(read_result: SyncWsTimedRead) -> SyncWsCloseReadOutcome {
    match read_result {
        Ok(Some(Ok(Message::Close(_)))) => SyncWsCloseReadOutcome::CloseFrame,
        Ok(Some(Err(_))) => SyncWsCloseReadOutcome::ReadFailed,
        Ok(None) => SyncWsCloseReadOutcome::Eof,
        Ok(Some(Ok(frame))) => SyncWsCloseReadOutcome::Unexpected(frame),
        Err(_) => SyncWsCloseReadOutcome::TimedOut,
    }
}

fn sync_ws_url(h: &TestHarness) -> String {
    format!("ws://{}/v1/sync", h.server.http_addr)
}

fn expect_sync_ws_request(ws_url: String, context: &str) -> SyncWsRequest {
    ws_url
        .into_client_request()
        .unwrap_or_else(|err| panic!("{context}: sync WebSocket request build failed: {err}"))
}

fn expect_sync_ws_header_value(header: &str, context: &str) -> HeaderValue {
    HeaderValue::from_str(header)
        .unwrap_or_else(|err| panic!("{context}: sync WebSocket header build failed: {err}"))
}

async fn expect_sync_ws_auth_rejection<R>(request: R, context: &str) -> String
where
    R: IntoClientRequest + Unpin,
{
    match connect_async(request).await {
        Ok(_) => panic!("{context}: expected sync WebSocket connect error"),
        Err(err) => {
            let msg = err.to_string();
            assert!(
                msg.contains("401") || msg.contains("HTTP error"),
                "{context}: expected HTTP auth rejection, got {msg}"
            );
            msg
        }
    }
}

fn assert_sync_ws_no_server_error(msg: &str, context: &str) {
    assert!(
        !msg.contains("500"),
        "{context}: sync WebSocket auth rejection leaked as server error: {msg}"
    );
}

async fn connect_sync_ws(request: SyncWsRequest, context: &str) -> ClientWebSocket {
    connect_async(request)
        .await
        .unwrap_or_else(|err| panic!("{context}: sync WebSocket connect failed: {err}"))
        .0
}

fn expect_sync_ws_hello(h: &TestHarness, context: &str) -> Vec<u8> {
    mnemed::sync::encode_hello(&h.server.state, [0x02; 16])
        .unwrap_or_else(|err| panic!("{context}: sync WebSocket hello encode failed: {err}"))
}

async fn send_sync_ws_binary(ws: &mut ClientWebSocket, data: Vec<u8>, context: &str) {
    ws.send(Message::Binary(data.into()))
        .await
        .unwrap_or_else(|err| panic!("{context}: sync WebSocket binary send failed: {err}"));
}

async fn expect_sync_ws_binary_data(ws: &mut ClientWebSocket, context: &str) -> Vec<u8> {
    recv_sync_ws_binary_frame(ws, context)
        .await
        .unwrap_or_else(|err| panic!("{context}: sync WebSocket binary response failed: {err}"))
}

async fn assert_sync_ws_close_or_eof(ws: &mut ClientWebSocket, context: &str) {
    expect_sync_ws_close_or_eof(ws, context)
        .await
        .unwrap_or_else(|err| panic!("{context}: sync WebSocket close/EOF check failed: {err}"));
}

fn authed_ws_request(h: &TestHarness) -> SyncWsRequest {
    let ws_url = format!("ws://{}/v1/sync", h.server.http_addr);
    let mut req = expect_sync_ws_request(ws_url, "authenticated sync WebSocket request");
    req.headers_mut().insert(
        "Authorization",
        expect_sync_ws_header_value(
            &h.agent_auth_header(),
            "authenticated sync WebSocket authorization header",
        ),
    );
    req
}

fn malformed_auth_ws_request(h: &TestHarness) -> SyncWsRequest {
    let ws_url = format!("ws://{}/v1/sync", h.server.http_addr);
    let mut req = expect_sync_ws_request(ws_url, "malformed sync WebSocket request");
    req.headers_mut()
        .insert("Authorization", HeaderValue::from_static("Bearer oA=="));
    req
}

fn oversized_auth_ws_request(h: &TestHarness) -> SyncWsRequest {
    let ws_url = format!("ws://{}/v1/sync", h.server.http_addr);
    let mut req = expect_sync_ws_request(ws_url, "oversized sync WebSocket request");
    let header = format!(
        "Bearer {}",
        "A".repeat(mnemed::state::MAX_CAPABILITY_B64_LEN + 1)
    );
    req.headers_mut().insert(
        "Authorization",
        expect_sync_ws_header_value(&header, "oversized sync WebSocket authorization header"),
    );
    req
}

#[tokio::test]
async fn websocket_sync_requires_auth() {
    let h = TestHarness::new().await;
    expect_sync_ws_auth_rejection(sync_ws_url(&h), "unauthenticated sync WebSocket").await;
    h.shutdown().await;
}

#[tokio::test]
async fn websocket_sync_rejects_malformed_header_capability_without_server_error() {
    let h = TestHarness::new().await;
    let msg = expect_sync_ws_auth_rejection(
        malformed_auth_ws_request(&h),
        "malformed header sync WebSocket capability",
    )
    .await;
    assert_sync_ws_no_server_error(&msg, "malformed header sync WebSocket capability");
    h.shutdown().await;
}

#[tokio::test]
async fn websocket_sync_rejects_malformed_query_capability_without_server_error() {
    let h = TestHarness::new().await;
    let ws_url = format!("ws://{}/v1/sync?cap=oA%3D%3D", h.server.http_addr);
    let msg =
        expect_sync_ws_auth_rejection(ws_url, "malformed query sync WebSocket capability").await;
    assert_sync_ws_no_server_error(&msg, "malformed query sync WebSocket capability");
    h.shutdown().await;
}

#[tokio::test]
async fn websocket_sync_rejects_oversized_header_capability_without_server_error() {
    let h = TestHarness::new().await;
    let msg = expect_sync_ws_auth_rejection(
        oversized_auth_ws_request(&h),
        "oversized header sync WebSocket capability",
    )
    .await;
    assert_sync_ws_no_server_error(&msg, "oversized header sync WebSocket capability");
    h.shutdown().await;
}

#[tokio::test]
async fn websocket_sync_rejects_oversized_query_capability_without_server_error() {
    let h = TestHarness::new().await;
    let ws_url = format!(
        "ws://{}/v1/sync?cap={}",
        h.server.http_addr,
        "A".repeat(mnemed::state::MAX_CAPABILITY_B64_LEN + 1)
    );
    let msg =
        expect_sync_ws_auth_rejection(ws_url, "oversized query sync WebSocket capability").await;
    assert_sync_ws_no_server_error(&msg, "oversized query sync WebSocket capability");
    h.shutdown().await;
}

#[tokio::test]
async fn websocket_sync_hello_root_proof() {
    let h = TestHarness::new().await;
    let mut ws = connect_sync_ws(authed_ws_request(&h), "RootProof sync WebSocket").await;

    let hello = expect_sync_ws_hello(&h, "RootProof sync WebSocket");
    send_sync_ws_binary(&mut ws, hello, "RootProof sync WebSocket hello").await;

    let data = expect_sync_ws_binary_data(&mut ws, "RootProof response").await;
    assert_eq!(data[0], 0x02, "expected RootProof message type");
    assert!(data.len() > 1);
    drop(ws);
    h.shutdown().await;
}

#[tokio::test]
async fn websocket_sync_rejects_oversized_binary_frame() {
    let h = TestHarness::new().await;
    let mut ws = connect_sync_ws(authed_ws_request(&h), "oversized frame sync WebSocket").await;

    match send_oversized_sync_frame(&mut ws).await {
        OversizedSyncSendOutcome::Sent => {
            assert_sync_ws_close_or_eof(&mut ws, "oversized frame rejection").await;
        }
        OversizedSyncSendOutcome::Closed => {}
    }
    drop(ws);
    h.shutdown().await;
}

#[tokio::test]
async fn websocket_sync_bye_closes() {
    let h = TestHarness::new().await;
    let mut ws = connect_sync_ws(authed_ws_request(&h), "Bye sync WebSocket").await;
    send_sync_ws_binary(&mut ws, vec![0x07], "Bye sync WebSocket frame").await;
    assert_sync_ws_close_or_eof(&mut ws, "Bye").await;
    drop(ws);
    h.shutdown().await;
}
