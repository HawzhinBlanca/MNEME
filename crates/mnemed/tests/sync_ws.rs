use super::common::TestHarness;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;

type ClientWebSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

const SYNC_WS_BINARY_FRAME_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);
const SYNC_WS_CLOSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OversizedSyncSendOutcome {
    Sent,
    Closed,
}

async fn recv_sync_ws_binary_frame(
    ws: &mut ClientWebSocket,
    context: &str,
) -> Result<Vec<u8>, String> {
    match tokio::time::timeout(SYNC_WS_BINARY_FRAME_TIMEOUT, ws.next()).await {
        Ok(Some(Ok(Message::Binary(data)))) => Ok(data.to_vec()),
        Ok(Some(Ok(other))) => Err(format!("{context} expected binary frame, got {other:?}")),
        Ok(Some(Err(err))) => Err(format!("{context} websocket read failed: {err}")),
        Ok(None) => Err(format!("{context} websocket closed before response")),
        Err(_) => Err(format!("{context} timed out waiting for binary response")),
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
    match tokio::time::timeout(SYNC_WS_CLOSE_TIMEOUT, ws.next()).await {
        Ok(Some(Ok(Message::Close(_)))) | Ok(Some(Err(_))) | Ok(None) => Ok(()),
        Ok(Some(Ok(other))) => Err(format!("{context} produced unexpected response: {other:?}")),
        Err(_) => Err(format!(
            "{context} left sync websocket open without close or EOF"
        )),
    }
}

fn authed_ws_request(h: &TestHarness) -> tokio_tungstenite::tungstenite::http::Request<()> {
    let ws_url = format!("ws://{}/v1/sync", h.server.http_addr);
    let mut req = ws_url.into_client_request().expect("ws request");
    req.headers_mut().insert(
        "Authorization",
        HeaderValue::from_str(&h.agent_auth_header()).expect("auth header"),
    );
    req
}

fn malformed_auth_ws_request(h: &TestHarness) -> tokio_tungstenite::tungstenite::http::Request<()> {
    let ws_url = format!("ws://{}/v1/sync", h.server.http_addr);
    let mut req = ws_url.into_client_request().expect("ws request");
    req.headers_mut()
        .insert("Authorization", HeaderValue::from_static("Bearer oA=="));
    req
}

fn oversized_auth_ws_request(h: &TestHarness) -> tokio_tungstenite::tungstenite::http::Request<()> {
    let ws_url = format!("ws://{}/v1/sync", h.server.http_addr);
    let mut req = ws_url.into_client_request().expect("ws request");
    let header = format!(
        "Bearer {}",
        "A".repeat(mnemed::state::MAX_CAPABILITY_B64_LEN + 1)
    );
    req.headers_mut().insert(
        "Authorization",
        HeaderValue::from_str(&header).expect("auth header"),
    );
    req
}

#[tokio::test]
async fn websocket_sync_requires_auth() {
    let h = TestHarness::new().await;
    let ws_url = format!("ws://{}/v1/sync", h.server.http_addr);
    let err = connect_async(&ws_url)
        .await
        .expect_err("unauthenticated sync websocket must fail closed");
    let msg = err.to_string();
    assert!(
        msg.contains("401") || msg.contains("HTTP error"),
        "expected HTTP auth rejection, got {msg}"
    );
    h.shutdown().await;
}

#[tokio::test]
async fn websocket_sync_rejects_malformed_header_capability_without_server_error() {
    let h = TestHarness::new().await;
    let err = connect_async(malformed_auth_ws_request(&h))
        .await
        .expect_err("malformed sync capability must fail closed");
    let msg = err.to_string();
    assert!(
        msg.contains("401") || msg.contains("HTTP error"),
        "expected HTTP auth rejection, got {msg}"
    );
    assert!(
        !msg.contains("500"),
        "malformed sync capability leaked as server error: {msg}"
    );
    h.shutdown().await;
}

#[tokio::test]
async fn websocket_sync_rejects_malformed_query_capability_without_server_error() {
    let h = TestHarness::new().await;
    let ws_url = format!("ws://{}/v1/sync?cap=oA%3D%3D", h.server.http_addr);
    let err = connect_async(&ws_url)
        .await
        .expect_err("malformed sync query capability must fail closed");
    let msg = err.to_string();
    assert!(
        msg.contains("401") || msg.contains("HTTP error"),
        "expected HTTP auth rejection, got {msg}"
    );
    assert!(
        !msg.contains("500"),
        "malformed sync query capability leaked as server error: {msg}"
    );
    h.shutdown().await;
}

#[tokio::test]
async fn websocket_sync_rejects_oversized_header_capability_without_server_error() {
    let h = TestHarness::new().await;
    let err = connect_async(oversized_auth_ws_request(&h))
        .await
        .expect_err("oversized sync capability must fail closed");
    let msg = err.to_string();
    assert!(
        msg.contains("401") || msg.contains("HTTP error"),
        "expected HTTP auth rejection, got {msg}"
    );
    assert!(
        !msg.contains("500"),
        "oversized sync capability leaked as server error: {msg}"
    );
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
    let err = connect_async(&ws_url)
        .await
        .expect_err("oversized sync query capability must fail closed");
    let msg = err.to_string();
    assert!(
        msg.contains("401") || msg.contains("HTTP error"),
        "expected HTTP auth rejection, got {msg}"
    );
    assert!(
        !msg.contains("500"),
        "oversized sync query capability leaked as server error: {msg}"
    );
    h.shutdown().await;
}

#[tokio::test]
async fn websocket_sync_hello_root_proof() {
    let h = TestHarness::new().await;
    let (mut ws, _) = connect_async(authed_ws_request(&h))
        .await
        .expect("ws connect");

    let hello = mnemed::sync::encode_hello(&h.server.state, [0x02; 16]).expect("hello");
    ws.send(tokio_tungstenite::tungstenite::Message::Binary(
        hello.into(),
    ))
    .await
    .expect("send hello");

    let data = recv_sync_ws_binary_frame(&mut ws, "RootProof response")
        .await
        .expect("RootProof binary response");
    assert_eq!(data[0], 0x02, "expected RootProof message type");
    assert!(data.len() > 1);
    drop(ws);
    h.shutdown().await;
}

#[tokio::test]
async fn websocket_sync_rejects_oversized_binary_frame() {
    let h = TestHarness::new().await;
    let (mut ws, _) = connect_async(authed_ws_request(&h))
        .await
        .expect("ws connect");

    match send_oversized_sync_frame(&mut ws).await {
        OversizedSyncSendOutcome::Sent => {
            expect_sync_ws_close_or_eof(&mut ws, "oversized frame rejection")
                .await
                .expect("oversized frame rejection closes or EOFs");
        }
        OversizedSyncSendOutcome::Closed => {}
    }
    drop(ws);
    h.shutdown().await;
}

#[tokio::test]
async fn websocket_sync_bye_closes() {
    let h = TestHarness::new().await;
    let (mut ws, _) = connect_async(authed_ws_request(&h))
        .await
        .expect("ws connect");
    ws.send(tokio_tungstenite::tungstenite::Message::Binary(
        vec![0x07].into(),
    ))
    .await
    .expect("bye");
    expect_sync_ws_close_or_eof(&mut ws, "Bye")
        .await
        .expect("Bye closes or EOFs");
    drop(ws);
    h.shutdown().await;
}
