//! Canonical §11 WebSocket **client** for anti-entropy pull (blueprint §11).
//!
//! Production counterpart to the in-test `pull_canonical` helper: operators and
//! `mneme sync pull` use this module; the server side remains in [`super::sync`].

use futures_util::{SinkExt, StreamExt};
use mneme_core::MnemeError;
use mneme_core::hash_obj;
use mneme_store::Store;
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async_with_config};

const MSG_BYE: u8 = 0x07;
const DEFAULT_SYNC_CLIENT_IO_TIMEOUT: Duration = Duration::from_secs(5);

type SyncClientWebSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// Pull the peer's divergent object delta over canonical §11 frames and merge into `store`.
///
/// Wire sequence: `DiffReq` → `DiffResp` → (local delta) → `WantObjects` → `HaveObjects`
/// → [`Store::merge_from_snapshot`] (re-hash + writer authorization inside the kernel).
///
/// Returns the number of objects fetched and merged (0 if already converged).
pub async fn pull_canonical(store: &mut Store, peer_ws_url: &str) -> Result<usize, MnemeError> {
    pull_canonical_inner(store, peer_ws_url, None, DEFAULT_SYNC_CLIENT_IO_TIMEOUT).await
}

pub async fn pull_canonical_with_cap(
    store: &mut Store,
    peer_ws_url: &str,
    cap_b64: &str,
) -> Result<usize, MnemeError> {
    pull_canonical_inner(
        store,
        peer_ws_url,
        Some(cap_b64),
        DEFAULT_SYNC_CLIENT_IO_TIMEOUT,
    )
    .await
}

pub async fn pull_canonical_with_timeout(
    store: &mut Store,
    peer_ws_url: &str,
    io_timeout: Duration,
) -> Result<usize, MnemeError> {
    pull_canonical_inner(store, peer_ws_url, None, io_timeout).await
}

pub async fn pull_canonical_with_cap_and_timeout(
    store: &mut Store,
    peer_ws_url: &str,
    cap_b64: &str,
    io_timeout: Duration,
) -> Result<usize, MnemeError> {
    pull_canonical_inner(store, peer_ws_url, Some(cap_b64), io_timeout).await
}

async fn pull_canonical_inner(
    store: &mut Store,
    peer_ws_url: &str,
    cap_b64: Option<&str>,
    io_timeout: Duration,
) -> Result<usize, MnemeError> {
    let io_timeout = normalize_io_timeout(io_timeout);
    let mut req = peer_ws_url
        .into_client_request()
        .map_err(|e| sync_io_error(peer_ws_url, e.to_string()))?;
    if let Some(cap_b64) = cap_b64 {
        let auth = format!("Bearer {cap_b64}");
        let header =
            HeaderValue::from_str(&auth).map_err(|e| sync_io_error(peer_ws_url, e.to_string()))?;
        req.headers_mut().insert("Authorization", header);
    }
    let (mut ws, _) = with_io_timeout(
        peer_ws_url,
        "websocket connect",
        io_timeout,
        connect_async_with_config(req, Some(sync_client_websocket_config()), false),
    )
    .await?;
    let local_root = store.current_root()?.key_index_root;
    send_binary(
        &mut ws,
        peer_ws_url,
        super::sync::encode_diff_request(local_root).ok_or(MnemeError::SchemaDrift)?,
        io_timeout,
    )
    .await?;

    let diff_frame = recv_binary(&mut ws, peer_ws_url, io_timeout).await?;
    let summaries =
        super::sync::decode_diff_response(&diff_frame).ok_or(MnemeError::SchemaDrift)?;

    let local_ids: std::collections::HashSet<[u8; 32]> = store
        .export_sync_manifest()
        .object_ids
        .into_iter()
        .collect();
    let want: Vec<[u8; 32]> = summaries
        .into_iter()
        .filter(|object_id| !local_ids.contains(object_id))
        .collect();
    if want.is_empty() {
        send_binary(&mut ws, peer_ws_url, vec![MSG_BYE], io_timeout)
            .await
            .ok();
        return Ok(0);
    }

    send_binary(
        &mut ws,
        peer_ws_url,
        super::sync::encode_want_objects_canonical(&want).ok_or(MnemeError::SchemaDrift)?,
        io_timeout,
    )
    .await?;

    let have_frame = recv_binary(&mut ws, peer_ws_url, io_timeout).await?;
    let snapshot = super::sync::decode_have_objects_canonical(&have_frame)?;
    let fetched = snapshot
        .objects
        .iter()
        .filter(|bytes| !local_ids.contains(&hash_obj(bytes)))
        .count();
    store.merge_from_snapshot(&snapshot)?;
    send_binary(&mut ws, peer_ws_url, vec![MSG_BYE], io_timeout)
        .await
        .ok();
    Ok(fetched)
}

async fn recv_binary(
    ws: &mut SyncClientWebSocket,
    peer_ws_url: &str,
    io_timeout: Duration,
) -> Result<Vec<u8>, MnemeError> {
    loop {
        let frame = match tokio::time::timeout(io_timeout, ws.next()).await {
            Ok(Some(Ok(frame))) => frame,
            Ok(Some(Err(e))) => return Err(sync_io_error(peer_ws_url, e.to_string())),
            Ok(None) => return Err(sync_io_error(peer_ws_url, "websocket closed")),
            Err(_) => return Err(sync_io_error(peer_ws_url, "websocket receive timed out")),
        };
        if let Message::Binary(data) = frame {
            return Ok(data.to_vec());
        }
    }
}

async fn send_binary(
    ws: &mut SyncClientWebSocket,
    peer_ws_url: &str,
    bytes: Vec<u8>,
    io_timeout: Duration,
) -> Result<(), MnemeError> {
    with_io_timeout(
        peer_ws_url,
        "websocket send",
        io_timeout,
        ws.send(Message::Binary(bytes.into())),
    )
    .await
}

async fn with_io_timeout<T, E>(
    peer_ws_url: &str,
    operation: &str,
    io_timeout: Duration,
    future: impl std::future::Future<Output = Result<T, E>>,
) -> Result<T, MnemeError>
where
    E: std::fmt::Display,
{
    match tokio::time::timeout(io_timeout, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) => Err(sync_io_error(peer_ws_url, e.to_string())),
        Err(_) => Err(sync_io_error(peer_ws_url, format!("{operation} timed out"))),
    }
}

fn sync_client_websocket_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(super::sync::SYNC_MAX_FRAME))
        .max_frame_size(Some(super::sync::SYNC_MAX_FRAME))
}

fn normalize_io_timeout(io_timeout: Duration) -> Duration {
    if io_timeout.is_zero() {
        DEFAULT_SYNC_CLIENT_IO_TIMEOUT
    } else {
        io_timeout
    }
}

fn sync_io_error(peer_ws_url: &str, kind: impl Into<String>) -> MnemeError {
    MnemeError::IoFailed {
        path: peer_ws_url.to_string(),
        kind: kind.into(),
    }
}
