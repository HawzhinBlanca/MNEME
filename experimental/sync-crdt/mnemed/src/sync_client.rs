//! Canonical §11 WebSocket **client** for anti-entropy pull (blueprint §11).
//!
//! Production counterpart to the in-test `pull_canonical` helper: operators and
//! `mneme sync pull` use this module; the server side remains in [`super::sync`].

use futures_util::{SinkExt, StreamExt};
use mneme_core::MnemeError;
use mneme_core::hash_obj;
use mneme_store::Store;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;

const MSG_BYE: u8 = 0x07;

/// Pull the peer's divergent object delta over canonical §11 frames and merge into `store`.
///
/// Wire sequence: `DiffReq` → `DiffResp` → (local delta) → `WantObjects` → `HaveObjects`
/// → [`Store::merge_from_snapshot`] (re-hash + writer authorization inside the kernel).
///
/// Returns the number of objects fetched and merged (0 if already converged).
pub async fn pull_canonical(store: &mut Store, peer_ws_url: &str) -> Result<usize, MnemeError> {
    pull_canonical_inner(store, peer_ws_url, None).await
}

pub async fn pull_canonical_with_cap(
    store: &mut Store,
    peer_ws_url: &str,
    cap_b64: &str,
) -> Result<usize, MnemeError> {
    pull_canonical_inner(store, peer_ws_url, Some(cap_b64)).await
}

async fn pull_canonical_inner(
    store: &mut Store,
    peer_ws_url: &str,
    cap_b64: Option<&str>,
) -> Result<usize, MnemeError> {
    let connect_result: Result<
        (
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
            tokio_tungstenite::tungstenite::handshake::client::Response,
        ),
        tokio_tungstenite::tungstenite::Error,
    > = if let Some(cap_b64) = cap_b64 {
        let mut req = peer_ws_url
            .into_client_request()
            .map_err(|e| MnemeError::IoFailed {
                path: peer_ws_url.to_string(),
                kind: e.to_string(),
            })?;
        let auth = format!("Bearer {cap_b64}");
        let header = HeaderValue::from_str(&auth).map_err(|e| MnemeError::IoFailed {
            path: peer_ws_url.to_string(),
            kind: e.to_string(),
        })?;
        req.headers_mut().insert("Authorization", header);
        connect_async(req).await
    } else {
        connect_async(peer_ws_url).await
    };
    let (mut ws, _) = connect_result.map_err(|e| MnemeError::IoFailed {
        path: peer_ws_url.to_string(),
        kind: e.to_string(),
    })?;
    let local_root = store.current_root()?.key_index_root;
    ws.send(Message::Binary(
        super::sync::encode_diff_request(local_root)
            .ok_or(MnemeError::SchemaDrift)?
            .into(),
    ))
    .await
    .map_err(|e| MnemeError::IoFailed {
        path: peer_ws_url.to_string(),
        kind: e.to_string(),
    })?;

    let diff_frame = recv_binary(&mut ws, peer_ws_url).await?;
    let summaries =
        super::sync::decode_diff_response(&diff_frame).ok_or(MnemeError::SchemaDrift)?;

    let local_ids: std::collections::HashSet<[u8; 32]> = store
        .export_sync_manifest()
        .object_ids
        .into_iter()
        .collect();
    let want: Vec<[u8; 32]> = summaries;
    if want.is_empty() {
        ws.send(Message::Binary(vec![MSG_BYE].into())).await.ok();
        return Ok(0);
    }

    ws.send(Message::Binary(
        super::sync::encode_want_objects_canonical(&want)
            .ok_or(MnemeError::SchemaDrift)?
            .into(),
    ))
    .await
    .map_err(|e| MnemeError::IoFailed {
        path: peer_ws_url.to_string(),
        kind: e.to_string(),
    })?;

    let have_frame = recv_binary(&mut ws, peer_ws_url).await?;
    let snapshot = super::sync::decode_have_objects_canonical(&have_frame)?;
    let fetched = snapshot
        .objects
        .iter()
        .filter(|bytes| !local_ids.contains(&hash_obj(bytes)))
        .count();
    store.merge_from_snapshot(&snapshot)?;
    ws.send(Message::Binary(vec![MSG_BYE].into())).await.ok();
    Ok(fetched)
}

async fn recv_binary(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    peer_ws_url: &str,
) -> Result<Vec<u8>, MnemeError> {
    loop {
        let frame = ws
            .next()
            .await
            .ok_or(MnemeError::IoFailed {
                path: peer_ws_url.to_string(),
                kind: "websocket closed".into(),
            })?
            .map_err(|e| MnemeError::IoFailed {
                path: peer_ws_url.to_string(),
                kind: e.to_string(),
            })?;
        if let Message::Binary(data) = frame {
            return Ok(data.to_vec());
        }
    }
}
