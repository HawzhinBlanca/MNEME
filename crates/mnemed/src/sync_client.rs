//! Canonical §11 WebSocket **client** for anti-entropy pull (blueprint §11).
//!
//! Production counterpart to the in-test `pull_canonical` helper: operators and
//! `mneme sync pull` use this module; the server side remains in [`super::sync`].

use crate::audit;
use futures_util::{SinkExt, StreamExt};
use mneme_core::MnemeError;
use mneme_core::hash_obj;
use mneme_store::Store;
use std::time::Duration;
use tokio_tungstenite::tungstenite::Error as WebSocketError;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async_with_config};

const MSG_BYE: u8 = 0x07;
const DEFAULT_SYNC_CLIENT_IO_TIMEOUT: Duration = Duration::from_secs(5);

type SyncClientWebSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
type SyncClientNextMessage = Option<Result<Message, WebSocketError>>;
type TimedSyncClientMessage = Result<SyncClientNextMessage, tokio::time::error::Elapsed>;
type TimedSyncClientOperation<T, E> = Result<Result<T, E>, tokio::time::error::Elapsed>;

enum SyncClientTimedMessageOutcome {
    Received(Message),
    ReadFailed(WebSocketError),
    Closed,
    TimedOut,
}

enum SyncClientFrameOutcome {
    Binary(Vec<u8>),
    KeepAlive,
    Closed,
    Unexpected(&'static str),
}

enum SyncClientByeSendOutcome {
    Sent,
    Failed(MnemeError),
}

enum SyncClientIoTimeoutOutcome<T, E> {
    Completed(T),
    Failed(E),
    TimedOut,
}

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
        super::sync::encode_diff_request(local_root)
            .map_err(|err| sync_frame_error(peer_ws_url, "diff request encode", err))?,
        io_timeout,
    )
    .await?;

    let diff_frame = recv_binary(&mut ws, peer_ws_url, io_timeout).await?;
    let summaries = super::sync::decode_diff_response(&diff_frame)
        .map_err(|err| sync_frame_error(peer_ws_url, "diff response decode", err))?;

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
        send_bye_best_effort(&mut ws, peer_ws_url, io_timeout).await;
        return Ok(0);
    }

    send_binary(
        &mut ws,
        peer_ws_url,
        super::sync::encode_want_objects_canonical(&want)
            .map_err(|err| sync_frame_error(peer_ws_url, "want-objects encode", err))?,
        io_timeout,
    )
    .await?;

    let have_frame = recv_binary(&mut ws, peer_ws_url, io_timeout).await?;
    let snapshot = super::sync::decode_have_objects_canonical(&have_frame)
        .map_err(|err| sync_have_objects_decode_error(peer_ws_url, err))?;
    let fetched = snapshot
        .objects
        .iter()
        .filter(|bytes| !local_ids.contains(&hash_obj(bytes)))
        .count();
    store.merge_from_snapshot(&snapshot)?;
    send_bye_best_effort(&mut ws, peer_ws_url, io_timeout).await;
    Ok(fetched)
}

async fn recv_binary(
    ws: &mut SyncClientWebSocket,
    peer_ws_url: &str,
    io_timeout: Duration,
) -> Result<Vec<u8>, MnemeError> {
    loop {
        let frame = match recv_sync_client_message_with_timeout(ws, io_timeout).await {
            SyncClientTimedMessageOutcome::Received(frame) => frame,
            SyncClientTimedMessageOutcome::ReadFailed(e) => {
                return Err(sync_io_error(peer_ws_url, e.to_string()));
            }
            SyncClientTimedMessageOutcome::Closed => {
                return Err(sync_io_error(peer_ws_url, "websocket closed"));
            }
            SyncClientTimedMessageOutcome::TimedOut => {
                return Err(sync_io_error(peer_ws_url, "websocket receive timed out"));
            }
        };
        match classify_sync_client_frame(frame) {
            SyncClientFrameOutcome::Binary(data) => return Ok(data),
            SyncClientFrameOutcome::KeepAlive => continue,
            SyncClientFrameOutcome::Closed => {
                return Err(sync_io_error(peer_ws_url, "websocket closed"));
            }
            SyncClientFrameOutcome::Unexpected(kind) => {
                return Err(sync_io_error(peer_ws_url, kind));
            }
        }
    }
}

fn classify_sync_client_frame(frame: Message) -> SyncClientFrameOutcome {
    match frame {
        Message::Binary(data) => SyncClientFrameOutcome::Binary(data.to_vec()),
        Message::Ping(_) | Message::Pong(_) => SyncClientFrameOutcome::KeepAlive,
        Message::Close(_) => SyncClientFrameOutcome::Closed,
        Message::Text(_) => SyncClientFrameOutcome::Unexpected("unexpected websocket text frame"),
        Message::Frame(_) => SyncClientFrameOutcome::Unexpected("unexpected raw websocket frame"),
    }
}

async fn recv_sync_client_message_with_timeout(
    ws: &mut SyncClientWebSocket,
    io_timeout: Duration,
) -> SyncClientTimedMessageOutcome {
    classify_sync_client_timed_message(tokio::time::timeout(io_timeout, ws.next()).await)
}

fn classify_sync_client_timed_message(
    read_result: TimedSyncClientMessage,
) -> SyncClientTimedMessageOutcome {
    match read_result {
        Ok(Some(Ok(frame))) => SyncClientTimedMessageOutcome::Received(frame),
        Ok(Some(Err(e))) => SyncClientTimedMessageOutcome::ReadFailed(e),
        Ok(None) => SyncClientTimedMessageOutcome::Closed,
        Err(_) => SyncClientTimedMessageOutcome::TimedOut,
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

async fn send_bye_best_effort(
    ws: &mut SyncClientWebSocket,
    peer_ws_url: &str,
    io_timeout: Duration,
) {
    let outcome = classify_sync_client_bye_send(
        send_binary(ws, peer_ws_url, vec![MSG_BYE], io_timeout).await,
    );
    observe_sync_client_bye_send(outcome, peer_ws_url);
}

fn classify_sync_client_bye_send(result: Result<(), MnemeError>) -> SyncClientByeSendOutcome {
    match result {
        Ok(()) => SyncClientByeSendOutcome::Sent,
        Err(err) => SyncClientByeSendOutcome::Failed(err),
    }
}

fn observe_sync_client_bye_send(outcome: SyncClientByeSendOutcome, peer_ws_url: &str) {
    match outcome {
        SyncClientByeSendOutcome::Sent => {}
        SyncClientByeSendOutcome::Failed(err) => {
            tracing::debug!("sync client best-effort BYE send failed for {peer_ws_url}: {err}");
        }
    }
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
    match classify_sync_client_io_timeout(tokio::time::timeout(io_timeout, future).await) {
        SyncClientIoTimeoutOutcome::Completed(value) => Ok(value),
        SyncClientIoTimeoutOutcome::Failed(e) => Err(sync_io_error(peer_ws_url, e.to_string())),
        SyncClientIoTimeoutOutcome::TimedOut => {
            Err(sync_io_error(peer_ws_url, format!("{operation} timed out")))
        }
    }
}

fn classify_sync_client_io_timeout<T, E>(
    operation_result: TimedSyncClientOperation<T, E>,
) -> SyncClientIoTimeoutOutcome<T, E> {
    match operation_result {
        Ok(Ok(value)) => SyncClientIoTimeoutOutcome::Completed(value),
        Ok(Err(e)) => SyncClientIoTimeoutOutcome::Failed(e),
        Err(_) => SyncClientIoTimeoutOutcome::TimedOut,
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
    sync_peer_dropped_error(peer_ws_url, kind)
}

fn sync_peer_dropped_error(peer_ws_url: &str, kind: impl Into<String>) -> MnemeError {
    let kind = kind.into();
    audit::emit_sync_peer_dropped(peer_ws_url, &kind);
    MnemeError::IoFailed {
        path: peer_ws_url.to_string(),
        kind,
    }
}

fn sync_frame_error(
    peer_ws_url: &str,
    operation: &str,
    err: super::sync::SyncFrameError,
) -> MnemeError {
    sync_io_error(peer_ws_url, format!("{operation} failed: {err}"))
}

fn sync_have_objects_decode_error(
    peer_ws_url: &str,
    err: super::sync::SyncFrameError,
) -> MnemeError {
    match err {
        super::sync::SyncFrameError::ObjectTampered => {
            audit::emit_sync_peer_dropped(
                peer_ws_url,
                "have-objects decode failed: canonical sync object tampered",
            );
            MnemeError::ObjectTampered
        }
        err => sync_frame_error(peer_ws_url, "have-objects decode", err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type SyncClientClassifierCheck = Result<(), String>;

    fn assert_sync_client_received_binary_frame(
        outcome: SyncClientTimedMessageOutcome,
        expected: &[u8],
    ) {
        let frame = expect_sync_client_received_binary_frame(outcome, expected);

        assert_sync_client_classifier_check_passed(frame);
    }

    fn expect_sync_client_received_binary_frame(
        outcome: SyncClientTimedMessageOutcome,
        expected: &[u8],
    ) -> SyncClientClassifierCheck {
        match outcome {
            SyncClientTimedMessageOutcome::Received(Message::Binary(data))
                if data.as_ref() == expected =>
            {
                Ok(())
            }
            SyncClientTimedMessageOutcome::Received(Message::Binary(_)) => {
                Err("received binary frame payload changed".into())
            }
            _ => Err("received binary frame should be preserved".into()),
        }
    }

    fn assert_sync_client_completed_io_timeout_value(
        outcome: SyncClientIoTimeoutOutcome<usize, &str>,
        expected: usize,
    ) {
        let completed = expect_sync_client_completed_io_timeout_value(outcome, expected);

        assert_sync_client_classifier_check_passed(completed);
    }

    fn expect_sync_client_completed_io_timeout_value(
        outcome: SyncClientIoTimeoutOutcome<usize, &str>,
        expected: usize,
    ) -> SyncClientClassifierCheck {
        match outcome {
            SyncClientIoTimeoutOutcome::Completed(value) if value == expected => Ok(()),
            SyncClientIoTimeoutOutcome::Completed(_) => {
                Err("completed operation value changed".into())
            }
            _ => Err("completed operation should preserve value".into()),
        }
    }

    fn assert_sync_client_failed_io_timeout_error(
        outcome: SyncClientIoTimeoutOutcome<usize, &str>,
        expected: &str,
    ) {
        let failed = expect_sync_client_failed_io_timeout_error(outcome, expected);

        assert_sync_client_classifier_check_passed(failed);
    }

    fn expect_sync_client_failed_io_timeout_error(
        outcome: SyncClientIoTimeoutOutcome<usize, &str>,
        expected: &str,
    ) -> SyncClientClassifierCheck {
        match outcome {
            SyncClientIoTimeoutOutcome::Failed(err) if err == expected => Ok(()),
            SyncClientIoTimeoutOutcome::Failed(_) => Err("failed operation error changed".into()),
            _ => Err("failed operation should preserve error".into()),
        }
    }

    fn assert_sync_client_binary_frame_payload(outcome: SyncClientFrameOutcome, expected: &[u8]) {
        let payload = expect_sync_client_binary_frame_payload(outcome, expected);

        assert_sync_client_classifier_check_passed(payload);
    }

    fn expect_sync_client_binary_frame_payload(
        outcome: SyncClientFrameOutcome,
        expected: &[u8],
    ) -> SyncClientClassifierCheck {
        match outcome {
            SyncClientFrameOutcome::Binary(data) if data.as_slice() == expected => Ok(()),
            SyncClientFrameOutcome::Binary(_) => Err("binary frame payload changed".into()),
            _ => Err("binary frame should be classified as payload".into()),
        }
    }

    fn assert_sync_client_classifier_check_passed(check: SyncClientClassifierCheck) {
        match check {
            Ok(()) => {}
            Err(message) => panic!("{message}"),
        }
    }

    #[test]
    fn sync_client_have_objects_decode_error_preserves_object_tamper() {
        let err = sync_have_objects_decode_error(
            "ws://peer.example/v1/sync",
            crate::sync::SyncFrameError::ObjectTampered,
        );

        assert_eq!(err, MnemeError::ObjectTampered);
    }

    #[test]
    fn sync_client_have_objects_decode_error_wraps_wire_failures_as_io() {
        let err = sync_have_objects_decode_error(
            "ws://peer.example/v1/sync",
            crate::sync::SyncFrameError::UnexpectedMessageType,
        );

        match err {
            MnemeError::IoFailed { path, kind } => {
                assert_eq!(path, "ws://peer.example/v1/sync");
                assert!(
                    kind.contains("have-objects decode failed"),
                    "I/O wrapper should preserve operation context: {kind}"
                );
                assert!(
                    kind.contains("unexpected canonical message type"),
                    "I/O wrapper should preserve sync frame error text: {kind}"
                );
            }
            other => panic!("expected sync client I/O wrapper, got {other:?}"),
        }
    }

    #[test]
    fn sync_client_timed_message_classifier_preserves_received_frame() {
        let outcome = classify_sync_client_timed_message(Ok(Some(Ok(Message::Binary(
            vec![0x04, 0xaa].into(),
        )))));

        assert_sync_client_received_binary_frame(outcome, &[0x04, 0xaa]);
    }

    #[test]
    fn sync_client_timed_message_classifier_marks_read_failure_and_close() {
        assert!(matches!(
            classify_sync_client_timed_message(Ok(Some(Err(WebSocketError::ConnectionClosed)))),
            SyncClientTimedMessageOutcome::ReadFailed(_)
        ));
        assert!(matches!(
            classify_sync_client_timed_message(Ok(None)),
            SyncClientTimedMessageOutcome::Closed
        ));
    }

    #[tokio::test]
    async fn sync_client_timed_message_classifier_marks_timeout() {
        let read_result = tokio::time::timeout(
            Duration::ZERO,
            std::future::pending::<SyncClientNextMessage>(),
        )
        .await;

        assert!(matches!(
            classify_sync_client_timed_message(read_result),
            SyncClientTimedMessageOutcome::TimedOut
        ));
    }

    #[test]
    fn sync_client_io_timeout_classifier_preserves_completed_and_failed_operations() {
        let completed = classify_sync_client_io_timeout::<usize, &str>(Ok(Ok(7)));
        let failed = classify_sync_client_io_timeout::<usize, &str>(Ok(Err("write failed")));

        assert_sync_client_completed_io_timeout_value(completed, 7);
        assert_sync_client_failed_io_timeout_error(failed, "write failed");
    }

    #[tokio::test]
    async fn sync_client_io_timeout_classifier_marks_timeout() {
        let operation_result = tokio::time::timeout(
            Duration::ZERO,
            std::future::pending::<Result<(), &'static str>>(),
        )
        .await;

        assert!(matches!(
            classify_sync_client_io_timeout(operation_result),
            SyncClientIoTimeoutOutcome::TimedOut
        ));
    }

    #[test]
    fn sync_client_frame_classifier_preserves_binary_payload() {
        let outcome = classify_sync_client_frame(Message::Binary(vec![0x04, 0xaa].into()));

        assert_sync_client_binary_frame_payload(outcome, &[0x04, 0xaa]);
    }

    #[test]
    fn sync_client_frame_classifier_tolerates_keepalives() {
        assert!(matches!(
            classify_sync_client_frame(Message::Ping(Vec::new().into())),
            SyncClientFrameOutcome::KeepAlive
        ));
        assert!(matches!(
            classify_sync_client_frame(Message::Pong(Vec::new().into())),
            SyncClientFrameOutcome::KeepAlive
        ));
    }

    #[test]
    fn sync_client_frame_classifier_rejects_close_and_text() {
        assert!(matches!(
            classify_sync_client_frame(Message::Close(None)),
            SyncClientFrameOutcome::Closed
        ));
        assert!(matches!(
            classify_sync_client_frame(Message::Text("not binary".into())),
            SyncClientFrameOutcome::Unexpected("unexpected websocket text frame")
        ));
    }
}
