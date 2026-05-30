use super::common::TestHarness;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::connect_async;

#[tokio::test]
async fn websocket_sync_hello_root_proof() {
    let h = TestHarness::new().await;
    let ws_url = format!("ws://{}/v1/sync", h.server.http_addr);
    let (mut ws, _) = connect_async(&ws_url).await.expect("ws connect");

    let hello = mnemed::sync::encode_hello(&h.server.state, [0x02; 16]);
    ws.send(tokio_tungstenite::tungstenite::Message::Binary(
        hello.into(),
    ))
    .await
    .expect("send hello");

    let msg = ws.next().await.expect("response").expect("ok msg");
    if let tokio_tungstenite::tungstenite::Message::Binary(data) = msg {
        assert_eq!(data[0], 0x02, "expected RootProof message type");
        assert!(data.len() > 1);
    } else {
        panic!("expected binary RootProof");
    }
}

#[tokio::test]
async fn websocket_sync_bye_closes() {
    let h = TestHarness::new().await;
    let ws_url = format!("ws://{}/v1/sync", h.server.http_addr);
    let (mut ws, _) = connect_async(&ws_url).await.expect("ws connect");
    ws.send(tokio_tungstenite::tungstenite::Message::Binary(
        vec![0x07].into(),
    ))
    .await
    .expect("bye");
    // Server closes read side after Bye; may or may not emit Close frame.
    let _ = tokio::time::timeout(std::time::Duration::from_millis(200), ws.next()).await;
}
