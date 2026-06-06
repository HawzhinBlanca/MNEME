#[test]
fn sync_client_reuses_server_sync_frame_limit() {
    let sync_client = include_str!("../src/sync_client.rs");

    assert!(
        !sync_client.contains("SYNC_CLIENT_MAX_FRAME"),
        "sync client must reuse sync::SYNC_MAX_FRAME instead of defining its own frame cap"
    );
    assert!(
        sync_client.contains("sync::SYNC_MAX_FRAME"),
        "sync client WebSocket config must reference the server sync frame cap"
    );
}

#[test]
fn v11_object_sync_tests_do_not_abort_fake_peers() {
    let v11_object_sync = include_str!("v11_object_sync.rs");

    assert!(
        !v11_object_sync.contains(".abort()"),
        "v11 object sync fake peers should observe client close and join, not use abort-based cleanup"
    );
}

#[test]
fn v11_object_sync_fake_peers_assert_close_outcomes() {
    let v11_object_sync = include_str!("v11_object_sync.rs");

    assert!(
        !v11_object_sync.contains("let _ = ws.next().await"),
        "v11 object sync fake peers should assert close outcomes instead of discarding ws.next()"
    );
    assert!(
        !v11_object_sync.contains("while ws.next().await.is_some() {}"),
        "v11 object sync fake peers should bound and assert close drains"
    );
    assert!(
        v11_object_sync.contains("expect_fake_peer_close(&mut ws"),
        "v11 object sync fake peers should use the shared close/EOF assertion helper"
    );
    assert!(
        !v11_object_sync.contains("tokio::time::timeout(Duration::from_secs(1), ws.next()).await"),
        "v11 object sync fake-peer close observation should use a named close timeout"
    );
    assert!(
        v11_object_sync.contains("const FAKE_PEER_CLOSE_TIMEOUT: Duration"),
        "v11 object sync fake-peer close observation should share a bounded close timeout"
    );
    assert!(
        v11_object_sync.contains("tokio::time::timeout(FAKE_PEER_CLOSE_TIMEOUT, ws.next()).await"),
        "v11 object sync fake-peer close observation should route ws.next through the named timeout"
    );
}

#[test]
fn v11_object_sync_fake_peers_return_typed_results() {
    let v11_object_sync = include_str!("v11_object_sync.rs");

    assert!(
        !v11_object_sync.contains("JoinHandle<()>"),
        "v11 object sync fake peers should return typed task results instead of opaque unit joins"
    );
    assert!(
        v11_object_sync.contains("type FakePeerResult = Result<(), String>"),
        "v11 object sync fake peers should share a typed peer-result contract"
    );
}

#[test]
fn v11_object_sync_vector_fake_peers_return_typed_results() {
    let v11_object_sync = include_str!("v11_object_sync.rs");

    assert!(
        !v11_object_sync.contains("JoinHandle<Vec<[u8; 32]>>"),
        "v11 object sync fake peers that return wanted ids should preserve protocol failures as typed task results"
    );
    assert!(
        v11_object_sync.contains("type FakePeerWantedIds = Result<Vec<[u8; 32]>, String>"),
        "v11 object sync wanted-id fake peers should share a typed peer-result contract"
    );
    assert!(
        !v11_object_sync.contains("async fn recv_recorded_binary("),
        "v11 object sync fake peers should not use a panic-based binary frame receiver"
    );
}

#[test]
fn v11_object_sync_fake_peer_joins_use_shared_helpers() {
    let v11_object_sync = include_str!("v11_object_sync.rs");

    assert!(
        !v11_object_sync
            .contains("tokio::time::timeout(Duration::from_secs(1), peer)\n        .await"),
        "v11 object sync fake-peer joins should route timeout/join/result handling through shared helpers"
    );
    assert!(
        !v11_object_sync.contains(" peer joins\""),
        "v11 object sync fake-peer join messages should be centralized instead of repeated inline"
    );
    assert!(
        !v11_object_sync.contains(" peer completes\""),
        "v11 object sync fake-peer completion messages should be centralized instead of repeated inline"
    );
    assert!(
        v11_object_sync.contains("const FAKE_PEER_JOIN_TIMEOUT: Duration"),
        "v11 object sync fake-peer joins should share a bounded join timeout"
    );
    assert!(
        v11_object_sync.contains("async fn expect_fake_peer("),
        "v11 object sync unit fake peers should use a shared join helper"
    );
    assert!(
        v11_object_sync.contains("async fn expect_fake_peer_wanted_ids("),
        "v11 object sync wanted-id fake peers should use a shared join helper"
    );
    assert_eq!(
        v11_object_sync.matches("expect_fake_peer(peer,").count(),
        2,
        "both v11 unit fake-peer tests should route joins through the shared helper"
    );
    assert_eq!(
        v11_object_sync
            .matches("expect_fake_peer_wanted_ids(peer,")
            .count(),
        2,
        "both v11 wanted-id fake-peer tests should route joins through the shared helper"
    );
}

#[test]
fn v11_object_sync_pull_canonical_deadlines_use_named_parameters() {
    let v11_object_sync = include_str!("v11_object_sync.rs");

    assert!(
        !v11_object_sync.contains("        Duration::from_secs(1),\n    )\n    .await"),
        "v11 canonical sync tests should use a named normal pull deadline"
    );
    assert!(
        !v11_object_sync.contains(
            "        Duration::from_millis(50),\n    )\n    .await\n    .expect_err(\"stalled peer must trip the sync client deadline\")"
        ),
        "v11 canonical stalled-peer test should use a named stalled pull deadline"
    );
    assert!(
        v11_object_sync.contains("const V11_PULL_CANONICAL_TEST_TIMEOUT: Duration"),
        "v11 canonical sync tests should share a normal pull deadline"
    );
    assert!(
        v11_object_sync.contains("const V11_PULL_CANONICAL_STALLED_PEER_TIMEOUT: Duration"),
        "v11 canonical stalled-peer test should share a stalled pull deadline"
    );
    assert_eq!(
        v11_object_sync
            .matches("        V11_PULL_CANONICAL_TEST_TIMEOUT,\n    )\n    .await")
            .count(),
        3,
        "all three non-stalled v11 canonical pulls should route through the normal deadline"
    );
    assert!(
        v11_object_sync.contains(
            "        V11_PULL_CANONICAL_STALLED_PEER_TIMEOUT,\n    )\n    .await\n    .expect_err(\"stalled peer must trip the sync client deadline\")"
        ),
        "v11 stalled canonical pull should route through the stalled deadline"
    );
}

#[test]
fn v11_object_sync_direct_reads_use_typed_binary_frame_reader() {
    let v11_object_sync = include_str!("v11_object_sync.rs");

    assert!(
        !v11_object_sync.contains("async fn recv_binary("),
        "v11 object sync direct WebSocket reads should use a typed binary frame reader"
    );
    assert!(
        v11_object_sync.contains("async fn recv_client_binary_frame("),
        "v11 object sync direct WebSocket reads should share a typed client frame reader"
    );
}

#[test]
fn v11_object_sync_fake_peer_accepts_are_bounded() {
    let v11_object_sync = include_str!("v11_object_sync.rs");

    assert!(
        !v11_object_sync.contains(".accept()\n            .await"),
        "v11 fake WebSocket peers should not wait forever in bare listener.accept().await calls"
    );
    assert!(
        !v11_object_sync.contains("tokio_tungstenite::accept_async(stream)\n            .await"),
        "v11 fake WebSocket peers should not wait forever in bare websocket handshakes"
    );
    assert!(
        v11_object_sync.contains("const FAKE_PEER_ACCEPT_TIMEOUT: Duration"),
        "v11 fake WebSocket peers should share a bounded accept/handshake timeout"
    );
    assert!(
        v11_object_sync.contains("async fn accept_fake_websocket_peer("),
        "v11 fake WebSocket peers should share a named accept/handshake helper"
    );
    assert!(
        v11_object_sync
            .contains("tokio::time::timeout(FAKE_PEER_ACCEPT_TIMEOUT, listener.accept())"),
        "v11 fake WebSocket peer accepts should be wrapped in the shared timeout"
    );
    assert_eq!(
        v11_object_sync
            .matches("accept_fake_websocket_peer(listener,")
            .count(),
        4,
        "all v11 fake WebSocket peers should route listener accepts through the shared helper"
    );
}

#[test]
fn v11_object_sync_binary_frame_reads_are_bounded() {
    let v11_object_sync = include_str!("v11_object_sync.rs");

    assert!(
        !v11_object_sync.contains("match ws.next().await"),
        "v11 WebSocket binary frame readers should not wait forever in raw ws.next().await loops"
    );
    assert!(
        v11_object_sync.contains("const V11_BINARY_FRAME_TIMEOUT: Duration"),
        "v11 WebSocket binary frame readers should share a bounded read timeout"
    );
    assert!(
        v11_object_sync.contains("async fn recv_ws_binary_frame_with_timeout"),
        "v11 WebSocket binary frame readers should share a timeout-wrapped frame reader"
    );
    assert!(
        v11_object_sync.contains("tokio::time::timeout(V11_BINARY_FRAME_TIMEOUT, ws.next()).await"),
        "v11 WebSocket binary frame reads should route ws.next through the shared timeout"
    );
}

#[test]
fn v11_object_sync_oversized_send_outcomes_are_classified() {
    let v11_object_sync = include_str!("v11_object_sync.rs");

    assert!(
        !v11_object_sync.contains(".await\n            .is_ok()"),
        "v11 fake-peer oversized response sends should classify send outcomes instead of branching on is_ok inline"
    );
    assert!(
        v11_object_sync.contains("enum OversizedPeerSendOutcome"),
        "v11 fake-peer oversized response sends should expose sent/closed outcomes"
    );
    assert!(
        v11_object_sync.contains("async fn send_oversized_fake_peer_frame("),
        "v11 fake-peer oversized response sends should use a named helper"
    );
    assert_eq!(
        v11_object_sync
            .matches("match send_oversized_fake_peer_frame(&mut ws,")
            .count(),
        2,
        "both v11 fake-peer oversized response sends should branch on classified outcomes"
    );
}

#[test]
fn sync_ws_tests_do_not_discard_timeout_outcomes() {
    let sync_ws = include_str!("sync_ws.rs");

    assert!(
        !sync_ws.contains("let _ = tokio::time::timeout("),
        "sync WebSocket tests must assert timeout outcomes instead of discarding them"
    );
}

#[test]
fn sync_ws_uses_typed_binary_response_reader() {
    let sync_ws = include_str!("sync_ws.rs");

    assert!(
        !sync_ws.contains("ws.next().await.expect(\"response\").expect(\"ok msg\")"),
        "sync WebSocket tests should use a typed response reader instead of generic expect chains"
    );
    assert!(
        sync_ws.contains("async fn recv_sync_ws_binary_frame("),
        "sync WebSocket tests should share a typed binary response reader"
    );
}

#[test]
fn sync_ws_binary_response_reads_are_bounded() {
    let sync_ws = include_str!("sync_ws.rs");

    assert!(
        !sync_ws.contains("match ws.next().await"),
        "sync WebSocket binary response reader should not wait forever in a raw ws.next().await"
    );
    assert!(
        sync_ws.contains("const SYNC_WS_BINARY_FRAME_TIMEOUT: std::time::Duration"),
        "sync WebSocket binary response reader should share a named timeout"
    );
    assert!(
        sync_ws.contains("tokio::time::timeout(SYNC_WS_BINARY_FRAME_TIMEOUT, ws.next()).await"),
        "sync WebSocket binary response reader should route ws.next through the named timeout"
    );
}

#[test]
fn sync_ws_uses_typed_close_observer() {
    let sync_ws = include_str!("sync_ws.rs");

    for panic_message in [
        "oversized frame produced unexpected response",
        "oversized frame left sync websocket open without a rejection",
        "Bye produced unexpected sync response",
        "Bye left sync websocket open without close or EOF",
    ] {
        assert!(
            !sync_ws.contains(panic_message),
            "sync WebSocket close/EOF checks should return typed helper errors, not inline panics: {panic_message}"
        );
    }
    assert!(
        sync_ws.contains("async fn expect_sync_ws_close_or_eof("),
        "sync WebSocket close/EOF checks should share a typed close observer"
    );
    assert!(
        !sync_ws
            .contains("tokio::time::timeout(std::time::Duration::from_secs(1), ws.next()).await"),
        "sync WebSocket close/EOF observer should use a named close timeout"
    );
    assert!(
        sync_ws.contains("const SYNC_WS_CLOSE_TIMEOUT: std::time::Duration"),
        "sync WebSocket close/EOF observer should share a named close timeout"
    );
    assert!(
        sync_ws.contains("tokio::time::timeout(SYNC_WS_CLOSE_TIMEOUT, ws.next()).await"),
        "sync WebSocket close/EOF observer should route ws.next through the named timeout"
    );
}

#[test]
fn sync_ws_oversized_send_outcomes_are_classified() {
    let sync_ws = include_str!("sync_ws.rs");

    assert!(
        !sync_ws.contains(".await\n        .is_ok()"),
        "sync WebSocket oversized frame sends should classify send outcomes instead of branching on is_ok inline"
    );
    assert!(
        sync_ws.contains("enum OversizedSyncSendOutcome"),
        "sync WebSocket oversized frame sends should expose sent/closed outcomes"
    );
    assert!(
        sync_ws.contains("async fn send_oversized_sync_frame("),
        "sync WebSocket oversized frame sends should use a named helper"
    );
    assert!(
        sync_ws.contains("match send_oversized_sync_frame(&mut ws).await"),
        "sync WebSocket oversized frame test should branch on classified send outcomes"
    );
}

#[test]
fn sync_websocket_receive_outcomes_are_classified() {
    let sync = include_str!("../src/sync.rs");

    assert!(
        !sync.contains("while let Some(Ok(msg)) = socket.recv().await"),
        "sync WebSocket receive loop must classify receive errors separately from clean close"
    );
    assert!(
        sync.contains("enum SyncReceiveOutcome"),
        "sync WebSocket receive loop should expose message/closed/failed outcomes"
    );
    assert!(
        sync.contains("fn classify_sync_receive("),
        "sync WebSocket receive loop should use a named receive classifier"
    );
    assert!(
        sync.contains("match classify_sync_receive(socket.recv().await)"),
        "sync WebSocket handler should route socket.recv through the classifier"
    );
}

#[test]
fn sync_websocket_send_outcomes_are_classified() {
    let sync = include_str!("../src/sync.rs");

    assert!(
        !sync.contains("socket.send(Message::Binary(bytes.into())).await.is_err()"),
        "sync WebSocket response send failures must be classified explicitly"
    );
    assert!(
        sync.contains("enum SyncSendOutcome"),
        "sync WebSocket response sends should expose sent/failed outcomes"
    );
    assert!(
        sync.contains("async fn send_sync_response("),
        "sync WebSocket response sends should use a named send helper"
    );
    assert!(
        sync.contains("match send_sync_response(&mut socket, bytes).await"),
        "sync WebSocket handler should route response sends through the helper"
    );
}

#[test]
fn two_peer_ws_sync_uses_typed_binary_frame_reader() {
    let two_peer_ws_sync = include_str!("two_peer_ws_sync.rs");

    assert!(
        !two_peer_ws_sync.contains("ws.next().await.expect(\"frame\").expect(\"ok\")"),
        "two-peer WebSocket sync tests should use a typed binary frame reader instead of generic expect chains"
    );
    assert!(
        two_peer_ws_sync.contains("async fn recv_ws_binary_frame("),
        "two-peer WebSocket sync tests should share a typed binary frame reader"
    );
}

#[test]
fn two_peer_ws_sync_binary_frame_reads_are_bounded() {
    let two_peer_ws_sync = include_str!("two_peer_ws_sync.rs");

    assert!(
        !two_peer_ws_sync.contains("match ws.next().await"),
        "two-peer WebSocket binary frame reader should not wait forever in raw ws.next().await loops"
    );
    assert!(
        two_peer_ws_sync.contains("const TWO_PEER_WS_BINARY_FRAME_TIMEOUT: Duration"),
        "two-peer WebSocket binary frame reader should share a named timeout"
    );
    assert!(
        two_peer_ws_sync
            .contains("tokio::time::timeout(TWO_PEER_WS_BINARY_FRAME_TIMEOUT, ws.next()).await"),
        "two-peer WebSocket binary frame reader should route ws.next through the named timeout"
    );
}

#[test]
fn running_server_shutdown_does_not_ignore_join_results() {
    let lib = include_str!("../src/lib.rs");

    assert!(
        !lib.contains("let _ = h.await"),
        "RunningServer::shutdown must not discard join results"
    );
    assert!(
        lib.contains("expect(\"server task panicked during shutdown\")"),
        "RunningServer::shutdown must surface task panics during shutdown"
    );
}

#[test]
fn running_server_tasks_return_serve_errors_to_shutdown() {
    let lib = include_str!("../src/lib.rs");

    assert!(
        lib.contains("type ServerTaskResult = Result<(), MnemeError>"),
        "mnemed server tasks must return typed results"
    );
    assert!(
        lib.contains("JoinHandle<ServerTaskResult>"),
        "RunningServer must retain task results through the join handle"
    );
    assert!(
        lib.contains("expect(\"server task failed during shutdown\")"),
        "RunningServer::shutdown must surface serve errors from server tasks"
    );
    for swallowed in [
        "tracing::error!(\"http serve failed",
        "tracing::error!(\"grpc serve failed",
        "tracing::error!(\"unix serve failed",
    ] {
        assert!(
            !lib.contains(swallowed),
            "server task serve errors must be returned to shutdown, not only logged: {swallowed}"
        );
    }
}

#[test]
fn running_server_shutdown_notification_result_is_explicit() {
    let lib = include_str!("../src/lib.rs");

    assert!(
        !lib.contains("let _ = self.shutdown.send(())"),
        "RunningServer::shutdown must not discard shutdown notification results inline"
    );
    assert!(
        lib.contains("enum ShutdownSignalDelivery"),
        "RunningServer shutdown notification should expose delivered/no-receiver outcomes"
    );
    assert!(
        lib.contains("fn notify_running_server_shutdown("),
        "RunningServer shutdown notification should use a named helper"
    );
    assert!(
        lib.contains("notify_running_server_shutdown(&self.shutdown)"),
        "RunningServer::shutdown should route notification through the helper"
    );
}

#[test]
fn running_server_graceful_shutdown_signal_is_explicitly_observed() {
    let lib = include_str!("../src/lib.rs");

    assert!(
        !lib.contains("let _ = shutdown_rx_http.changed().await"),
        "HTTP graceful shutdown must not discard the watch receiver result inline"
    );
    assert!(
        !lib.contains("let _ = shutdown_rx_grpc.changed().await"),
        "gRPC graceful shutdown must not discard the watch receiver result inline"
    );
    assert!(
        lib.contains("async fn wait_for_running_server_shutdown("),
        "RunningServer graceful shutdown should use a named shutdown-signal helper"
    );
    assert_eq!(
        lib.matches("wait_for_running_server_shutdown(shutdown_rx_")
            .count(),
        2,
        "HTTP and gRPC servers should both route graceful shutdown through the helper"
    );
}

#[test]
fn daemon_main_does_not_discard_ctrl_c_errors() {
    let main = include_str!("../src/main.rs");

    assert!(
        !main.contains("let _ = tokio::signal::ctrl_c().await"),
        "mnemed main must not discard ctrl-c signal listener errors"
    );
    assert!(
        main.contains("wait_for_shutdown_signal(tokio::signal::ctrl_c()).await"),
        "mnemed main must route ctrl-c through the checked shutdown signal helper"
    );
    assert!(
        main.contains("failed to listen for shutdown signal"),
        "mnemed main must preserve signal listener error context"
    );
}

#[test]
fn unix_connection_task_join_failures_are_not_only_logged() {
    let unix = include_str!("../src/unix.rs");

    assert!(
        unix.contains("fn observe_connection_result(\n    joined: Option<Result<Result<(), std::io::Error>, tokio::task::JoinError>>,\n) -> Result<(), std::io::Error>"),
        "Unix connection join observation must be a result-returning contract"
    );
    assert!(
        unix.contains("connection task panicked"),
        "Unix connection task panics must surface as server errors"
    );
    assert!(
        unix.contains("is_cancelled()"),
        "Unix shutdown cleanup must distinguish expected aborted connection tasks"
    );
    assert!(
        !unix.contains("tracing::debug!(\"unix kernel connection task join failed"),
        "Unix connection join failures must not be only debug-logged"
    );
}

#[test]
fn unix_framing_error_writes_are_classified() {
    let unix = include_str!("../src/unix.rs");

    assert!(
        !unix.contains("let _ = write_kernel_err("),
        "Unix framing-error response writes must be classified, not discarded"
    );
    assert!(
        unix.contains("enum KernelErrWriteOutcome"),
        "Unix kernel error writes should expose sent/failed outcomes"
    );
    assert!(
        unix.contains("fn classify_kernel_err_write_result("),
        "Unix kernel error write results should be classified through a named helper"
    );
    assert!(
        unix.contains("async fn write_framing_error_response("),
        "Unix framing-error responses should use a named write helper"
    );
}

#[test]
fn unix_response_serialization_is_checked() {
    let unix = include_str!("../src/unix.rs");

    assert!(
        !unix.contains("unwrap_or_default()"),
        "Unix response serialization must not silently fall back to empty frames"
    );
    assert!(
        unix.contains("fn encode_kernel_response("),
        "Unix response serialization should use a named checked helper"
    );
    assert_eq!(
        unix.matches("let out = encode_kernel_response(&").count(),
        2,
        "Unix error and dispatch response writes should both use checked serialization"
    );
}

#[test]
fn unix_api_tests_do_not_use_long_sleep_as_io_signal() {
    let unix_api_tests = include_str!("unix_api.rs");

    assert!(
        !unix_api_tests.contains("tokio::time::sleep(Duration::from_millis(120))"),
        "Unix API silent-client timeout tests should wait on socket closure, not a long sleep"
    );
    assert!(
        !unix_api_tests.contains("tokio::time::sleep(Duration::from_millis(200))"),
        "Unix API stalled-peer tests should wait on client timeout/peer closure, not a long sleep"
    );
    assert!(
        !unix_api_tests
            .contains("tokio::time::sleep(Duration::from_millis(20)).await;\n    let _ = shutdown_tx.send(());"),
        "Unix API startup-failure tests should await the failing server task directly, not sleep before shutdown"
    );
    assert!(
        !unix_api_tests.contains("tokio::time::sleep(Duration::from_millis(20))"),
        "Unix API zero-timeout tests should use explicit handshakes, not short wall-clock sleeps"
    );
}

#[test]
fn unix_api_fake_peer_tasks_return_typed_results() {
    let unix_api_tests = include_str!("unix_api.rs");

    assert!(
        !unix_api_tests.contains("server.await.expect(\"server task\");"),
        "Unix API fake-peer tasks should assert typed task results instead of bare joins"
    );
    assert!(
        unix_api_tests.contains("type FakeUnixPeerResult = Result<(), String>"),
        "Unix API fake-peer tasks should share a typed peer-result contract"
    );
    assert!(
        unix_api_tests.contains("expect_fake_unix_peer(server,"),
        "Unix API tests should route fake-peer joins through the shared typed assertion helper"
    );
}

#[test]
fn unix_api_fake_peer_accepts_are_bounded() {
    let unix_api_tests = include_str!("unix_api.rs");

    assert!(
        !unix_api_tests.contains(".accept()\n            .await"),
        "Unix API fake peers should not wait forever in bare listener.accept().await calls"
    );
    assert!(
        unix_api_tests.contains("const FAKE_UNIX_PEER_ACCEPT_TIMEOUT: Duration"),
        "Unix API fake peers should share a bounded accept timeout"
    );
    assert!(
        unix_api_tests.contains("async fn accept_fake_unix_peer("),
        "Unix API fake peers should share a named accept helper"
    );
    assert!(
        unix_api_tests
            .contains("tokio::time::timeout(FAKE_UNIX_PEER_ACCEPT_TIMEOUT, listener.accept())"),
        "Unix API fake peer accepts should be wrapped in the shared timeout"
    );
    assert_eq!(
        unix_api_tests
            .matches("accept_fake_unix_peer(listener,")
            .count(),
        3,
        "all Unix API fake peers should route listener accepts through the shared helper"
    );
}

#[test]
fn unix_api_fake_peer_request_reads_are_bounded() {
    let unix_api_tests = include_str!("unix_api.rs");

    assert!(
        !unix_api_tests.contains(
            "async fn read_fake_unix_request(stream: &mut UnixStream, context: &str) -> Result<Vec<u8>, String> {\n    let mut len_buf = [0u8; 4];\n    stream\n        .read_exact(&mut len_buf)\n        .await"
        ),
        "Unix API fake peers should not wait forever reading request lengths"
    );
    assert!(
        !unix_api_tests.contains(
            "let mut req_buf = vec![0u8; req_len];\n    stream\n        .read_exact(&mut req_buf)\n        .await"
        ),
        "Unix API fake peers should not wait forever reading request bodies"
    );
    assert!(
        unix_api_tests.contains("const FAKE_UNIX_PEER_REQUEST_TIMEOUT: Duration"),
        "Unix API fake peers should share a bounded request-read timeout"
    );
    assert!(
        unix_api_tests.contains("async fn read_fake_unix_request_exact("),
        "Unix API fake peers should share a named exact-read helper"
    );
    assert!(
        unix_api_tests.contains(
            "tokio::time::timeout(FAKE_UNIX_PEER_REQUEST_TIMEOUT, stream.read_exact(buf))",
        ),
        "Unix API fake peer request reads should route read_exact through the shared timeout"
    );
    assert!(
        unix_api_tests.contains(
            "read_fake_unix_request_exact(stream, &mut len_buf, context, \"length\").await",
        ),
        "Unix API fake peer request length reads should use the timeout helper"
    );
    assert!(
        unix_api_tests.contains(
            "read_fake_unix_request_exact(stream, &mut req_buf, context, \"body\").await",
        ),
        "Unix API fake peer request body reads should use the timeout helper"
    );
}

#[test]
fn unix_api_stalled_peer_client_close_read_uses_named_timeout() {
    let unix_api_tests = include_str!("unix_api.rs");

    assert!(
        !unix_api_tests.contains(
            "tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut extra))"
        ),
        "Unix API stalled-peer client-close reads should use a named timeout"
    );
    assert!(
        unix_api_tests.contains("const FAKE_UNIX_PEER_CLIENT_CLOSE_TIMEOUT: Duration"),
        "Unix API stalled-peer client-close reads should share a named timeout"
    );
    assert!(
        unix_api_tests.contains(
            "FAKE_UNIX_PEER_CLIENT_CLOSE_TIMEOUT,\n            stream.read_exact(&mut extra),"
        ),
        "Unix API stalled-peer client-close reads should route through the named timeout"
    );
}

#[test]
fn unix_api_zero_timeout_request_seen_uses_named_timeout() {
    let unix_api_tests = include_str!("unix_api.rs");

    assert!(
        !unix_api_tests.contains("tokio::time::timeout(Duration::from_secs(1), request_seen_rx)"),
        "Unix API zero-timeout request-seen waits should use a named timeout"
    );
    assert!(
        unix_api_tests.contains("const ZERO_TIMEOUT_REQUEST_SEEN_TIMEOUT: Duration"),
        "Unix API zero-timeout request-seen waits should share a named timeout"
    );
    assert!(
        unix_api_tests
            .contains("tokio::time::timeout(ZERO_TIMEOUT_REQUEST_SEEN_TIMEOUT, request_seen_rx)"),
        "Unix API zero-timeout request-seen waits should route through the named timeout"
    );
}

#[test]
fn unix_api_zero_timeout_client_join_uses_named_timeout() {
    let unix_api_tests = include_str!("unix_api.rs");

    assert!(
        !unix_api_tests.contains("tokio::time::timeout(Duration::from_secs(1), client)"),
        "Unix API zero-timeout client joins should use a named timeout"
    );
    assert!(
        unix_api_tests.contains("const ZERO_TIMEOUT_CLIENT_JOIN_TIMEOUT: Duration"),
        "Unix API zero-timeout client joins should share a named timeout"
    );
    assert!(
        unix_api_tests.contains("tokio::time::timeout(ZERO_TIMEOUT_CLIENT_JOIN_TIMEOUT, client)"),
        "Unix API zero-timeout client joins should route through the named timeout"
    );
}

#[test]
fn unix_api_shutdown_write_outcomes_are_classified() {
    let unix_api_tests = include_str!("unix_api.rs");

    assert!(
        !unix_api_tests.contains("if write_raw_request(&mut stream, &req).await.is_err()"),
        "Unix API shutdown tests should classify post-shutdown write outcomes instead of returning from a bare is_err branch"
    );
    assert!(
        unix_api_tests.contains("enum PostShutdownWriteOutcome"),
        "Unix API shutdown tests should expose written/closed outcomes"
    );
    assert!(
        unix_api_tests.contains("async fn write_after_shutdown("),
        "Unix API shutdown tests should use a named post-shutdown write observer"
    );
    assert!(
        unix_api_tests.contains("match write_after_shutdown(&mut stream, &req).await"),
        "Unix API shutdown tests should branch on classified post-shutdown write outcomes"
    );
}

#[test]
fn unix_api_shutdown_read_outcomes_are_classified() {
    let unix_api_tests = include_str!("unix_api.rs");

    assert!(
        !unix_api_tests.contains(
            "Ok(Ok(_)) => panic!(\"idle connection processed a request after server shutdown\")"
        ),
        "Unix API shutdown tests should classify post-shutdown read outcomes instead of matching raw timeout/read results inline"
    );
    assert!(
        unix_api_tests.contains("enum PostShutdownReadOutcome"),
        "Unix API shutdown tests should expose closed/timed-out/replied outcomes"
    );
    assert!(
        unix_api_tests.contains("async fn read_after_shutdown("),
        "Unix API shutdown tests should use a named post-shutdown read observer"
    );
    assert!(
        unix_api_tests.contains("match read_after_shutdown(&mut stream).await"),
        "Unix API shutdown tests should branch on classified post-shutdown read outcomes"
    );
}

#[test]
fn unix_api_post_shutdown_response_read_uses_named_timeout() {
    let unix_api_tests = include_str!("unix_api.rs");

    assert!(
        !unix_api_tests.contains("std::time::Duration::from_millis(200)"),
        "Unix API post-shutdown response reads should use a named timeout"
    );
    assert!(
        unix_api_tests.contains("const POST_SHUTDOWN_RESPONSE_READ_TIMEOUT: Duration"),
        "Unix API post-shutdown response reads should share a named timeout"
    );
    assert!(
        unix_api_tests.contains(
            "POST_SHUTDOWN_RESPONSE_READ_TIMEOUT,\n        stream.read_exact(&mut len_buf),"
        ),
        "Unix API post-shutdown response reads should route through the named timeout"
    );
}

#[test]
fn unix_api_real_server_lifecycle_uses_typed_helpers() {
    let unix_api_tests = include_str!("unix_api.rs");

    assert_eq!(
        unix_api_tests
            .matches(".expect(\"server task joins\")")
            .count(),
        1,
        "Unix API real-server task joins should be centralized in RunningUnix::shutdown"
    );
    assert!(
        !unix_api_tests
            .contains("tokio::time::timeout(std::time::Duration::from_secs(1), self.handle)"),
        "Unix API real-server shutdown joins should use a named lifecycle timeout"
    );
    assert!(
        unix_api_tests.contains("const UNIX_SERVER_SHUTDOWN_TIMEOUT: Duration"),
        "Unix API real-server shutdown joins should share a named lifecycle timeout"
    );
    assert!(
        unix_api_tests.contains("tokio::time::timeout(UNIX_SERVER_SHUTDOWN_TIMEOUT, self.handle)"),
        "Unix API real-server shutdown joins should route through the named timeout"
    );
    assert_eq!(
        unix_api_tests
            .matches("tokio::sync::watch::channel(())")
            .count(),
        2,
        "Unix API real-server watch channels should be centralized in spawn/error helpers"
    );
    assert!(
        unix_api_tests.contains("async fn spawn_unix_with_io_timeout("),
        "Unix API configured-timeout servers should use a named lifecycle helper"
    );
    assert!(
        unix_api_tests.contains("async fn expect_unix_start_error("),
        "Unix API startup-failure tests should observe task errors through a named helper"
    );
    assert!(
        !unix_api_tests.contains("tokio::time::timeout(Duration::from_secs(1), handle)"),
        "Unix API startup-failure joins should use a named lifecycle timeout"
    );
    assert!(
        unix_api_tests.contains("const UNIX_START_ERROR_TIMEOUT: Duration"),
        "Unix API startup-failure joins should share a named lifecycle timeout"
    );
    assert!(
        unix_api_tests.contains("tokio::time::timeout(UNIX_START_ERROR_TIMEOUT, handle)"),
        "Unix API startup-failure joins should route through the named timeout"
    );
}

#[test]
fn unix_api_silent_client_close_read_uses_named_timeout() {
    let unix_api_tests = include_str!("unix_api.rs");

    assert!(
        !unix_api_tests.contains(
            "tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut len_buf))"
        ),
        "Unix API silent-client close reads should use a named timeout"
    );
    assert!(
        unix_api_tests.contains("const UNIX_SILENT_CLIENT_CLOSE_TIMEOUT: Duration"),
        "Unix API silent-client close reads should share a named timeout"
    );
    assert!(
        unix_api_tests.contains(
            "UNIX_SILENT_CLIENT_CLOSE_TIMEOUT,\n        stream.read_exact(&mut len_buf),"
        ),
        "Unix API silent-client close reads should route through the named timeout"
    );
}

#[test]
fn unix_api_silent_client_io_timeout_uses_named_parameter() {
    let unix_api_tests = include_str!("unix_api.rs");

    assert!(
        !unix_api_tests
            .contains("spawn_unix_with_io_timeout(sock.clone(), state, Duration::from_millis(50))"),
        "Unix API silent-client server I/O timeout should use a named parameter"
    );
    assert!(
        unix_api_tests.contains("const UNIX_SILENT_CLIENT_IO_TIMEOUT: Duration"),
        "Unix API silent-client server I/O timeout should be named"
    );
    assert!(
        unix_api_tests.contains(
            "spawn_unix_with_io_timeout(sock.clone(), state, UNIX_SILENT_CLIENT_IO_TIMEOUT)"
        ),
        "Unix API silent-client server I/O timeout should route through the named parameter"
    );
}

#[test]
fn unix_api_stalled_response_client_timeout_uses_named_parameter() {
    let unix_api_tests = include_str!("unix_api.rs");

    assert!(
        !unix_api_tests.contains(
            "        Duration::from_millis(50),\n    )\n    .await\n    .expect_err(\"stalled peer must trip the client timeout\")"
        ),
        "Unix API stalled-response client timeout should use a named parameter"
    );
    assert!(
        unix_api_tests.contains("const STALLED_RESPONSE_CLIENT_TIMEOUT: Duration"),
        "Unix API stalled-response client timeout should be named"
    );
    assert!(
        unix_api_tests.contains(
            "        STALLED_RESPONSE_CLIENT_TIMEOUT,\n    )\n    .await\n    .expect_err(\"stalled peer must trip the client timeout\")"
        ),
        "Unix API stalled-response client timeout should route through the named parameter"
    );
}

#[test]
fn unix_zero_io_timeout_normalizes_to_default_deadline() {
    let unix = include_str!("../src/unix.rs");

    assert!(
        unix.contains("fn normalize_io_timeout(io_timeout: Duration) -> Duration"),
        "Unix API must keep a single timeout normalization helper"
    );
    assert!(
        unix.contains("if io_timeout.is_zero()"),
        "Unix API zero I/O timeout must not be passed through as an immediate timeout"
    );
    assert!(
        unix.contains("DEFAULT_CONNECTION_IO_TIMEOUT"),
        "Unix API zero I/O timeout must normalize to the default connection deadline"
    );
}

#[test]
fn unix_socket_readiness_tests_probe_connection_not_path_existence() {
    let unix_ready = include_str!("unix_ready.rs");

    assert!(
        unix_ready.contains("UnixStream::connect(path).await"),
        "shared Unix readiness helper must prove readiness by opening a Unix socket connection"
    );
    assert!(
        !unix_ready.contains("path.exists()"),
        "shared Unix readiness helper must not treat socket path existence as readiness"
    );

    for (path, contents) in [
        ("unix_api.rs", include_str!("unix_api.rs")),
        ("redteam_paths.rs", include_str!("redteam_paths.rs")),
    ] {
        assert!(
            !contents.contains("async fn wait_for_socket"),
            "{path} should use the shared connect-based Unix readiness helper"
        );
        assert!(
            !contents.contains("path.exists()"),
            "{path} should not treat Unix socket path existence as readiness"
        );
    }
}

#[test]
fn redteam_paths_uses_typed_unix_server_lifecycle_helper() {
    let redteam = include_str!("redteam_paths.rs");

    assert!(
        !redteam.contains(".expect(\"server task joins\");"),
        "redteam Unix server lifecycle should assert typed task results through a helper"
    );
    assert!(
        redteam.contains("struct RedteamUnixServer"),
        "redteam Unix server lifecycle should be owned by a typed helper"
    );
    assert!(
        !redteam.contains("tokio::time::timeout(std::time::Duration::from_secs(1), self.handle)"),
        "redteam Unix server shutdown joins should use a named lifecycle timeout"
    );
    assert!(
        redteam.contains("const REDTEAM_UNIX_SERVER_SHUTDOWN_TIMEOUT: std::time::Duration"),
        "redteam Unix server shutdown joins should share a named lifecycle timeout"
    );
    assert!(
        redteam.contains("tokio::time::timeout(REDTEAM_UNIX_SERVER_SHUTDOWN_TIMEOUT, self.handle)"),
        "redteam Unix server shutdown joins should route through the named timeout"
    );
    assert!(
        redteam.contains("async fn shutdown(self)"),
        "redteam Unix server lifecycle helper should expose explicit async shutdown"
    );
}

#[test]
fn test_harness_uses_explicit_async_shutdown() {
    let common = include_str!("common/mod.rs");

    assert!(
        common.contains("pub async fn shutdown(self)"),
        "TestHarness must expose an explicit async shutdown method"
    );
    assert!(
        !common.contains("impl Drop for TestHarness"),
        "TestHarness must not rely on no-op Drop/runtime teardown for server lifecycle"
    );
    assert!(
        !common.contains("OS reclaims port on process exit"),
        "TestHarness lifecycle comments must not normalize leaked test servers"
    );
}

#[test]
fn test_harness_users_shutdown_explicitly() {
    for (path, contents) in [
        ("http_api.rs", include_str!("http_api.rs")),
        ("grpc_api.rs", include_str!("grpc_api.rs")),
        ("sync_ws.rs", include_str!("sync_ws.rs")),
        ("redteam_paths.rs", include_str!("redteam_paths.rs")),
    ] {
        let starts = contents.matches("TestHarness::new().await").count();
        let shutdowns = contents.matches("h.shutdown().await").count();
        assert_eq!(
            starts, shutdowns,
            "{path} must explicitly shut down every TestHarness it starts"
        );
    }
}
