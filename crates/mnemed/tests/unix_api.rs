//! Unix socket RPC smoke test (remember / head / sync hello).

mod unix_ready;

use base64::Engine;
use mneme_cap::agent_cap;
use mneme_core::{NodeId, SyncMessage};
use mneme_crdt::encode_sync_message;
use mneme_crypto::KeyPair;
use mnemed::{
    DEFAULT_RATE_LIMIT_PER_MINUTE, ServerConfig, cap_to_b64, start_with_state, test_state,
    unix::{KernelRequest, KernelResponse, UnixServer, request_json, request_json_with_timeout},
};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinHandle;
use unix_ready::wait_for_unix_socket_accepting;

type ConnectionClosedErrorCheck = Result<(), String>;
type DaemonStartResult = Result<mnemed::RunningServer, mneme_core::MnemeError>;
type DaemonStartIoFailureCheck = Result<String, String>;
type KernelResponseCodeCheck = Result<(), String>;
type KernelResponsePayloadCheck = Result<serde_json::Value, String>;
type UnixApiStateWithKeys = (mnemed::AppState, KeyPair, KeyPair);
type UnixServerTaskResult = Result<(), std::io::Error>;
type UnixServerTaskJoin = Result<UnixServerTaskResult, tokio::task::JoinError>;
type TimedUnixServerTaskJoin = Result<UnixServerTaskJoin, tokio::time::error::Elapsed>;
type RequestJsonResult = Result<KernelResponse, std::io::Error>;
type ZeroTimeoutClientResult = Result<KernelResponse, std::io::Error>;
type ZeroTimeoutClientJoin = Result<ZeroTimeoutClientResult, tokio::task::JoinError>;
type TimedZeroTimeoutClientJoin = Result<ZeroTimeoutClientJoin, tokio::time::error::Elapsed>;
type ZeroTimeoutRequestSeenReceiver = tokio::sync::oneshot::Receiver<()>;
type ZeroTimeoutResponseReleaseSender = tokio::sync::oneshot::Sender<()>;
type FakeUnixPeerResult = Result<(), String>;
type FakeUnixPeerJoin = Result<FakeUnixPeerResult, tokio::task::JoinError>;
type RawFakeUnixPeerStreamAccept =
    Result<(UnixStream, tokio::net::unix::SocketAddr), std::io::Error>;
type TimedRawFakeUnixPeerStreamAccept =
    Result<RawFakeUnixPeerStreamAccept, tokio::time::error::Elapsed>;
type RawFakeUnixPeerExactRead = Result<usize, std::io::Error>;
type TimedRawFakeUnixPeerExactRead = Result<RawFakeUnixPeerExactRead, tokio::time::error::Elapsed>;
type RawFakeUnixPeerClientCloseRead = Result<usize, std::io::Error>;
type TimedRawFakeUnixPeerClientCloseRead =
    Result<RawFakeUnixPeerClientCloseRead, tokio::time::error::Elapsed>;
type RawSilentClientCloseRead = Result<usize, std::io::Error>;
type TimedSilentClientCloseRead = Result<RawSilentClientCloseRead, tokio::time::error::Elapsed>;

enum FakeUnixPeerAcceptOutcome {
    Accepted(UnixStream),
    Failed(std::io::Error),
    TimedOut(tokio::time::error::Elapsed),
}

enum FakeUnixPeerRequestReadOutcome {
    Read,
    Failed(std::io::Error),
    TimedOut(tokio::time::error::Elapsed),
}

enum FakeUnixPeerClientCloseReadOutcome {
    Closed(std::io::Error),
    WroteExtra,
    TimedOut(tokio::time::error::Elapsed),
}

enum SilentClientCloseReadOutcome {
    Closed(std::io::Error),
    Replied,
    TimedOut(tokio::time::error::Elapsed),
}

enum UnixShutdownSignalDelivery {
    Delivered,
    NoReceivers,
}

enum UnixServerJoinOutcome {
    Completed(UnixServerTaskResult),
    JoinFailed(tokio::task::JoinError),
    TimedOut,
}

enum ZeroTimeoutClientJoinOutcome {
    Completed(ZeroTimeoutClientResult),
    JoinFailed(tokio::task::JoinError),
    TimedOut,
}

const FAKE_UNIX_PEER_ACCEPT_TIMEOUT: Duration = Duration::from_secs(1);
const FAKE_UNIX_PEER_REQUEST_TIMEOUT: Duration = Duration::from_secs(1);
const FAKE_UNIX_PEER_CLIENT_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);
const POST_SHUTDOWN_RESPONSE_READ_TIMEOUT: Duration = Duration::from_millis(200);
const STALLED_RESPONSE_CLIENT_TIMEOUT: Duration = Duration::from_millis(50);
const UNIX_SERVER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);
const UNIX_START_ERROR_TIMEOUT: Duration = Duration::from_secs(1);
const UNIX_SILENT_CLIENT_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);
const UNIX_SILENT_CLIENT_IO_TIMEOUT: Duration = Duration::from_millis(50);
const ZERO_TIMEOUT_CLIENT_JOIN_TIMEOUT: Duration = Duration::from_secs(1);
const ZERO_TIMEOUT_PROGRESS_YIELDS: usize = 3;
const ZERO_TIMEOUT_REQUEST_SEEN_TIMEOUT: Duration = Duration::from_secs(1);

struct RunningUnix {
    shutdown_tx: tokio::sync::watch::Sender<()>,
    handle: JoinHandle<UnixServerTaskResult>,
}

impl RunningUnix {
    async fn shutdown(self) {
        let shutdown_signal = observe_unix_shutdown_signal(&self.shutdown_tx);
        match shutdown_signal {
            UnixShutdownSignalDelivery::Delivered | UnixShutdownSignalDelivery::NoReceivers => {}
        }
        let shutdown_join = join_unix_server_shutdown(self.handle).await;
        assert_unix_shutdown_join_completed(shutdown_join);
    }
}

fn observe_unix_shutdown_signal(
    shutdown: &tokio::sync::watch::Sender<()>,
) -> UnixShutdownSignalDelivery {
    match shutdown.send(()) {
        Ok(()) => UnixShutdownSignalDelivery::Delivered,
        Err(_) => UnixShutdownSignalDelivery::NoReceivers,
    }
}

async fn join_unix_server_shutdown(
    handle: JoinHandle<UnixServerTaskResult>,
) -> UnixServerJoinOutcome {
    classify_unix_server_task_join(tokio::time::timeout(UNIX_SERVER_SHUTDOWN_TIMEOUT, handle).await)
}

async fn join_unix_start_error(handle: JoinHandle<UnixServerTaskResult>) -> UnixServerJoinOutcome {
    classify_unix_server_task_join(tokio::time::timeout(UNIX_START_ERROR_TIMEOUT, handle).await)
}

fn classify_unix_server_task_join(join: TimedUnixServerTaskJoin) -> UnixServerJoinOutcome {
    match join {
        Ok(Ok(result)) => UnixServerJoinOutcome::Completed(result),
        Ok(Err(err)) => UnixServerJoinOutcome::JoinFailed(err),
        Err(_) => UnixServerJoinOutcome::TimedOut,
    }
}

fn assert_unix_shutdown_join_completed(join: UnixServerJoinOutcome) {
    match join {
        UnixServerJoinOutcome::Completed(Ok(())) => {}
        UnixServerJoinOutcome::Completed(Err(err)) => {
            panic!("server returned error during shutdown: {err}")
        }
        UnixServerJoinOutcome::JoinFailed(err) => {
            panic!("server task failed to join during shutdown: {err}")
        }
        UnixServerJoinOutcome::TimedOut => {
            panic!("server did not exit before shutdown timeout")
        }
    }
}

async fn spawn_unix(path: PathBuf, state: mnemed::AppState) -> RunningUnix {
    spawn_unix_with_optional_io_timeout(path, state, None).await
}

async fn spawn_unix_with_io_timeout(
    path: PathBuf,
    state: mnemed::AppState,
    io_timeout: Duration,
) -> RunningUnix {
    spawn_unix_with_optional_io_timeout(path, state, Some(io_timeout)).await
}

async fn spawn_unix_with_optional_io_timeout(
    path: PathBuf,
    state: mnemed::AppState,
    io_timeout: Option<Duration>,
) -> RunningUnix {
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
    let handle = tokio::spawn({
        let path = path.clone();
        async move {
            let server = UnixServer::new(path, state);
            let server = if let Some(io_timeout) = io_timeout {
                server.with_io_timeout(io_timeout)
            } else {
                server
            };
            server.serve_until_shutdown(shutdown_rx).await
        }
    });
    wait_for_unix_socket_accepting(&path).await;
    RunningUnix {
        shutdown_tx,
        handle,
    }
}

async fn expect_unix_start_error(path: PathBuf, state: mnemed::AppState) -> std::io::Error {
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
    let handle = tokio::spawn(async move {
        UnixServer::new(path, state)
            .serve_until_shutdown(shutdown_rx)
            .await
    });

    let start_error_join = join_unix_start_error(handle).await;

    expect_unix_start_error_join_failed_closed(start_error_join)
}

fn expect_unix_start_error_join_failed_closed(join: UnixServerJoinOutcome) -> std::io::Error {
    match join {
        UnixServerJoinOutcome::Completed(Err(err)) => err,
        UnixServerJoinOutcome::Completed(Ok(())) => {
            panic!("Unix server start unexpectedly succeeded")
        }
        UnixServerJoinOutcome::JoinFailed(err) => {
            panic!("start-failure Unix server task failed to join: {err}")
        }
        UnixServerJoinOutcome::TimedOut => {
            panic!("Unix server start-failure task did not exit before timeout")
        }
    }
}

async fn join_zero_timeout_client(
    client: JoinHandle<ZeroTimeoutClientResult>,
) -> ZeroTimeoutClientJoinOutcome {
    classify_zero_timeout_client_join(
        tokio::time::timeout(ZERO_TIMEOUT_CLIENT_JOIN_TIMEOUT, client).await,
    )
}

fn classify_zero_timeout_client_join(
    join: TimedZeroTimeoutClientJoin,
) -> ZeroTimeoutClientJoinOutcome {
    match join {
        Ok(Ok(result)) => ZeroTimeoutClientJoinOutcome::Completed(result),
        Ok(Err(err)) => ZeroTimeoutClientJoinOutcome::JoinFailed(err),
        Err(_) => ZeroTimeoutClientJoinOutcome::TimedOut,
    }
}

fn expect_zero_timeout_client_response(join: ZeroTimeoutClientJoinOutcome) -> KernelResponse {
    match join {
        ZeroTimeoutClientJoinOutcome::Completed(Ok(resp)) => resp,
        ZeroTimeoutClientJoinOutcome::Completed(Err(err)) => {
            panic!("zero timeout should fall back to default deadline: {err}")
        }
        ZeroTimeoutClientJoinOutcome::JoinFailed(err) => {
            panic!("zero-timeout client task failed to join: {err}")
        }
        ZeroTimeoutClientJoinOutcome::TimedOut => {
            panic!("zero-timeout client did not exit after released response before timeout")
        }
    }
}

async fn expect_zero_timeout_request_seen(
    request_seen_rx: ZeroTimeoutRequestSeenReceiver,
    context: &str,
) {
    match tokio::time::timeout(ZERO_TIMEOUT_REQUEST_SEEN_TIMEOUT, request_seen_rx).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            panic!("{context}: zero-timeout request seen signal failed: sender dropped")
        }
        Err(err) => panic!("{context}: zero-timeout request seen wait timed out: {err}"),
    }
}

fn release_zero_timeout_response(
    send_response_tx: ZeroTimeoutResponseReleaseSender,
    context: &str,
) {
    send_response_tx.send(()).unwrap_or_else(|_| {
        panic!("{context}: zero-timeout response release failed: receiver dropped")
    });
}

async fn expect_daemon_start_failure(
    result: DaemonStartResult,
    context: &str,
) -> mneme_core::MnemeError {
    match result {
        Err(err) => err,
        Ok(server) => {
            shutdown_unexpected_daemon_start(server).await;
            panic_unexpected_daemon_start(context);
        }
    }
}

async fn shutdown_unexpected_daemon_start(server: mnemed::RunningServer) {
    server.shutdown().await;
}

fn panic_unexpected_daemon_start(context: &str) -> ! {
    panic!("{context} unexpectedly started");
}

fn expect_daemon_start_io_failure(
    err: mneme_core::MnemeError,
    sock: &Path,
    context: &str,
) -> String {
    let daemon_start_io = validate_daemon_start_io_failure(err, sock, context);

    expect_daemon_start_io_failure_check_passed(daemon_start_io)
}

fn validate_daemon_start_io_failure(
    err: mneme_core::MnemeError,
    sock: &Path,
    context: &str,
) -> DaemonStartIoFailureCheck {
    let expected_path = sock.display().to_string();

    match err {
        mneme_core::MnemeError::IoFailed { path, kind } if path == expected_path => Ok(kind),
        mneme_core::MnemeError::IoFailed { path, kind } => Err(format!(
            "{context}: expected daemon Unix socket I/O failure path {expected_path}, got {path}: {kind}"
        )),
        other => Err(format!(
            "expected {context} daemon Unix socket I/O failure, got {other:?}"
        )),
    }
}

fn expect_daemon_start_io_failure_check_passed(check: DaemonStartIoFailureCheck) -> String {
    match check {
        Ok(kind) => kind,
        Err(message) => panic!("{message}"),
    }
}

fn expect_daemon_loopback_http_addr(context: &str) -> SocketAddr {
    "127.0.0.1:0"
        .parse()
        .unwrap_or_else(|err| panic!("{context}: daemon loopback HTTP address parse failed: {err}"))
}

async fn expect_daemon_start_with_unix_socket(
    sock: &Path,
    state: mnemed::AppState,
    context: &str,
) -> mnemed::RunningServer {
    start_with_state(
        ServerConfig {
            http_addr: expect_daemon_loopback_http_addr(context),
            grpc_addr: None,
            rate_limit_per_minute: DEFAULT_RATE_LIMIT_PER_MINUTE,
            unix_socket: Some(sock.to_path_buf()),
        },
        state,
    )
    .await
    .unwrap_or_else(|err| panic!("{context}: daemon Unix socket start failed: {err:?}"))
}

async fn expect_daemon_start_failure_with_unix_socket(
    sock: &Path,
    state: mnemed::AppState,
    context: &str,
) -> mneme_core::MnemeError {
    let result = start_with_state(
        ServerConfig {
            http_addr: expect_daemon_loopback_http_addr(context),
            grpc_addr: None,
            rate_limit_per_minute: DEFAULT_RATE_LIMIT_PER_MINUTE,
            unix_socket: Some(sock.to_path_buf()),
        },
        state,
    )
    .await;

    expect_daemon_start_failure(result, context).await
}

fn expect_unix_sync_hello_bytes_b64(context: &str) -> String {
    let hello = SyncMessage::Hello {
        proto_ver: 1,
        node_id: NodeId([0x01; 16]),
        head_root: [0u8; 32],
        head_sig: vec![],
    };
    let wire = encode_sync_message(&hello)
        .unwrap_or_else(|err| panic!("{context}: Unix sync hello encode failed: {err:?}"));

    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, wire)
}

fn expect_unix_sync_frame_request(cap_b64: String, context: &str) -> KernelRequest {
    KernelRequest::SyncFrame {
        cap_b64,
        bytes_b64: expect_unix_sync_hello_bytes_b64(context),
    }
}

async fn yield_zero_timeout_progress() {
    for _ in 0..ZERO_TIMEOUT_PROGRESS_YIELDS {
        tokio::task::yield_now().await;
    }
}

async fn write_raw_request(
    stream: &mut UnixStream,
    req: &KernelRequest,
) -> Result<(), std::io::Error> {
    let frame = serde_json::to_vec(req).map_err(std::io::Error::other)?;
    stream
        .write_all(&(frame.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(&frame).await
}

async fn expect_raw_unix_request_written(
    stream: &mut UnixStream,
    req: &KernelRequest,
    context: &str,
) {
    write_raw_request(stream, req)
        .await
        .unwrap_or_else(|err| panic!("{context}: Unix API raw request write failed: {err}"));
}

async fn expect_raw_unix_kernel_response(stream: &mut UnixStream, context: &str) -> KernelResponse {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .unwrap_or_else(|err| panic!("{context}: Unix API raw response length read failed: {err}"));
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; resp_len];
    stream
        .read_exact(&mut buf)
        .await
        .unwrap_or_else(|err| panic!("{context}: Unix API raw response body read failed: {err}"));
    serde_json::from_slice(&buf)
        .unwrap_or_else(|err| panic!("{context}: Unix API raw response JSON failed: {err}"))
}

fn assert_schema_drift(resp: KernelResponse, context: &str) {
    assert_kernel_response_error_code(resp, "SchemaDrift", context);
}

fn assert_cap_denied(resp: KernelResponse, context: &str) {
    assert_kernel_response_error_code(resp, "CapDenied", context);
}

fn assert_kernel_response_error_code(resp: KernelResponse, expected_code: &str, context: &str) {
    let response_code = expect_kernel_response_error_code(resp, expected_code, context);
    assert_kernel_response_code_check_passed(response_code);
}

fn expect_kernel_response_error_code(
    resp: KernelResponse,
    expected_code: &str,
    context: &str,
) -> KernelResponseCodeCheck {
    match resp {
        KernelResponse::Err { code, .. } if code == expected_code => Ok(()),
        KernelResponse::Err { code, .. } => Err(format!(
            "{context}: expected error code {expected_code}, got {code}"
        )),
        KernelResponse::Ok { payload } => {
            Err(format!("{context} unexpectedly succeeded: {payload}"))
        }
    }
}

fn assert_kernel_response_code_check_passed(response_code: KernelResponseCodeCheck) {
    match response_code {
        Ok(()) => {}
        Err(message) => panic!("{message}"),
    }
}

fn expect_kernel_response_payload(resp: KernelResponse, context: &str) -> serde_json::Value {
    let payload = validate_kernel_response_payload(resp, context);
    expect_kernel_response_payload_check_passed(payload)
}

fn validate_kernel_response_payload(
    resp: KernelResponse,
    context: &str,
) -> KernelResponsePayloadCheck {
    match resp {
        KernelResponse::Ok { payload } => Ok(payload),
        KernelResponse::Err { message, .. } => Err(format!("{context} failed: {message}")),
    }
}

fn expect_kernel_response_payload_check_passed(
    payload: KernelResponsePayloadCheck,
) -> serde_json::Value {
    match payload {
        Ok(payload) => payload,
        Err(message) => panic!("{message}"),
    }
}

fn expect_unix_json_str<'a>(value: &'a serde_json::Value, key: &str, context: &str) -> &'a str {
    expect_unix_json_value_str(&value[key], &format!("{context}: Unix JSON `{key}`"))
}

fn expect_unix_json_value_str<'a>(value: &'a serde_json::Value, context: &str) -> &'a str {
    value
        .as_str()
        .unwrap_or_else(|| panic!("{context} string missing"))
}

fn expect_unix_json_object<'a>(
    value: &'a serde_json::Value,
    key: &str,
    context: &str,
) -> &'a serde_json::Map<String, serde_json::Value> {
    value[key]
        .as_object()
        .unwrap_or_else(|| panic!("{context}: Unix JSON `{key}` object missing"))
}

fn expect_unix_forget_proof_bytes(proof_b64: &str, context: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(proof_b64)
        .unwrap_or_else(|err| panic!("{context}: Unix forget-proof base64 decode failed: {err}"))
}

fn expect_unix_forget_proof(proof_bytes: &[u8], context: &str) -> mneme_core::ForgetProof {
    mneme_core::decode_forget_proof(proof_bytes)
        .unwrap_or_else(|err| panic!("{context}: Unix forget-proof CBOR decode failed: {err:?}"))
}

fn assert_connection_closed_error(err: &std::io::Error, context: &str) {
    let connection_closed = expect_connection_closed_error(err, context);
    assert_connection_closed_check_passed(connection_closed);
}

fn assert_connection_closed_check_passed(connection_closed: ConnectionClosedErrorCheck) {
    match connection_closed {
        Ok(()) => {}
        Err(message) => panic!("{message}"),
    }
}

fn expect_connection_closed_error(
    err: &std::io::Error,
    context: &str,
) -> ConnectionClosedErrorCheck {
    if matches!(
        err.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::ConnectionAborted
    ) {
        Ok(())
    } else {
        Err(format!(
            "{context}: unexpected error kind {:?}: {err}",
            err.kind()
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PostShutdownWriteOutcome {
    Written,
    Closed,
}

#[derive(Debug)]
enum PostShutdownReadOutcome {
    Closed(std::io::Error),
    TimedOut,
    Replied,
}

type PostShutdownRawRead = Result<usize, std::io::Error>;
type TimedPostShutdownRead = Result<PostShutdownRawRead, tokio::time::error::Elapsed>;

async fn write_after_shutdown(
    stream: &mut UnixStream,
    req: &KernelRequest,
) -> PostShutdownWriteOutcome {
    match write_raw_request(stream, req).await {
        Ok(()) => PostShutdownWriteOutcome::Written,
        Err(err) => {
            assert_connection_closed_error(&err, "post-shutdown request write");
            PostShutdownWriteOutcome::Closed
        }
    }
}

fn classify_post_shutdown_read(read_result: TimedPostShutdownRead) -> PostShutdownReadOutcome {
    match read_result {
        Ok(Err(err)) => PostShutdownReadOutcome::Closed(err),
        Err(_) => PostShutdownReadOutcome::TimedOut,
        Ok(Ok(_)) => PostShutdownReadOutcome::Replied,
    }
}

async fn read_after_shutdown(stream: &mut UnixStream) -> PostShutdownReadOutcome {
    let mut len_buf = [0u8; 4];
    match classify_post_shutdown_read(
        tokio::time::timeout(
            POST_SHUTDOWN_RESPONSE_READ_TIMEOUT,
            stream.read_exact(&mut len_buf),
        )
        .await,
    ) {
        PostShutdownReadOutcome::Closed(err) => {
            assert_connection_closed_error(&err, "post-shutdown response read");
            PostShutdownReadOutcome::Closed(err)
        }
        PostShutdownReadOutcome::TimedOut => PostShutdownReadOutcome::TimedOut,
        PostShutdownReadOutcome::Replied => PostShutdownReadOutcome::Replied,
    }
}

fn panic_post_shutdown_unexpected_response() {
    panic!("idle connection processed a request after server shutdown")
}

async fn expect_fake_unix_peer(handle: JoinHandle<FakeUnixPeerResult>, context: &str) {
    let joined = observe_fake_unix_peer_join(handle).await;
    let task_result = expect_joined_fake_unix_peer_task(joined, context);

    expect_successful_fake_unix_peer_result(task_result, context);
}

async fn observe_fake_unix_peer_join(handle: JoinHandle<FakeUnixPeerResult>) -> FakeUnixPeerJoin {
    handle.await
}

fn expect_joined_fake_unix_peer_task(
    joined: FakeUnixPeerJoin,
    context: &str,
) -> FakeUnixPeerResult {
    match joined {
        Ok(task_result) => task_result,
        Err(err) => panic!("{context} task panicked: {err}"),
    }
}

fn expect_successful_fake_unix_peer_result(task_result: FakeUnixPeerResult, context: &str) {
    match task_result {
        Ok(()) => {}
        Err(err) => panic!("{context} task failed: {err}"),
    }
}

async fn accept_fake_unix_peer(
    listener: UnixListener,
    context: &str,
) -> Result<UnixStream, String> {
    match accept_fake_unix_peer_stream_with_timeout(listener).await {
        FakeUnixPeerAcceptOutcome::Accepted(stream) => Ok(stream),
        FakeUnixPeerAcceptOutcome::Failed(err) => Err(format!("{context} accept failed: {err}")),
        FakeUnixPeerAcceptOutcome::TimedOut(_) => {
            Err(format!("{context} timed out waiting for client connection"))
        }
    }
}

async fn accept_fake_unix_peer_stream_with_timeout(
    listener: UnixListener,
) -> FakeUnixPeerAcceptOutcome {
    classify_fake_unix_peer_accept(
        tokio::time::timeout(FAKE_UNIX_PEER_ACCEPT_TIMEOUT, listener.accept()).await,
    )
}

fn classify_fake_unix_peer_accept(
    accept_result: TimedRawFakeUnixPeerStreamAccept,
) -> FakeUnixPeerAcceptOutcome {
    match accept_result {
        Ok(Ok((stream, _))) => FakeUnixPeerAcceptOutcome::Accepted(stream),
        Ok(Err(err)) => FakeUnixPeerAcceptOutcome::Failed(err),
        Err(err) => FakeUnixPeerAcceptOutcome::TimedOut(err),
    }
}

async fn read_fake_unix_request_exact(
    stream: &mut UnixStream,
    buf: &mut [u8],
    context: &str,
    part: &str,
) -> Result<(), String> {
    match read_fake_unix_request_exact_with_timeout(stream, buf).await {
        FakeUnixPeerRequestReadOutcome::Read => Ok(()),
        FakeUnixPeerRequestReadOutcome::Failed(err) => {
            Err(format!("{context} request {part} read failed: {err}"))
        }
        FakeUnixPeerRequestReadOutcome::TimedOut(_) => {
            Err(format!("{context} timed out waiting for request {part}"))
        }
    }
}

async fn read_fake_unix_request_exact_with_timeout(
    stream: &mut UnixStream,
    buf: &mut [u8],
) -> FakeUnixPeerRequestReadOutcome {
    classify_fake_unix_request_exact_read(
        tokio::time::timeout(FAKE_UNIX_PEER_REQUEST_TIMEOUT, stream.read_exact(buf)).await,
    )
}

fn classify_fake_unix_request_exact_read(
    read_result: TimedRawFakeUnixPeerExactRead,
) -> FakeUnixPeerRequestReadOutcome {
    match read_result {
        Ok(Ok(_)) => FakeUnixPeerRequestReadOutcome::Read,
        Ok(Err(err)) => FakeUnixPeerRequestReadOutcome::Failed(err),
        Err(err) => FakeUnixPeerRequestReadOutcome::TimedOut(err),
    }
}

async fn expect_fake_unix_peer_client_close(
    stream: &mut UnixStream,
    peer_context: &str,
    close_context: &str,
) -> Result<(), String> {
    let mut extra = [0u8; 1];
    match read_fake_unix_peer_client_close_with_timeout(stream, &mut extra).await {
        FakeUnixPeerClientCloseReadOutcome::Closed(err) => {
            expect_connection_closed_error(&err, close_context)
        }
        FakeUnixPeerClientCloseReadOutcome::WroteExtra => Err(format!(
            "{peer_context} client unexpectedly wrote another frame"
        )),
        FakeUnixPeerClientCloseReadOutcome::TimedOut(_) => Err(format!(
            "{peer_context} did not observe client close before timeout"
        )),
    }
}

async fn read_fake_unix_peer_client_close_with_timeout(
    stream: &mut UnixStream,
    buf: &mut [u8],
) -> FakeUnixPeerClientCloseReadOutcome {
    classify_fake_unix_peer_client_close(
        tokio::time::timeout(FAKE_UNIX_PEER_CLIENT_CLOSE_TIMEOUT, stream.read_exact(buf)).await,
    )
}

fn classify_fake_unix_peer_client_close(
    read_result: TimedRawFakeUnixPeerClientCloseRead,
) -> FakeUnixPeerClientCloseReadOutcome {
    match read_result {
        Ok(Err(err)) => FakeUnixPeerClientCloseReadOutcome::Closed(err),
        Ok(Ok(_)) => FakeUnixPeerClientCloseReadOutcome::WroteExtra,
        Err(err) => FakeUnixPeerClientCloseReadOutcome::TimedOut(err),
    }
}

async fn read_fake_unix_request(stream: &mut UnixStream, context: &str) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; 4];
    read_fake_unix_request_exact(stream, &mut len_buf, context, "length").await?;
    let req_len = u32::from_be_bytes(len_buf) as usize;
    let mut req_buf = vec![0u8; req_len];
    read_fake_unix_request_exact(stream, &mut req_buf, context, "body").await?;
    Ok(req_buf)
}

fn panic_silent_client_unexpected_response_frame() {
    panic!("silent client unexpectedly received a response frame")
}

fn panic_silent_client_close_timeout() {
    panic!("silent client connection should close after server I/O timeout")
}

async fn assert_silent_client_connection_close(stream: &mut UnixStream) {
    let mut len_buf = [0u8; 4];
    match read_silent_client_close_with_timeout(stream, &mut len_buf).await {
        SilentClientCloseReadOutcome::Closed(err) => {
            assert_connection_closed_error(&err, "silent client connection close")
        }
        SilentClientCloseReadOutcome::Replied => {
            panic_silent_client_unexpected_response_frame();
        }
        SilentClientCloseReadOutcome::TimedOut(_) => {
            panic_silent_client_close_timeout();
        }
    }
}

async fn read_silent_client_close_with_timeout(
    stream: &mut UnixStream,
    buf: &mut [u8],
) -> SilentClientCloseReadOutcome {
    classify_silent_client_close_read(
        tokio::time::timeout(UNIX_SILENT_CLIENT_CLOSE_TIMEOUT, stream.read_exact(buf)).await,
    )
}

fn classify_silent_client_close_read(
    read_result: TimedSilentClientCloseRead,
) -> SilentClientCloseReadOutcome {
    match read_result {
        Ok(Err(err)) => SilentClientCloseReadOutcome::Closed(err),
        Ok(Ok(_)) => SilentClientCloseReadOutcome::Replied,
        Err(err) => SilentClientCloseReadOutcome::TimedOut(err),
    }
}

fn expect_unix_api_tempdir(context: &str) -> tempfile::TempDir {
    tempdir().unwrap_or_else(|err| panic!("{context}: Unix API tempdir failed: {err}"))
}

fn expect_unix_api_state(store_path: &Path, context: &str) -> mnemed::AppState {
    let (state, _operator, _agent) = test_state(store_path)
        .unwrap_or_else(|err| panic!("{context}: Unix API test state failed: {err:?}"));
    state
}

fn expect_unix_api_state_with_keys(store_path: &Path, context: &str) -> UnixApiStateWithKeys {
    test_state(store_path)
        .unwrap_or_else(|err| panic!("{context}: Unix API state with keys failed: {err:?}"))
}

fn expect_unix_agent_cap_b64(operator: &KeyPair, agent: &KeyPair, context: &str) -> String {
    let cap = agent_cap(operator, agent.public_key_bytes())
        .unwrap_or_else(|err| panic!("{context}: Unix API agent capability failed: {err:?}"));
    cap_to_b64(&cap)
        .unwrap_or_else(|err| panic!("{context}: Unix API capability encoding failed: {err:?}"))
}

fn authorize_unix_api_writer(state: &mnemed::AppState, writer: &KeyPair, context: &str) {
    let mut store = state
        .store
        .lock()
        .unwrap_or_else(|err| panic!("{context}: Unix API store lock failed: {err}"));
    store.trust = store.trust.clone().with_writer(writer.public_key_bytes());
}

fn expect_occupied_socket_file_written(sock: &Path, contents: &[u8], context: &str) {
    std::fs::write(sock, contents)
        .unwrap_or_else(|err| panic!("{context}: occupied socket file write failed: {err}"));
}

fn expect_occupied_socket_file_bytes(sock: &Path, context: &str) -> Vec<u8> {
    std::fs::read(sock)
        .unwrap_or_else(|err| panic!("{context}: occupied socket file read failed: {err}"))
}

async fn expect_unix_api_stream_connect(sock: &Path, context: &str) -> UnixStream {
    UnixStream::connect(sock)
        .await
        .unwrap_or_else(|err| panic!("{context}: Unix API stream connect failed: {err}"))
}

fn expect_fake_unix_listener(sock: &Path, context: &str) -> UnixListener {
    UnixListener::bind(sock)
        .unwrap_or_else(|err| panic!("{context}: fake Unix listener bind failed: {err}"))
}

async fn expect_request_json_error(
    request: impl std::future::Future<Output = RequestJsonResult>,
    context: &str,
) -> std::io::Error {
    match request.await {
        Ok(response) => panic!("{context}: request-json unexpectedly succeeded: {response:?}"),
        Err(err) => err,
    }
}

async fn expect_request_json_response(
    request: impl std::future::Future<Output = RequestJsonResult>,
    context: &str,
) -> KernelResponse {
    request
        .await
        .unwrap_or_else(|err| panic!("{context}: request-json request failed: {err}"))
}

#[tokio::test]
async fn unix_server_exits_on_shutdown_signal() {
    let dir = expect_unix_api_tempdir("shutdown-signal test");
    let sock = dir.path().join("shutdown.sock");
    let state = expect_unix_api_state(dir.path(), "shutdown-signal test");
    let server = spawn_unix(sock.clone(), state).await;

    assert!(sock.exists(), "socket should be bound before shutdown");
    server.shutdown().await;
    assert!(!sock.exists(), "socket should be removed after shutdown");
}

#[tokio::test]
async fn unix_server_refuses_to_clobber_existing_non_socket_path() {
    let dir = expect_unix_api_tempdir("existing-path refusal test");
    let sock = dir.path().join("occupied.sock");
    expect_occupied_socket_file_written(&sock, b"preserve this file", "existing-path refusal test");
    let state = expect_unix_api_state(dir.path(), "existing-path refusal test");
    let err = expect_unix_start_error(sock.clone(), state).await;

    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(
        expect_occupied_socket_file_bytes(&sock, "existing-path refusal test"),
        b"preserve this file"
    );
}

#[tokio::test]
async fn unix_shutdown_closes_idle_connections() {
    let dir = expect_unix_api_tempdir("idle-shutdown test");
    let sock = dir.path().join("idle-shutdown.sock");
    let state = expect_unix_api_state(dir.path(), "idle-shutdown test");
    let server = spawn_unix(sock.clone(), state).await;

    let mut stream = expect_unix_api_stream_connect(&sock, "idle-shutdown test").await;
    server.shutdown().await;

    let req = KernelRequest::Head {
        cap_b64: "invalid".into(),
    };

    match write_after_shutdown(&mut stream, &req).await {
        PostShutdownWriteOutcome::Closed => {}
        PostShutdownWriteOutcome::Written => match read_after_shutdown(&mut stream).await {
            PostShutdownReadOutcome::Closed(_) | PostShutdownReadOutcome::TimedOut => {}
            PostShutdownReadOutcome::Replied => {
                panic_post_shutdown_unexpected_response();
            }
        },
    }
}

#[tokio::test]
async fn unix_connection_io_timeout_closes_silent_client() {
    let dir = expect_unix_api_tempdir("silent-client close test");
    let sock = dir.path().join("io-timeout.sock");
    let state = expect_unix_api_state(dir.path(), "silent-client close test");
    let server =
        spawn_unix_with_io_timeout(sock.clone(), state, UNIX_SILENT_CLIENT_IO_TIMEOUT).await;

    let mut stream = expect_unix_api_stream_connect(&sock, "silent-client close test").await;
    assert_silent_client_connection_close(&mut stream).await;

    server.shutdown().await;
}

#[tokio::test]
async fn request_json_rejects_oversized_request_before_connect() {
    let dir = expect_unix_api_tempdir("oversized request before connect");
    let missing_sock = dir.path().join("missing.sock");
    let req = KernelRequest::Remember {
        cap_b64: "invalid".into(),
        namespace: "unix".into(),
        name: "oversized".into(),
        body_b64: "A".repeat(mnemed::unix::UNIX_MAX_FRAME + 1),
        embedding: None,
    };

    let err = expect_request_json_error(
        request_json(&missing_sock, &req),
        "oversized request before connect",
    )
    .await;

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(
        err.to_string()
            .contains("request frame length exceeds MAX_FRAME"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn request_json_rejects_oversized_response_frame() {
    let dir = expect_unix_api_tempdir("oversized response peer");
    let sock = dir.path().join("oversized-response.sock");
    let listener = expect_fake_unix_listener(&sock, "oversized response peer");
    let server = tokio::spawn(async move {
        let mut stream = accept_fake_unix_peer(listener, "oversized response peer").await?;
        let _req = read_fake_unix_request(&mut stream, "oversized response peer").await?;
        let oversized_len = ((mnemed::unix::UNIX_MAX_FRAME + 1) as u32).to_be_bytes();
        stream
            .write_all(&oversized_len)
            .await
            .map_err(|err| format!("oversized response peer response length write failed: {err}"))
    });

    let err = expect_request_json_error(
        request_json(
            &sock,
            &KernelRequest::Head {
                cap_b64: "invalid".into(),
            },
        ),
        "oversized response peer",
    )
    .await;

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(
        err.to_string()
            .contains("response frame length exceeds MAX_FRAME"),
        "unexpected error: {err}"
    );
    expect_fake_unix_peer(server, "oversized response peer").await;
}

#[tokio::test]
async fn request_json_times_out_when_peer_stalls_response() {
    let dir = expect_unix_api_tempdir("stalled response peer");
    let sock = dir.path().join("stalled-response.sock");
    let listener = expect_fake_unix_listener(&sock, "stalled response peer");
    let server = tokio::spawn(async move {
        let mut stream = accept_fake_unix_peer(listener, "stalled response peer").await?;
        let _req = read_fake_unix_request(&mut stream, "stalled response peer").await?;
        expect_fake_unix_peer_client_close(
            &mut stream,
            "stalled response peer",
            "stalled peer client close",
        )
        .await
    });

    let err = expect_request_json_error(
        request_json_with_timeout(
            &sock,
            &KernelRequest::Head {
                cap_b64: "invalid".into(),
            },
            STALLED_RESPONSE_CLIENT_TIMEOUT,
        ),
        "stalled response peer",
    )
    .await;

    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    assert!(
        err.to_string().contains("Unix kernel request timed out"),
        "unexpected error: {err}"
    );
    expect_fake_unix_peer(server, "stalled response peer").await;
}

#[tokio::test]
async fn request_json_zero_timeout_uses_default_deadline() {
    let dir = expect_unix_api_tempdir("zero-timeout response peer");
    let sock = dir.path().join("client-zero-timeout.sock");
    let listener = expect_fake_unix_listener(&sock, "zero-timeout response peer");
    let (request_seen_tx, request_seen_rx) = tokio::sync::oneshot::channel();
    let (send_response_tx, send_response_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut stream = accept_fake_unix_peer(listener, "zero-timeout response peer").await?;
        let _req = read_fake_unix_request(&mut stream, "zero-timeout response peer").await?;
        request_seen_tx
            .send(())
            .map_err(|_| "zero-timeout response peer request-seen receiver dropped".to_string())?;
        send_response_rx
            .await
            .map_err(|_| "zero-timeout response peer release signal dropped".to_string())?;
        let resp = mnemed::unix::KernelResponse::Err {
            code: "delayed".into(),
            message: "delayed response".into(),
        };
        let out = serde_json::to_vec(&resp)
            .map_err(|err| format!("zero-timeout response peer response json failed: {err}"))?;
        stream
            .write_all(&(out.len() as u32).to_be_bytes())
            .await
            .map_err(|err| {
                format!("zero-timeout response peer response length write failed: {err}")
            })?;
        stream
            .write_all(&out)
            .await
            .map_err(|err| format!("zero-timeout response peer response body write failed: {err}"))
    });

    let client_sock = sock.clone();
    let client = tokio::spawn(async move {
        request_json_with_timeout(
            &client_sock,
            &KernelRequest::Head {
                cap_b64: "invalid".into(),
            },
            Duration::ZERO,
        )
        .await
    });

    expect_zero_timeout_request_seen(request_seen_rx, "zero-timeout response peer").await;
    yield_zero_timeout_progress().await;
    assert!(
        !client.is_finished(),
        "zero client timeout should normalize to the default deadline while response is withheld"
    );
    release_zero_timeout_response(send_response_tx, "zero-timeout response peer");

    let client_join = join_zero_timeout_client(client).await;
    let resp = expect_zero_timeout_client_response(client_join);

    assert_kernel_response_error_code(resp, "delayed", "zero-timeout delayed response");
    expect_fake_unix_peer(server, "zero-timeout response peer").await;
}

#[tokio::test]
async fn unix_server_zero_timeout_uses_default_deadline() {
    let dir = expect_unix_api_tempdir("server zero-timeout test");
    let sock = dir.path().join("server-zero-timeout.sock");
    let state = expect_unix_api_state(dir.path(), "server zero-timeout test");
    let server = spawn_unix_with_io_timeout(sock.clone(), state, Duration::ZERO).await;

    let mut stream = expect_unix_api_stream_connect(&sock, "server zero-timeout test").await;
    yield_zero_timeout_progress().await;
    expect_raw_unix_request_written(
        &mut stream,
        &KernelRequest::Head {
            cap_b64: "invalid".into(),
        },
        "server zero-timeout test",
    )
    .await;
    let resp = expect_raw_unix_kernel_response(&mut stream, "server zero-timeout test").await;

    assert_cap_denied(
        resp,
        "zero-timeout invalid capability must fail as auth denial",
    );

    server.shutdown().await;
}

#[tokio::test]
async fn unix_remember_and_head_roundtrip() {
    let dir = expect_unix_api_tempdir("remember/head roundtrip");
    let sock = dir.path().join("mneme.sock");
    let (state, operator, agent) =
        expect_unix_api_state_with_keys(dir.path(), "remember/head roundtrip");
    let cap_b64 = expect_unix_agent_cap_b64(&operator, &agent, "remember/head roundtrip");
    authorize_unix_api_writer(&state, &agent, "remember/head roundtrip");
    let server = spawn_unix(sock.clone(), state).await;

    let remember = expect_request_json_response(
        request_json(
            &sock,
            &KernelRequest::Remember {
                cap_b64: cap_b64.clone(),
                namespace: "unix".into(),
                name: "key".into(),
                body_b64: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    b"payload",
                ),
                embedding: None,
            },
        ),
        "remember/head remember request",
    )
    .await;
    let remember_payload = expect_kernel_response_payload(remember, "remember");
    assert!(remember_payload.get("object_id").is_some());

    let head = expect_request_json_response(
        request_json(
            &sock,
            &KernelRequest::Head {
                cap_b64: cap_b64.clone(),
            },
        ),
        "remember/head head request",
    )
    .await;
    let head_payload = expect_kernel_response_payload(head, "head");
    assert_eq!(head_payload["sequence"].as_u64(), Some(2));

    server.shutdown().await;
}

#[tokio::test]
async fn unix_head_rejects_malformed_decoded_capability_as_cap_denied() {
    let dir = expect_unix_api_tempdir("malformed head capability");
    let sock = dir.path().join("malformed-head-cap.sock");
    let state = expect_unix_api_state(dir.path(), "malformed head capability");
    let server = spawn_unix(sock.clone(), state).await;

    let resp = expect_request_json_response(
        request_json(
            &sock,
            &KernelRequest::Head {
                cap_b64: "oA==".into(),
            },
        ),
        "malformed head capability request",
    )
    .await;
    assert_cap_denied(
        resp,
        "malformed decoded capability must fail as auth denial",
    );

    server.shutdown().await;
}

#[tokio::test]
async fn unix_head_rejects_oversized_capability_as_cap_denied() {
    let dir = expect_unix_api_tempdir("oversized head capability");
    let sock = dir.path().join("oversized-head-cap.sock");
    let state = expect_unix_api_state(dir.path(), "oversized head capability");
    let server = spawn_unix(sock.clone(), state).await;

    let resp = expect_request_json_response(
        request_json(
            &sock,
            &KernelRequest::Head {
                cap_b64: "A".repeat(mnemed::state::MAX_CAPABILITY_B64_LEN + 1),
            },
        ),
        "oversized head capability request",
    )
    .await;
    assert_cap_denied(resp, "oversized capability must fail as auth denial");

    server.shutdown().await;
}

#[tokio::test]
async fn daemon_start_serves_configured_unix_socket() {
    let dir = expect_unix_api_tempdir("daemon configured Unix socket");
    let sock = dir.path().join("daemon.sock");
    let (state, operator, agent) =
        expect_unix_api_state_with_keys(dir.path(), "daemon configured Unix socket");
    let cap_b64 = expect_unix_agent_cap_b64(&operator, &agent, "daemon configured Unix socket");
    let server =
        expect_daemon_start_with_unix_socket(&sock, state, "daemon configured Unix socket").await;

    wait_for_unix_socket_accepting(&sock).await;
    let head = expect_request_json_response(
        request_json(&sock, &KernelRequest::Head { cap_b64 }),
        "daemon configured Unix socket head request",
    )
    .await;
    let head_payload = expect_kernel_response_payload(head, "daemon unix head");
    assert_eq!(head_payload["sequence"].as_u64(), Some(1));

    server.shutdown().await;
    assert!(!sock.exists(), "daemon shutdown should remove Unix socket");
}

#[tokio::test]
async fn daemon_start_refuses_to_clobber_existing_non_socket_path() {
    let dir = expect_unix_api_tempdir("occupied Unix socket path");
    let sock = dir.path().join("occupied-daemon.sock");
    expect_occupied_socket_file_written(
        &sock,
        b"preserve daemon path",
        "occupied Unix socket path",
    );
    let state = expect_unix_api_state(dir.path(), "occupied Unix socket path");

    let err =
        expect_daemon_start_failure_with_unix_socket(&sock, state, "occupied Unix socket path")
            .await;
    let kind = expect_daemon_start_io_failure(err, &sock, "occupied Unix socket path");
    assert!(
        kind.contains("not a socket"),
        "unexpected daemon Unix socket error: {kind}"
    );
    assert_eq!(
        expect_occupied_socket_file_bytes(&sock, "occupied Unix socket path"),
        b"preserve daemon path"
    );
}

#[tokio::test]
async fn daemon_start_rejects_unbindable_unix_socket_path() {
    let dir = expect_unix_api_tempdir("unbindable Unix socket path");
    let sock = dir.path().join("x".repeat(240));
    let state = expect_unix_api_state(dir.path(), "unbindable Unix socket path");

    let err =
        expect_daemon_start_failure_with_unix_socket(&sock, state, "unbindable Unix socket path")
            .await;
    let kind = expect_daemon_start_io_failure(err, &sock, "unbindable Unix socket path");
    assert!(
        kind.contains("too long")
            || kind.contains("Invalid")
            || kind.contains("invalid")
            || kind.contains("exceeds")
            || kind.contains("SUN_LEN"),
        "unexpected daemon Unix socket bind error: {kind}"
    );
    assert!(
        !sock.exists(),
        "unbindable Unix socket path should not leave a filesystem entry"
    );
}

#[tokio::test]
async fn unix_key_scoped_requests_reject_empty_logical_key() {
    let dir = expect_unix_api_tempdir("key-scoped empty logical key");
    let sock = dir.path().join("blank-key.sock");
    let (state, operator, agent) =
        expect_unix_api_state_with_keys(dir.path(), "key-scoped empty logical key");
    let cap_b64 = expect_unix_agent_cap_b64(&operator, &agent, "key-scoped empty logical key");
    authorize_unix_api_writer(&state, &agent, "key-scoped empty logical key");
    let server = spawn_unix(sock.clone(), state).await;

    let remember = expect_request_json_response(
        request_json(
            &sock,
            &KernelRequest::Remember {
                cap_b64: cap_b64.clone(),
                namespace: "   ".into(),
                name: "note".into(),
                body_b64: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    b"invalid",
                ),
                embedding: None,
            },
        ),
        "key-scoped empty logical key remember request",
    )
    .await;
    assert_schema_drift(remember, "empty namespace must fail before remember");

    let recall = expect_request_json_response(
        request_json(
            &sock,
            &KernelRequest::RecallVerified {
                cap_b64: cap_b64.clone(),
                namespace: "unix".into(),
                name: " ".into(),
                prompt: None,
                weight_measurement_hex: None,
                sampling_params: None,
                output_token_commit_hex: None,
                embedding: None,
            },
        ),
        "key-scoped empty logical key recall request",
    )
    .await;
    assert_schema_drift(recall, "empty name must fail before recall");

    let forget = expect_request_json_response(
        request_json(
            &sock,
            &KernelRequest::Forget {
                cap_b64: cap_b64.clone(),
                namespace: "".into(),
                name: "note".into(),
                mode: "shred".into(),
                emit_proof: None,
            },
        ),
        "key-scoped empty logical key forget request",
    )
    .await;
    assert_schema_drift(forget, "empty namespace must fail before forget");

    let prove_absent = expect_request_json_response(
        request_json(
            &sock,
            &KernelRequest::ProveAbsent {
                cap_b64,
                namespace: "unix".into(),
                name: "".into(),
            },
        ),
        "key-scoped empty logical key prove-absent request",
    )
    .await;
    assert_schema_drift(prove_absent, "empty name must fail before prove-absent");

    server.shutdown().await;
}

#[tokio::test]
async fn unix_sync_hello_returns_root_proof() {
    let dir = expect_unix_api_tempdir("sync hello");
    let sock = dir.path().join("sync.sock");
    let (state, operator, agent) = expect_unix_api_state_with_keys(dir.path(), "sync hello");
    let cap_b64 = expect_unix_agent_cap_b64(&operator, &agent, "sync hello");
    let server = spawn_unix(sock.clone(), state).await;

    let sync_request = expect_unix_sync_frame_request(cap_b64, "sync hello");
    let resp =
        expect_request_json_response(request_json(&sock, &sync_request), "sync hello request")
            .await;
    let sync_payload = expect_kernel_response_payload(resp, "sync");
    assert!(sync_payload.get("sync_bytes_b64").is_some());
    server.shutdown().await;
}

#[tokio::test]
async fn unix_sync_frame_requires_capability() {
    let dir = expect_unix_api_tempdir("sync frame without capability");
    let sock = dir.path().join("sync-auth.sock");
    let state = expect_unix_api_state(dir.path(), "sync frame without capability");
    let server = spawn_unix(sock.clone(), state).await;

    let sync_request =
        expect_unix_sync_frame_request("not-valid".into(), "sync frame without capability");
    let resp = expect_request_json_response(
        request_json(&sock, &sync_request),
        "sync frame without capability request",
    )
    .await;
    assert_cap_denied(
        resp,
        "sync frame without capability must fail as auth denial",
    );
    server.shutdown().await;
}

#[tokio::test]
async fn unix_sync_frame_rejects_malformed_decoded_capability_as_cap_denied() {
    let dir = expect_unix_api_tempdir("malformed sync capability");
    let sock = dir.path().join("malformed-sync-cap.sock");
    let state = expect_unix_api_state(dir.path(), "malformed sync capability");
    let server = spawn_unix(sock.clone(), state).await;

    let sync_request = expect_unix_sync_frame_request("oA==".into(), "malformed sync capability");
    let resp = expect_request_json_response(
        request_json(&sock, &sync_request),
        "malformed sync capability request",
    )
    .await;
    assert_cap_denied(
        resp,
        "malformed decoded sync capability must fail as auth denial",
    );

    server.shutdown().await;
}

#[tokio::test]
async fn unix_sync_frame_rejects_oversized_capability_as_cap_denied() {
    let dir = expect_unix_api_tempdir("oversized sync capability");
    let sock = dir.path().join("oversized-sync-cap.sock");
    let state = expect_unix_api_state(dir.path(), "oversized sync capability");
    let server = spawn_unix(sock.clone(), state).await;

    let sync_request = expect_unix_sync_frame_request(
        "A".repeat(mnemed::state::MAX_CAPABILITY_B64_LEN + 1),
        "oversized sync capability",
    );
    let resp = expect_request_json_response(
        request_json(&sock, &sync_request),
        "oversized sync capability request",
    )
    .await;
    assert_cap_denied(resp, "oversized sync capability must fail as auth denial");

    server.shutdown().await;
}

#[tokio::test]
async fn unix_prove_absent_requires_capability() {
    let dir = expect_unix_api_tempdir("prove-absent missing capability");
    let sock = dir.path().join("absent-auth.sock");
    let state = expect_unix_api_state(dir.path(), "prove-absent missing capability");
    let server = spawn_unix(sock.clone(), state).await;

    let resp = expect_request_json_response(
        request_json(
            &sock,
            &KernelRequest::ProveAbsent {
                cap_b64: "not-valid".into(),
                namespace: "user".into(),
                name: "never-seen".into(),
            },
        ),
        "prove-absent missing capability request",
    )
    .await;
    assert_cap_denied(
        resp,
        "prove-absent without capability must fail as auth denial",
    );
    server.shutdown().await;
}

#[tokio::test]
async fn unix_forget_proof_returns_canonical_proof_bound_to_signed_root() {
    let dir = expect_unix_api_tempdir("forget-proof");
    let sock = dir.path().join("forget-proof.sock");
    let (state, operator, agent) = expect_unix_api_state_with_keys(dir.path(), "forget-proof");
    let cap_b64 = expect_unix_agent_cap_b64(&operator, &agent, "forget-proof");
    let server = spawn_unix(sock.clone(), state).await;

    let remember = expect_request_json_response(
        request_json(
            &sock,
            &KernelRequest::Remember {
                cap_b64: cap_b64.clone(),
                namespace: "unix".into(),
                name: "proof-target".into(),
                body_b64: base64::engine::general_purpose::STANDARD.encode(b"delete with proof"),
                embedding: None,
            },
        ),
        "forget-proof remember request",
    )
    .await;
    let _ = expect_kernel_response_payload(remember, "forget-proof remember response");

    let forget = expect_request_json_response(
        request_json(
            &sock,
            &KernelRequest::ForgetProof {
                cap_b64: cap_b64.clone(),
                namespace: "unix".into(),
                name: "proof-target".into(),
            },
        ),
        "forget-proof request",
    )
    .await;
    let payload = expect_kernel_response_payload(forget, "forget-proof response");
    let proof_b64 = expect_unix_json_str(&payload, "proof_cbor_b64", "forget-proof response");
    let proof_bytes = expect_unix_forget_proof_bytes(proof_b64, "forget-proof response");
    let proof = expect_unix_forget_proof(&proof_bytes, "forget-proof response");
    let root = expect_unix_json_object(&payload, "root", "forget-proof response");
    assert_eq!(
        hex::encode(proof.root_bound),
        expect_unix_json_value_str(
            &root["preimage_hash_hex"],
            "forget-proof root preimage hash"
        )
    );
    assert_eq!(
        hex::encode(proof.root_bound),
        expect_unix_json_str(&payload, "root_hash_hex", "forget-proof response")
    );
    assert_eq!(proof.version, mneme_core::FORGET_PROOF_VERSION);
    assert!(
        expect_unix_json_value_str(&root["signature_hex"], "forget-proof root signature").len()
            >= 128
    );

    let recall = expect_request_json_response(
        request_json(
            &sock,
            &KernelRequest::RecallVerified {
                cap_b64,
                namespace: "unix".into(),
                name: "proof-target".into(),
                prompt: None,
                weight_measurement_hex: None,
                sampling_params: None,
                output_token_commit_hex: None,
                embedding: None,
            },
        ),
        "forget-proof recall after request",
    )
    .await;
    assert_kernel_response_error_code(recall, "Forgotten", "forget-proof recall must fail closed");

    server.shutdown().await;
}

#[tokio::test]
async fn unix_recall_partial_robr_params_fail_closed() {
    // Supplying some — but not all four — ROBR receipt inputs is ambiguous and must be
    // rejected (before any recall work) rather than silently returning a recall with no
    // receipt.
    let dir = expect_unix_api_tempdir("robr-partial");
    let sock = dir.path().join("robr-partial.sock");
    let (state, operator, agent) = expect_unix_api_state_with_keys(dir.path(), "robr-partial");
    let cap_b64 = expect_unix_agent_cap_b64(&operator, &agent, "robr-partial");
    let server = spawn_unix(sock.clone(), state).await;

    // Only the prompt is supplied → fail closed (no remember needed: the request-shape
    // check runs before the recall).
    let recall = expect_request_json_response(
        request_json(
            &sock,
            &KernelRequest::RecallVerified {
                cap_b64,
                namespace: "unix".into(),
                name: "robr-key".into(),
                prompt: Some("only the prompt".into()),
                weight_measurement_hex: None,
                sampling_params: None,
                output_token_commit_hex: None,
                embedding: None,
            },
        ),
        "robr-partial recall request",
    )
    .await;
    assert_schema_drift(recall, "partial ROBR params must fail closed");

    server.shutdown().await;
}

#[tokio::test]
async fn unix_recall_full_robr_params_emit_verifiable_receipt() {
    use base64::Engine as _;
    use mneme_account::robr::RobrReceiptV1;

    let dir = expect_unix_api_tempdir("robr-full");
    let sock = dir.path().join("robr-full.sock");
    let (state, operator, agent) = expect_unix_api_state_with_keys(dir.path(), "robr-full");
    let cap_b64 = expect_unix_agent_cap_b64(&operator, &agent, "robr-full");
    // Trust the agent as a writer so the remembered entry verifies on recall.
    authorize_unix_api_writer(&state, &agent, "robr-full");
    let server = spawn_unix(sock.clone(), state).await;

    let remember = expect_request_json_response(
        request_json(
            &sock,
            &KernelRequest::Remember {
                cap_b64: cap_b64.clone(),
                namespace: "unix".into(),
                name: "robr-key".into(),
                body_b64: base64::engine::general_purpose::STANDARD.encode(b"robr body"),
                embedding: None,
            },
        ),
        "robr-full remember request",
    )
    .await;
    let _ = expect_kernel_response_payload(remember, "robr-full remember response");

    let recall = expect_request_json_response(
        request_json(
            &sock,
            &KernelRequest::RecallVerified {
                cap_b64,
                namespace: "unix".into(),
                name: "robr-key".into(),
                prompt: Some("what is in robr-key?".into()),
                weight_measurement_hex: Some("11".repeat(32)),
                sampling_params: Some("model=test;temp=0".into()),
                output_token_commit_hex: Some("22".repeat(32)),
                embedding: None,
            },
        ),
        "robr-full recall request",
    )
    .await;
    let payload = expect_kernel_response_payload(recall, "robr-full recall response");
    let receipt_b64 = expect_unix_json_str(&payload, "robr_receipt_b64", "robr-full receipt");
    let wire = base64::engine::general_purpose::STANDARD
        .decode(receipt_b64)
        .expect("receipt base64 decodes");

    // The minted receipt must verify offline under the store operator key (signature +
    // envelope consistency), and its bound context must match the recall result.
    let receipt = RobrReceiptV1::verify(&wire, Some(&operator.public_key_bytes()))
        .expect("minted receipt verifies under the store operator key");
    assert_eq!(receipt.output_token_commit, [0x22u8; 32]);
    assert_eq!(receipt.weight_measurement, [0x11u8; 32]);
    let count = payload
        .get("count")
        .and_then(|v| v.as_u64())
        .expect("recall count");
    assert_eq!(
        receipt.context_ids.len() as u64,
        count,
        "receipt context binds exactly the recalled entries"
    );

    server.shutdown().await;
}
