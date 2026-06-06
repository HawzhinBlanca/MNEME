//! Unix socket RPC smoke test (remember / head / sync hello).

mod unix_ready;

use mneme_cap::agent_cap;
use mneme_core::{NodeId, SyncMessage};
use mneme_crdt::encode_sync_message;
use mnemed::{
    ServerConfig, cap_to_b64, start_with_state, test_state,
    unix::{KernelRequest, KernelResponse, UnixServer, request_json, request_json_with_timeout},
};
use std::path::PathBuf;
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinHandle;
use unix_ready::wait_for_unix_socket_accepting;

type FakeUnixPeerResult = Result<(), String>;

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
const ZERO_TIMEOUT_REQUEST_SEEN_TIMEOUT: Duration = Duration::from_secs(1);

struct RunningUnix {
    shutdown_tx: tokio::sync::watch::Sender<()>,
    handle: JoinHandle<Result<(), std::io::Error>>,
}

impl RunningUnix {
    async fn shutdown(self) {
        self.shutdown_tx.send(()).expect("send shutdown");
        let result = tokio::time::timeout(UNIX_SERVER_SHUTDOWN_TIMEOUT, self.handle)
            .await
            .expect("server exits before timeout")
            .expect("server task joins");
        assert!(result.is_ok(), "server returned error: {result:?}");
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

    tokio::time::timeout(UNIX_START_ERROR_TIMEOUT, handle)
        .await
        .expect("server exits before timeout")
        .expect("start-failure Unix server task joins")
        .expect_err("Unix server start must fail closed")
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

fn assert_schema_drift(resp: KernelResponse, context: &str) {
    match resp {
        KernelResponse::Err { code, .. } => assert_eq!(code, "SchemaDrift", "{context}"),
        KernelResponse::Ok { payload } => panic!("{context} unexpectedly succeeded: {payload}"),
    }
}

fn assert_cap_denied(resp: KernelResponse, context: &str) {
    match resp {
        KernelResponse::Err { code, .. } => assert_eq!(code, "CapDenied", "{context}"),
        KernelResponse::Ok { payload } => panic!("{context} unexpectedly succeeded: {payload}"),
    }
}

fn assert_connection_closed_error(err: &std::io::Error, context: &str) {
    expect_connection_closed_error(err, context).unwrap_or_else(|message| panic!("{message}"));
}

fn expect_connection_closed_error(err: &std::io::Error, context: &str) -> Result<(), String> {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PostShutdownReadOutcome {
    Closed,
    TimedOut,
    Replied,
}

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

async fn read_after_shutdown(stream: &mut UnixStream) -> PostShutdownReadOutcome {
    let mut len_buf = [0u8; 4];
    match tokio::time::timeout(
        POST_SHUTDOWN_RESPONSE_READ_TIMEOUT,
        stream.read_exact(&mut len_buf),
    )
    .await
    {
        Ok(Err(err)) => {
            assert_connection_closed_error(&err, "post-shutdown response read");
            PostShutdownReadOutcome::Closed
        }
        Err(_) => PostShutdownReadOutcome::TimedOut,
        Ok(Ok(_)) => PostShutdownReadOutcome::Replied,
    }
}

async fn expect_fake_unix_peer(handle: JoinHandle<FakeUnixPeerResult>, context: &str) {
    handle
        .await
        .unwrap_or_else(|err| panic!("{context} task panicked: {err}"))
        .unwrap_or_else(|err| panic!("{context} task failed: {err}"));
}

async fn accept_fake_unix_peer(
    listener: UnixListener,
    context: &str,
) -> Result<UnixStream, String> {
    let (stream, _) = tokio::time::timeout(FAKE_UNIX_PEER_ACCEPT_TIMEOUT, listener.accept())
        .await
        .map_err(|_| format!("{context} timed out waiting for client connection"))?
        .map_err(|err| format!("{context} accept failed: {err}"))?;
    Ok(stream)
}

async fn read_fake_unix_request_exact(
    stream: &mut UnixStream,
    buf: &mut [u8],
    context: &str,
    part: &str,
) -> Result<(), String> {
    match tokio::time::timeout(FAKE_UNIX_PEER_REQUEST_TIMEOUT, stream.read_exact(buf)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(err)) => Err(format!("{context} request {part} read failed: {err}")),
        Err(_) => Err(format!("{context} timed out waiting for request {part}")),
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

#[tokio::test]
async fn unix_server_exits_on_shutdown_signal() {
    let dir = tempdir().expect("tempdir");
    let sock = dir.path().join("shutdown.sock");
    let (state, _operator, _agent) = test_state(dir.path()).expect("test_state");
    let server = spawn_unix(sock.clone(), state).await;

    assert!(sock.exists(), "socket should be bound before shutdown");
    server.shutdown().await;
    assert!(!sock.exists(), "socket should be removed after shutdown");
}

#[tokio::test]
async fn unix_server_refuses_to_clobber_existing_non_socket_path() {
    let dir = tempdir().expect("tempdir");
    let sock = dir.path().join("occupied.sock");
    std::fs::write(&sock, b"preserve this file").expect("write occupied path");
    let (state, _operator, _agent) = test_state(dir.path()).expect("test_state");
    let err = expect_unix_start_error(sock.clone(), state).await;

    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(
        std::fs::read(&sock).expect("occupied path still exists"),
        b"preserve this file"
    );
}

#[tokio::test]
async fn unix_shutdown_closes_idle_connections() {
    let dir = tempdir().expect("tempdir");
    let sock = dir.path().join("idle-shutdown.sock");
    let (state, _operator, _agent) = test_state(dir.path()).expect("test_state");
    let server = spawn_unix(sock.clone(), state).await;

    let mut stream = UnixStream::connect(&sock).await.expect("connect");
    server.shutdown().await;

    let req = KernelRequest::Head {
        cap_b64: "invalid".into(),
    };

    match write_after_shutdown(&mut stream, &req).await {
        PostShutdownWriteOutcome::Closed => {}
        PostShutdownWriteOutcome::Written => match read_after_shutdown(&mut stream).await {
            PostShutdownReadOutcome::Closed | PostShutdownReadOutcome::TimedOut => {}
            PostShutdownReadOutcome::Replied => {
                panic!("idle connection processed a request after server shutdown")
            }
        },
    }
}

#[tokio::test]
async fn unix_connection_io_timeout_closes_silent_client() {
    let dir = tempdir().expect("tempdir");
    let sock = dir.path().join("io-timeout.sock");
    let (state, _operator, _agent) = test_state(dir.path()).expect("test_state");
    let server =
        spawn_unix_with_io_timeout(sock.clone(), state, UNIX_SILENT_CLIENT_IO_TIMEOUT).await;

    let mut stream = UnixStream::connect(&sock).await.expect("connect");
    let mut len_buf = [0u8; 4];
    let err = tokio::time::timeout(
        UNIX_SILENT_CLIENT_CLOSE_TIMEOUT,
        stream.read_exact(&mut len_buf),
    )
    .await
    .expect("silent client connection should close after server I/O timeout")
    .expect_err("silent client unexpectedly received a response frame");
    assert_connection_closed_error(&err, "silent client connection close");

    server.shutdown().await;
}

#[tokio::test]
async fn request_json_rejects_oversized_request_before_connect() {
    let dir = tempdir().expect("tempdir");
    let missing_sock = dir.path().join("missing.sock");
    let req = KernelRequest::Remember {
        cap_b64: "invalid".into(),
        namespace: "unix".into(),
        name: "oversized".into(),
        body_b64: "A".repeat(mnemed::unix::UNIX_MAX_FRAME + 1),
    };

    let err = request_json(&missing_sock, &req)
        .await
        .expect_err("oversized request frame must fail before connect");

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(
        err.to_string()
            .contains("request frame length exceeds MAX_FRAME"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn request_json_rejects_oversized_response_frame() {
    let dir = tempdir().expect("tempdir");
    let sock = dir.path().join("oversized-response.sock");
    let listener = UnixListener::bind(&sock).expect("bind");
    let server = tokio::spawn(async move {
        let mut stream = accept_fake_unix_peer(listener, "oversized response peer").await?;
        let _req = read_fake_unix_request(&mut stream, "oversized response peer").await?;
        let oversized_len = ((mnemed::unix::UNIX_MAX_FRAME + 1) as u32).to_be_bytes();
        stream
            .write_all(&oversized_len)
            .await
            .map_err(|err| format!("oversized response peer response length write failed: {err}"))
    });

    let err = request_json(
        &sock,
        &KernelRequest::Head {
            cap_b64: "invalid".into(),
        },
    )
    .await
    .expect_err("oversized response frame must be rejected");

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
    let dir = tempdir().expect("tempdir");
    let sock = dir.path().join("stalled-response.sock");
    let listener = UnixListener::bind(&sock).expect("bind");
    let server = tokio::spawn(async move {
        let mut stream = accept_fake_unix_peer(listener, "stalled response peer").await?;
        let _req = read_fake_unix_request(&mut stream, "stalled response peer").await?;
        let mut extra = [0u8; 1];
        match tokio::time::timeout(
            FAKE_UNIX_PEER_CLIENT_CLOSE_TIMEOUT,
            stream.read_exact(&mut extra),
        )
        .await
        {
            Ok(Err(err)) => expect_connection_closed_error(&err, "stalled peer client close"),
            Ok(Ok(_)) => {
                Err("stalled response peer client unexpectedly wrote another frame".into())
            }
            Err(_) => {
                Err("stalled response peer did not observe client close before timeout".into())
            }
        }
    });

    let err = request_json_with_timeout(
        &sock,
        &KernelRequest::Head {
            cap_b64: "invalid".into(),
        },
        STALLED_RESPONSE_CLIENT_TIMEOUT,
    )
    .await
    .expect_err("stalled peer must trip the client timeout");

    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    assert!(
        err.to_string().contains("Unix kernel request timed out"),
        "unexpected error: {err}"
    );
    expect_fake_unix_peer(server, "stalled response peer").await;
}

#[tokio::test]
async fn request_json_zero_timeout_uses_default_deadline() {
    let dir = tempdir().expect("tempdir");
    let sock = dir.path().join("client-zero-timeout.sock");
    let listener = UnixListener::bind(&sock).expect("bind");
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

    tokio::time::timeout(ZERO_TIMEOUT_REQUEST_SEEN_TIMEOUT, request_seen_rx)
        .await
        .expect("server observes client request before timeout")
        .expect("server request seen signal");
    for _ in 0..3 {
        tokio::task::yield_now().await;
    }
    assert!(
        !client.is_finished(),
        "zero client timeout should normalize to the default deadline while response is withheld"
    );
    send_response_tx.send(()).expect("release response");

    let resp = tokio::time::timeout(ZERO_TIMEOUT_CLIENT_JOIN_TIMEOUT, client)
        .await
        .expect("client exits after released response")
        .expect("client task joins")
        .expect("zero timeout should fall back to default deadline");

    match resp {
        mnemed::unix::KernelResponse::Err { code, .. } => assert_eq!(code, "delayed"),
        mnemed::unix::KernelResponse::Ok { payload } => {
            panic!("invalid capability unexpectedly succeeded: {payload}")
        }
    }
    expect_fake_unix_peer(server, "zero-timeout response peer").await;
}

#[tokio::test]
async fn unix_server_zero_timeout_uses_default_deadline() {
    let dir = tempdir().expect("tempdir");
    let sock = dir.path().join("server-zero-timeout.sock");
    let (state, _operator, _agent) = test_state(dir.path()).expect("test_state");
    let server = spawn_unix_with_io_timeout(sock.clone(), state, Duration::ZERO).await;

    let mut stream = UnixStream::connect(&sock).await.expect("connect");
    for _ in 0..3 {
        tokio::task::yield_now().await;
    }
    write_raw_request(
        &mut stream,
        &KernelRequest::Head {
            cap_b64: "invalid".into(),
        },
    )
    .await
    .expect("delayed request write");
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .expect("response length");
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; resp_len];
    stream.read_exact(&mut buf).await.expect("response body");
    let resp: mnemed::unix::KernelResponse = serde_json::from_slice(&buf).expect("response json");

    match resp {
        mnemed::unix::KernelResponse::Err { code, .. } => assert_eq!(code, "CapDenied"),
        mnemed::unix::KernelResponse::Ok { payload } => {
            panic!("invalid capability unexpectedly succeeded: {payload}")
        }
    }

    server.shutdown().await;
}

#[tokio::test]
async fn unix_remember_and_head_roundtrip() {
    let dir = tempdir().expect("tempdir");
    let sock = dir.path().join("mneme.sock");
    let (state, operator, agent) = test_state(dir.path()).expect("test_state");
    let cap = agent_cap(&operator, agent.public_key_bytes()).expect("cap");
    let cap_b64 = cap_to_b64(&cap).expect("cap b64");
    {
        let mut store = state.store.lock().expect("lock");
        store.trust = store.trust.clone().with_writer(agent.public_key_bytes());
    }
    let server = spawn_unix(sock.clone(), state).await;

    let remember = request_json(
        &sock,
        &KernelRequest::Remember {
            cap_b64: cap_b64.clone(),
            namespace: "unix".into(),
            name: "key".into(),
            body_b64: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                b"payload",
            ),
        },
    )
    .await
    .expect("connect");
    match remember {
        mnemed::unix::KernelResponse::Ok { payload } => {
            assert!(payload.get("object_id").is_some());
        }
        mnemed::unix::KernelResponse::Err { message, .. } => panic!("remember failed: {message}"),
    }

    let head = request_json(
        &sock,
        &KernelRequest::Head {
            cap_b64: cap_b64.clone(),
        },
    )
    .await
    .expect("head");
    match head {
        mnemed::unix::KernelResponse::Ok { payload } => {
            assert_eq!(payload["sequence"].as_u64(), Some(2));
        }
        mnemed::unix::KernelResponse::Err { message, .. } => panic!("head failed: {message}"),
    }

    server.shutdown().await;
}

#[tokio::test]
async fn unix_head_rejects_malformed_decoded_capability_as_cap_denied() {
    let dir = tempdir().expect("tempdir");
    let sock = dir.path().join("malformed-head-cap.sock");
    let (state, _operator, _agent) = test_state(dir.path()).expect("test_state");
    let server = spawn_unix(sock.clone(), state).await;

    let resp = request_json(
        &sock,
        &KernelRequest::Head {
            cap_b64: "oA==".into(),
        },
    )
    .await
    .expect("head");
    assert_cap_denied(
        resp,
        "malformed decoded capability must fail as auth denial",
    );

    server.shutdown().await;
}

#[tokio::test]
async fn unix_head_rejects_oversized_capability_as_cap_denied() {
    let dir = tempdir().expect("tempdir");
    let sock = dir.path().join("oversized-head-cap.sock");
    let (state, _operator, _agent) = test_state(dir.path()).expect("test_state");
    let server = spawn_unix(sock.clone(), state).await;

    let resp = request_json(
        &sock,
        &KernelRequest::Head {
            cap_b64: "A".repeat(mnemed::state::MAX_CAPABILITY_B64_LEN + 1),
        },
    )
    .await
    .expect("head");
    assert_cap_denied(resp, "oversized capability must fail as auth denial");

    server.shutdown().await;
}

#[tokio::test]
async fn daemon_start_serves_configured_unix_socket() {
    let dir = tempdir().expect("tempdir");
    let sock = dir.path().join("daemon.sock");
    let (state, operator, agent) = test_state(dir.path()).expect("test_state");
    let cap = agent_cap(&operator, agent.public_key_bytes()).expect("cap");
    let cap_b64 = cap_to_b64(&cap).expect("cap b64");
    let server = start_with_state(
        ServerConfig {
            http_addr: "127.0.0.1:0".parse().expect("http addr"),
            grpc_addr: None,
            rate_limit_per_minute: 120,
            unix_socket: Some(sock.clone()),
        },
        state,
    )
    .await
    .expect("start daemon");

    wait_for_unix_socket_accepting(&sock).await;
    let head = request_json(&sock, &KernelRequest::Head { cap_b64 })
        .await
        .expect("unix head");
    match head {
        KernelResponse::Ok { payload } => assert_eq!(payload["sequence"].as_u64(), Some(1)),
        KernelResponse::Err { message, .. } => panic!("daemon unix head failed: {message}"),
    }

    server.shutdown().await;
    assert!(!sock.exists(), "daemon shutdown should remove Unix socket");
}

#[tokio::test]
async fn daemon_start_refuses_to_clobber_existing_non_socket_path() {
    let dir = tempdir().expect("tempdir");
    let sock = dir.path().join("occupied-daemon.sock");
    std::fs::write(&sock, b"preserve daemon path").expect("write occupied path");
    let (state, _operator, _agent) = test_state(dir.path()).expect("test_state");

    let result = start_with_state(
        ServerConfig {
            http_addr: "127.0.0.1:0".parse().expect("http addr"),
            grpc_addr: None,
            rate_limit_per_minute: 120,
            unix_socket: Some(sock.clone()),
        },
        state,
    )
    .await;
    let err = match result {
        Err(err) => err,
        Ok(server) => {
            server.shutdown().await;
            panic!("daemon unexpectedly started on occupied Unix socket path");
        }
    };

    match err {
        mneme_core::MnemeError::IoFailed { path, kind } => {
            assert_eq!(path, sock.display().to_string());
            assert!(
                kind.contains("not a socket"),
                "unexpected daemon Unix socket error: {kind}"
            );
        }
        other => panic!("expected daemon Unix socket I/O failure, got {other:?}"),
    }
    assert_eq!(
        std::fs::read(&sock).expect("occupied path still exists"),
        b"preserve daemon path"
    );
}

#[tokio::test]
async fn daemon_start_rejects_unbindable_unix_socket_path() {
    let dir = tempdir().expect("tempdir");
    let sock = dir.path().join("x".repeat(240));
    let (state, _operator, _agent) = test_state(dir.path()).expect("test_state");

    let result = start_with_state(
        ServerConfig {
            http_addr: "127.0.0.1:0".parse().expect("http addr"),
            grpc_addr: None,
            rate_limit_per_minute: 120,
            unix_socket: Some(sock.clone()),
        },
        state,
    )
    .await;
    let err = match result {
        Err(err) => err,
        Ok(server) => {
            server.shutdown().await;
            panic!("daemon unexpectedly started with an unbindable Unix socket path");
        }
    };

    match err {
        mneme_core::MnemeError::IoFailed { path, kind } => {
            assert_eq!(path, sock.display().to_string());
            assert!(
                kind.contains("too long")
                    || kind.contains("Invalid")
                    || kind.contains("invalid")
                    || kind.contains("exceeds")
                    || kind.contains("SUN_LEN"),
                "unexpected daemon Unix socket bind error: {kind}"
            );
        }
        other => panic!("expected daemon Unix socket I/O failure, got {other:?}"),
    }
    assert!(
        !sock.exists(),
        "unbindable Unix socket path should not leave a filesystem entry"
    );
}

#[tokio::test]
async fn unix_key_scoped_requests_reject_empty_logical_key() {
    let dir = tempdir().expect("tempdir");
    let sock = dir.path().join("blank-key.sock");
    let (state, operator, agent) = test_state(dir.path()).expect("test_state");
    let cap = agent_cap(&operator, agent.public_key_bytes()).expect("cap");
    let cap_b64 = cap_to_b64(&cap).expect("cap b64");
    {
        let mut store = state.store.lock().expect("lock");
        store.trust = store.trust.clone().with_writer(agent.public_key_bytes());
    }
    let server = spawn_unix(sock.clone(), state).await;

    let remember = request_json(
        &sock,
        &KernelRequest::Remember {
            cap_b64: cap_b64.clone(),
            namespace: "   ".into(),
            name: "note".into(),
            body_b64: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                b"invalid",
            ),
        },
    )
    .await
    .expect("remember request");
    assert_schema_drift(remember, "empty namespace must fail before remember");

    let recall = request_json(
        &sock,
        &KernelRequest::RecallVerified {
            cap_b64: cap_b64.clone(),
            namespace: "unix".into(),
            name: " ".into(),
        },
    )
    .await
    .expect("recall request");
    assert_schema_drift(recall, "empty name must fail before recall");

    let forget = request_json(
        &sock,
        &KernelRequest::Forget {
            cap_b64: cap_b64.clone(),
            namespace: "".into(),
            name: "note".into(),
            mode: "shred".into(),
        },
    )
    .await
    .expect("forget request");
    assert_schema_drift(forget, "empty namespace must fail before forget");

    let prove_absent = request_json(
        &sock,
        &KernelRequest::ProveAbsent {
            cap_b64,
            namespace: "unix".into(),
            name: "".into(),
        },
    )
    .await
    .expect("prove-absent request");
    assert_schema_drift(prove_absent, "empty name must fail before prove-absent");

    server.shutdown().await;
}

#[tokio::test]
async fn unix_sync_hello_returns_root_proof() {
    let dir = tempdir().expect("tempdir");
    let sock = dir.path().join("sync.sock");
    let (state, operator, agent) = test_state(dir.path()).expect("test_state");
    let cap = agent_cap(&operator, agent.public_key_bytes()).expect("cap");
    let cap_b64 = cap_to_b64(&cap).expect("cap b64");
    let server = spawn_unix(sock.clone(), state).await;

    let hello = SyncMessage::Hello {
        proto_ver: 1,
        node_id: NodeId([0x01; 16]),
        head_root: [0u8; 32],
        head_sig: vec![],
    };
    let wire = encode_sync_message(&hello).expect("encode");
    let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, wire);
    let resp = request_json(
        &sock,
        &KernelRequest::SyncFrame {
            cap_b64,
            bytes_b64: b64,
        },
    )
    .await
    .expect("sync");
    match resp {
        mnemed::unix::KernelResponse::Ok { payload } => {
            assert!(payload.get("sync_bytes_b64").is_some());
        }
        mnemed::unix::KernelResponse::Err { message, .. } => panic!("sync failed: {message}"),
    }
    server.shutdown().await;
}

#[tokio::test]
async fn unix_sync_frame_requires_capability() {
    let dir = tempdir().expect("tempdir");
    let sock = dir.path().join("sync-auth.sock");
    let (state, _operator, _agent) = test_state(dir.path()).expect("test_state");
    let server = spawn_unix(sock.clone(), state).await;

    let hello = SyncMessage::Hello {
        proto_ver: 1,
        node_id: NodeId([0x01; 16]),
        head_root: [0u8; 32],
        head_sig: vec![],
    };
    let wire = encode_sync_message(&hello).expect("encode");
    let bytes_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, wire);
    let resp = request_json(
        &sock,
        &KernelRequest::SyncFrame {
            cap_b64: "not-valid".into(),
            bytes_b64,
        },
    )
    .await
    .expect("sync");
    match resp {
        mnemed::unix::KernelResponse::Err { code, .. } => assert_eq!(code, "CapDenied"),
        mnemed::unix::KernelResponse::Ok { payload } => {
            panic!("unauthorized sync frame returned payload: {payload}")
        }
    }
    server.shutdown().await;
}

#[tokio::test]
async fn unix_sync_frame_rejects_malformed_decoded_capability_as_cap_denied() {
    let dir = tempdir().expect("tempdir");
    let sock = dir.path().join("malformed-sync-cap.sock");
    let (state, _operator, _agent) = test_state(dir.path()).expect("test_state");
    let server = spawn_unix(sock.clone(), state).await;

    let hello = SyncMessage::Hello {
        proto_ver: 1,
        node_id: NodeId([0x01; 16]),
        head_root: [0u8; 32],
        head_sig: vec![],
    };
    let wire = encode_sync_message(&hello).expect("encode");
    let bytes_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, wire);
    let resp = request_json(
        &sock,
        &KernelRequest::SyncFrame {
            cap_b64: "oA==".into(),
            bytes_b64,
        },
    )
    .await
    .expect("sync");
    assert_cap_denied(
        resp,
        "malformed decoded sync capability must fail as auth denial",
    );

    server.shutdown().await;
}

#[tokio::test]
async fn unix_sync_frame_rejects_oversized_capability_as_cap_denied() {
    let dir = tempdir().expect("tempdir");
    let sock = dir.path().join("oversized-sync-cap.sock");
    let (state, _operator, _agent) = test_state(dir.path()).expect("test_state");
    let server = spawn_unix(sock.clone(), state).await;

    let hello = SyncMessage::Hello {
        proto_ver: 1,
        node_id: NodeId([0x01; 16]),
        head_root: [0u8; 32],
        head_sig: vec![],
    };
    let wire = encode_sync_message(&hello).expect("encode");
    let bytes_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, wire);
    let resp = request_json(
        &sock,
        &KernelRequest::SyncFrame {
            cap_b64: "A".repeat(mnemed::state::MAX_CAPABILITY_B64_LEN + 1),
            bytes_b64,
        },
    )
    .await
    .expect("sync");
    assert_cap_denied(resp, "oversized sync capability must fail as auth denial");

    server.shutdown().await;
}

#[tokio::test]
async fn unix_prove_absent_requires_capability() {
    let dir = tempdir().expect("tempdir");
    let sock = dir.path().join("absent-auth.sock");
    let (state, _operator, _agent) = test_state(dir.path()).expect("test_state");
    let server = spawn_unix(sock.clone(), state).await;

    let resp = request_json(
        &sock,
        &KernelRequest::ProveAbsent {
            cap_b64: "not-valid".into(),
            namespace: "user".into(),
            name: "never-seen".into(),
        },
    )
    .await
    .expect("prove absent");
    match resp {
        mnemed::unix::KernelResponse::Err { code, .. } => assert_eq!(code, "CapDenied"),
        mnemed::unix::KernelResponse::Ok { payload } => {
            panic!("unauthorized prove-absent returned payload: {payload}")
        }
    }
    server.shutdown().await;
}
