//! Unix domain socket kernel API + §11 sync frames (local-first).

use crate::state::{AppState, capability_from_header};
use base64::Engine;
use mneme_core::{
    Draft, ForgetMode, ForgetTarget, LogicalKey, MemoryKind, MnemeError, Query, Root, SyncMessage,
    TrustTier, encode_forget_proof,
};
use mneme_crdt::{decode_sync_message, encode_sync_message};
use mneme_store::Store;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::MutexGuard;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;
use tokio::task::JoinSet;

pub const UNIX_MAX_FRAME: usize = 4 * 1024 * 1024;

#[cfg(unix)]
fn verify_unix_peer_credentials(stream: &UnixStream) -> Result<(), std::io::Error> {
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd"
    ))]
    {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        let ret = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if uid != unsafe { libc::getuid() } {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "unix peer uid mismatch",
            ));
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if cred.uid != unsafe { libc::getuid() } {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "unix peer uid mismatch",
            ));
        }
        Ok(())
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd"
    )))]
    {
        let _ = stream;
        Ok(())
    }
}
const DEFAULT_CONNECTION_IO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum KernelRequest {
    Head {
        cap_b64: String,
    },
    Remember {
        cap_b64: String,
        namespace: String,
        name: String,
        body_b64: String,
    },
    RecallVerified {
        cap_b64: String,
        namespace: String,
        name: String,
        #[serde(default)]
        prompt: Option<String>,
        #[serde(default)]
        weight_measurement_hex: Option<String>,
        #[serde(default)]
        sampling_params: Option<String>,
        #[serde(default)]
        output_token_commit_hex: Option<String>,
    },
    Forget {
        cap_b64: String,
        namespace: String,
        name: String,
        mode: String,
        #[serde(default)]
        emit_proof: Option<bool>,
    },
    ForgetProof {
        cap_b64: String,
        namespace: String,
        name: String,
    },
    ProveAbsent {
        cap_b64: String,
        namespace: String,
        name: String,
    },
    SyncFrame {
        cap_b64: String,
        bytes_b64: String,
    },
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum KernelResponse {
    Ok { payload: serde_json::Value },
    Err { code: String, message: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KernelErrWriteOutcome {
    Sent,
    PeerUnavailable,
    TimedOut,
    Failed(std::io::ErrorKind),
}

type TimedUnixReadExact = Result<Result<usize, std::io::Error>, tokio::time::error::Elapsed>;
type TimedUnixWriteAll = Result<Result<(), std::io::Error>, tokio::time::error::Elapsed>;
type TimedUnixConnect = Result<Result<UnixStream, std::io::Error>, tokio::time::error::Elapsed>;

enum UnixReadExactOutcome {
    Read,
    Failed(std::io::Error),
    TimedOut,
}

enum UnixConnectOutcome {
    Connected(UnixStream),
    Failed(std::io::Error),
    TimedOut,
}

enum UnixWriteAllOutcome {
    Written,
    Failed(std::io::Error),
    TimedOut,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum UnixKernelFailure {
    InvalidLogicalKey,
    BodyBase64Decode,
    SyncFrameBase64Decode,
    SyncFrameDecode(MnemeError),
    StoreUnavailable(&'static str),
}

pub struct UnixServer {
    path: PathBuf,
    state: AppState,
    io_timeout: Duration,
}

pub(crate) struct BoundUnixServer {
    path: PathBuf,
    state: AppState,
    io_timeout: Duration,
    listener: UnixListener,
}

impl UnixServer {
    pub fn new(path: PathBuf, state: AppState) -> Self {
        Self {
            path,
            state,
            io_timeout: DEFAULT_CONNECTION_IO_TIMEOUT,
        }
    }

    pub fn with_io_timeout(mut self, io_timeout: Duration) -> Self {
        self.io_timeout = normalize_io_timeout(io_timeout);
        self
    }

    pub async fn serve(self) -> Result<(), std::io::Error> {
        self.bind()?.serve_inner(None).await
    }

    pub async fn serve_until_shutdown(
        self,
        shutdown_rx: watch::Receiver<()>,
    ) -> Result<(), std::io::Error> {
        self.bind()?.serve_inner(Some(shutdown_rx)).await
    }

    pub(crate) fn bind(self) -> Result<BoundUnixServer, std::io::Error> {
        prepare_socket_path(&self.path)?;
        let listener = UnixListener::bind(&self.path)?;
        std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))?;
        Ok(BoundUnixServer {
            path: self.path,
            state: self.state,
            io_timeout: self.io_timeout,
            listener,
        })
    }
}

impl BoundUnixServer {
    pub(crate) async fn serve_until_shutdown(
        self,
        shutdown_rx: watch::Receiver<()>,
    ) -> Result<(), std::io::Error> {
        self.serve_inner(Some(shutdown_rx)).await
    }

    async fn serve_inner(
        self,
        shutdown_rx: Option<watch::Receiver<()>>,
    ) -> Result<(), std::io::Error> {
        let Self {
            path,
            state,
            io_timeout,
            listener,
        } = self;
        let mut connections = JoinSet::new();
        let result = match shutdown_rx {
            Some(mut shutdown_rx) => loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        break Ok(());
                    }
                    accepted = listener.accept() => {
                        let (stream, _) = accepted?;
                        if let Err(e) = verify_unix_peer_credentials(&stream) {
                            tracing::debug!("unix peer credential check failed: {e}");
                            continue;
                        }
                        spawn_connection(
                            &mut connections,
                            stream,
                            state.clone(),
                            io_timeout,
                        );
                    }
                    joined = connections.join_next(), if !connections.is_empty() => {
                        if let Err(e) = observe_connection_result(joined) {
                            break Err(e);
                        }
                    }
                }
            },
            None => loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (stream, _) = accepted?;
                        if let Err(e) = verify_unix_peer_credentials(&stream) {
                            tracing::debug!("unix peer credential check failed: {e}");
                            continue;
                        }
                        spawn_connection(
                            &mut connections,
                            stream,
                            state.clone(),
                            io_timeout,
                        );
                    }
                    joined = connections.join_next(), if !connections.is_empty() => {
                        if let Err(e) = observe_connection_result(joined) {
                            break Err(e);
                        }
                    }
                }
            },
        };

        let cleanup_result = close_connections(connections).await;
        if result.is_ok() {
            remove_socket_path(&path)?;
        }
        result.and(cleanup_result)
    }
}

pub(crate) fn prepare_socket_path(path: &Path) -> Result<(), std::io::Error> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_socket() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!(
                        "Unix kernel socket path already exists and is not a socket: {}",
                        path.display()
                    ),
                ));
            }
            remove_socket_path(path)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn remove_socket_path(path: &Path) -> Result<(), std::io::Error> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn spawn_connection(
    connections: &mut JoinSet<Result<(), std::io::Error>>,
    stream: UnixStream,
    state: AppState,
    io_timeout: Duration,
) {
    connections.spawn(async move { handle_connection(stream, state, io_timeout).await });
}

fn observe_connection_result(
    joined: Option<Result<Result<(), std::io::Error>, tokio::task::JoinError>>,
) -> Result<(), std::io::Error> {
    match joined {
        None | Some(Ok(Ok(()))) => Ok(()),
        Some(Ok(Err(e))) => {
            tracing::debug!("unix kernel connection ended with I/O error: {e}");
            Ok(())
        }
        Some(Err(e)) if e.is_cancelled() => Ok(()),
        Some(Err(e)) if e.is_panic() => Err(std::io::Error::other(format!(
            "unix kernel connection task panicked: {e}"
        ))),
        Some(Err(e)) => Err(std::io::Error::other(format!(
            "unix kernel connection task join failed: {e}"
        ))),
    }
}

async fn close_connections(
    mut connections: JoinSet<Result<(), std::io::Error>>,
) -> Result<(), std::io::Error> {
    connections.abort_all();
    let mut first_error = None;
    while let Some(joined) = connections.join_next().await {
        if let Err(e) = observe_connection_result(Some(joined)) {
            first_error.get_or_insert(e);
        }
    }
    if let Some(e) = first_error {
        Err(e)
    } else {
        Ok(())
    }
}

pub async fn request_json(
    path: &PathBuf,
    req: &KernelRequest,
) -> Result<KernelResponse, std::io::Error> {
    request_json_with_timeout(path, req, DEFAULT_CONNECTION_IO_TIMEOUT).await
}

pub async fn request_json_with_timeout(
    path: &PathBuf,
    req: &KernelRequest,
    io_timeout: Duration,
) -> Result<KernelResponse, std::io::Error> {
    let io_timeout = normalize_io_timeout(io_timeout);
    let frame = serde_json::to_vec(req).map_err(std::io::Error::other)?;
    if frame.len() > UNIX_MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "request frame length exceeds MAX_FRAME on Unix kernel API",
        ));
    }

    let mut stream = connect_unix_stream_with_timeout(path, io_timeout).await?;
    let len = (frame.len() as u32).to_be_bytes();
    write_all_with_timeout(&mut stream, &len, io_timeout, request_timeout_error).await?;
    write_all_with_timeout(&mut stream, &frame, io_timeout, request_timeout_error).await?;
    let mut len_buf = [0u8; 4];
    read_exact_with_timeout(&mut stream, &mut len_buf, io_timeout, request_timeout_error).await?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    if resp_len > UNIX_MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "response frame length exceeds MAX_FRAME on Unix kernel API",
        ));
    }
    let mut buf = vec![0u8; resp_len];
    read_exact_with_timeout(&mut stream, &mut buf, io_timeout, request_timeout_error).await?;
    serde_json::from_slice(&buf).map_err(std::io::Error::other)
}

async fn connect_unix_stream_with_timeout(
    path: &PathBuf,
    io_timeout: Duration,
) -> Result<UnixStream, std::io::Error> {
    match classify_unix_connect(tokio::time::timeout(io_timeout, UnixStream::connect(path)).await) {
        UnixConnectOutcome::Connected(stream) => Ok(stream),
        UnixConnectOutcome::Failed(e) => Err(e),
        UnixConnectOutcome::TimedOut => Err(request_timeout_error()),
    }
}

fn classify_unix_connect(connect_result: TimedUnixConnect) -> UnixConnectOutcome {
    match connect_result {
        Ok(Ok(stream)) => UnixConnectOutcome::Connected(stream),
        Ok(Err(e)) => UnixConnectOutcome::Failed(e),
        Err(_) => UnixConnectOutcome::TimedOut,
    }
}

fn normalize_io_timeout(io_timeout: Duration) -> Duration {
    if io_timeout.is_zero() {
        DEFAULT_CONNECTION_IO_TIMEOUT
    } else {
        io_timeout
    }
}

fn request_timeout_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "Unix kernel request timed out",
    )
}

async fn write_kernel_err(
    stream: &mut UnixStream,
    code: &str,
    message: &str,
    io_timeout: Duration,
) -> Result<(), std::io::Error> {
    let resp = KernelResponse::Err {
        code: code.into(),
        message: message.into(),
    };
    let out = encode_kernel_response(&resp)?;
    let frame_len = (out.len() as u32).to_be_bytes();
    write_all_with_timeout(
        stream,
        &frame_len,
        io_timeout,
        connection_write_timeout_error,
    )
    .await?;
    write_all_with_timeout(stream, &out, io_timeout, connection_write_timeout_error).await?;
    Ok(())
}

fn encode_kernel_response(resp: &KernelResponse) -> Result<Vec<u8>, std::io::Error> {
    serde_json::to_vec(resp).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Unix kernel response serialization failed: {e}"),
        )
    })
}

fn classify_kernel_err_write_result(result: Result<(), std::io::Error>) -> KernelErrWriteOutcome {
    match result {
        Ok(()) => KernelErrWriteOutcome::Sent,
        Err(e) => match e.kind() {
            std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::UnexpectedEof => KernelErrWriteOutcome::PeerUnavailable,
            std::io::ErrorKind::TimedOut => KernelErrWriteOutcome::TimedOut,
            kind => KernelErrWriteOutcome::Failed(kind),
        },
    }
}

async fn write_framing_error_response(
    stream: &mut UnixStream,
    message: &str,
    io_timeout: Duration,
) -> KernelErrWriteOutcome {
    classify_kernel_err_write_result(write_kernel_err(stream, "framing", message, io_timeout).await)
}

fn observe_framing_error_write(outcome: KernelErrWriteOutcome, context: &str) {
    match outcome {
        KernelErrWriteOutcome::Sent => {}
        KernelErrWriteOutcome::PeerUnavailable => {
            tracing::debug!(
                "unix kernel framing error response not delivered; peer unavailable: {context}"
            );
        }
        KernelErrWriteOutcome::TimedOut => {
            tracing::debug!("unix kernel framing error response timed out: {context}");
        }
        KernelErrWriteOutcome::Failed(kind) => {
            tracing::debug!(
                "unix kernel framing error response write failed with {kind:?}: {context}"
            );
        }
    }
}

async fn read_exact_with_timeout(
    stream: &mut UnixStream,
    buf: &mut [u8],
    io_timeout: Duration,
    timeout_error: fn() -> std::io::Error,
) -> Result<(), std::io::Error> {
    match classify_unix_read_exact(tokio::time::timeout(io_timeout, stream.read_exact(buf)).await) {
        UnixReadExactOutcome::Read => Ok(()),
        UnixReadExactOutcome::Failed(e) => Err(e),
        UnixReadExactOutcome::TimedOut => Err(timeout_error()),
    }
}

fn classify_unix_read_exact(read_result: TimedUnixReadExact) -> UnixReadExactOutcome {
    match read_result {
        Ok(Ok(_)) => UnixReadExactOutcome::Read,
        Ok(Err(e)) => UnixReadExactOutcome::Failed(e),
        Err(_) => UnixReadExactOutcome::TimedOut,
    }
}

async fn write_all_with_timeout(
    stream: &mut UnixStream,
    buf: &[u8],
    io_timeout: Duration,
    timeout_error: fn() -> std::io::Error,
) -> Result<(), std::io::Error> {
    match classify_unix_write_all(tokio::time::timeout(io_timeout, stream.write_all(buf)).await) {
        UnixWriteAllOutcome::Written => Ok(()),
        UnixWriteAllOutcome::Failed(e) => Err(e),
        UnixWriteAllOutcome::TimedOut => Err(timeout_error()),
    }
}

fn classify_unix_write_all(write_result: TimedUnixWriteAll) -> UnixWriteAllOutcome {
    match write_result {
        Ok(Ok(())) => UnixWriteAllOutcome::Written,
        Ok(Err(e)) => UnixWriteAllOutcome::Failed(e),
        Err(_) => UnixWriteAllOutcome::TimedOut,
    }
}

fn connection_read_timeout_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "Unix kernel connection read timed out",
    )
}

fn connection_write_timeout_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "Unix kernel connection write timed out",
    )
}

async fn handle_connection(
    mut stream: UnixStream,
    state: AppState,
    io_timeout: Duration,
) -> Result<(), std::io::Error> {
    let mut len_buf = [0u8; 4];
    if let Err(e) = read_exact_with_timeout(
        &mut stream,
        &mut len_buf,
        io_timeout,
        connection_read_timeout_error,
    )
    .await
    {
        if e.kind() == std::io::ErrorKind::TimedOut {
            return Ok(());
        }
        let outcome = write_framing_error_response(
            &mut stream,
            "incomplete length header on Unix kernel frame",
            io_timeout,
        )
        .await;
        observe_framing_error_write(outcome, "incomplete length header");
        return Ok(());
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > UNIX_MAX_FRAME {
        let outcome = write_framing_error_response(
            &mut stream,
            "frame length exceeds MAX_FRAME on Unix kernel API",
            io_timeout,
        )
        .await;
        observe_framing_error_write(outcome, "frame length exceeds MAX_FRAME");
        return Ok(());
    }
    let mut buf = vec![0u8; len];
    read_exact_with_timeout(
        &mut stream,
        &mut buf,
        io_timeout,
        connection_read_timeout_error,
    )
    .await?;
    let resp = dispatch(&state, &buf);
    let out = encode_kernel_response(&resp)?;
    let frame_len = (out.len() as u32).to_be_bytes();
    write_all_with_timeout(
        &mut stream,
        &frame_len,
        io_timeout,
        connection_write_timeout_error,
    )
    .await?;
    write_all_with_timeout(
        &mut stream,
        &out,
        io_timeout,
        connection_write_timeout_error,
    )
    .await?;
    Ok(())
}

fn dispatch(state: &AppState, frame: &[u8]) -> KernelResponse {
    let req: KernelRequest = match serde_json::from_slice(frame) {
        Ok(r) => r,
        Err(e) => {
            return KernelResponse::Err {
                code: "usage".into(),
                message: e.to_string(),
            };
        }
    };
    match dispatch_inner(state, req) {
        Ok(v) => KernelResponse::Ok { payload: v },
        Err(e) => KernelResponse::Err {
            code: format!("{e:?}"),
            message: e.to_string(),
        },
    }
}

fn dispatch_inner(state: &AppState, req: KernelRequest) -> Result<serde_json::Value, MnemeError> {
    match req {
        KernelRequest::Head { cap_b64 } => head(state, &cap_b64),
        KernelRequest::Remember {
            cap_b64,
            namespace,
            name,
            body_b64,
        } => remember(state, &cap_b64, namespace, name, body_b64),
        KernelRequest::RecallVerified {
            cap_b64,
            namespace,
            name,
            prompt,
            weight_measurement_hex,
            sampling_params,
            output_token_commit_hex,
        } => recall(
            state,
            &cap_b64,
            namespace,
            name,
            RobrRecallParams {
                prompt,
                weight_measurement_hex,
                sampling_params,
                output_token_commit_hex,
            },
        ),
        KernelRequest::Forget {
            cap_b64,
            namespace,
            name,
            mode,
            emit_proof,
        } => forget(state, &cap_b64, namespace, name, mode, emit_proof),
        KernelRequest::ForgetProof {
            cap_b64,
            namespace,
            name,
        } => forget_proof(state, &cap_b64, namespace, name),
        KernelRequest::ProveAbsent {
            cap_b64,
            namespace,
            name,
        } => prove_absent(state, &cap_b64, namespace, name),
        KernelRequest::SyncFrame { cap_b64, bytes_b64 } => sync_frame(state, &cap_b64, bytes_b64),
    }
}

fn cap_from_b64(b64: &str) -> Result<mneme_cap::Capability, MnemeError> {
    capability_from_header(b64).map_err(|_| MnemeError::CapDenied)
}

fn unix_kernel_failure_to_mneme(failure: UnixKernelFailure) -> MnemeError {
    match failure {
        UnixKernelFailure::InvalidLogicalKey
        | UnixKernelFailure::BodyBase64Decode
        | UnixKernelFailure::SyncFrameBase64Decode => MnemeError::SchemaDrift,
        UnixKernelFailure::SyncFrameDecode(err) => err,
        UnixKernelFailure::StoreUnavailable(context) => MnemeError::IoFailed {
            path: format!("unix kernel {context} store"),
            kind: "store lock poisoned".into(),
        },
    }
}

fn invalid_logical_key_error() -> MnemeError {
    unix_kernel_failure_to_mneme(UnixKernelFailure::InvalidLogicalKey)
}

fn decode_unix_body_b64(body_b64: &str) -> Result<Vec<u8>, MnemeError> {
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, body_b64.trim())
        .map_err(|_| unix_kernel_failure_to_mneme(UnixKernelFailure::BodyBase64Decode))
}

fn decode_unix_hex32(hex_str: &str) -> Result<[u8; 32], MnemeError> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(hex_str, &mut out)
        .map_err(|_| unix_kernel_failure_to_mneme(UnixKernelFailure::BodyBase64Decode))?;
    Ok(out)
}

fn decode_unix_sync_frame_b64(bytes_b64: &str) -> Result<SyncMessage, MnemeError> {
    let bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, bytes_b64.trim())
            .map_err(|_| unix_kernel_failure_to_mneme(UnixKernelFailure::SyncFrameBase64Decode))?;
    decode_sync_message(&bytes)
        .map_err(|err| unix_kernel_failure_to_mneme(UnixKernelFailure::SyncFrameDecode(err)))
}

fn lock_unix_store<'a>(
    state: &'a AppState,
    context: &'static str,
) -> Result<MutexGuard<'a, Store>, MnemeError> {
    state
        .store
        .lock()
        .map_err(|_| unix_kernel_failure_to_mneme(UnixKernelFailure::StoreUnavailable(context)))
}

fn validate_logical_key(namespace: &str, name: &str) -> Result<(), MnemeError> {
    if namespace.trim().is_empty() || name.trim().is_empty() {
        return Err(invalid_logical_key_error());
    }
    Ok(())
}

fn head(state: &AppState, cap_b64: &str) -> Result<serde_json::Value, MnemeError> {
    let cap = cap_from_b64(cap_b64)?;
    let store = lock_unix_store(state, "head")?;
    cap.verify(state.operator.as_ref(), store.current_hlc())?;
    let root = store.current_root()?;
    Ok(serde_json::json!({
        "preimage_hash": hex::encode(root.preimage_hash),
        "sequence": root.sequence,
    }))
}

fn remember(
    state: &AppState,
    cap_b64: &str,
    namespace: String,
    name: String,
    body_b64: String,
) -> Result<serde_json::Value, MnemeError> {
    let cap = cap_from_b64(cap_b64)?;
    validate_logical_key(&namespace, &name)?;
    let body = decode_unix_body_b64(&body_b64)?;
    let mut store = lock_unix_store(state, "remember")?;
    let draft = Draft {
        namespace,
        logical_name: name,
        kind: MemoryKind::Episodic,
        body,
        parent_ids: vec![],
        session: [0xab; 16],
        trust_tier: None,
        embedding: None,
        valid_time_ms: None,
    };
    let (id, root) = store.remember(draft, &cap)?;
    Ok(serde_json::json!({
        "object_id": hex::encode(id.as_bytes()),
        "root": hex::encode(root.preimage_hash),
    }))
}

/// Optional ROBR-1 binding-receipt inputs carried on a recall request. When all four
/// are present, the recall emits a signed receipt bound to the verified context.
#[derive(Default)]
struct RobrRecallParams {
    prompt: Option<String>,
    weight_measurement_hex: Option<String>,
    sampling_params: Option<String>,
    output_token_commit_hex: Option<String>,
}

fn recall(
    state: &AppState,
    cap_b64: &str,
    namespace: String,
    name: String,
    robr: RobrRecallParams,
) -> Result<serde_json::Value, MnemeError> {
    let cap = cap_from_b64(cap_b64)?;
    validate_logical_key(&namespace, &name)?;
    let store = lock_unix_store(state, "recall")?;
    let query = Query {
        logical_key: LogicalKey { namespace, name },
        min_tier: TrustTier::Working,
        embedding: None,
    };
    let entries = store.recall_verified_default(&query, &cap)?;

    let mut robr_receipt_b64 = None;
    if let (Some(prompt), Some(weight_hex), Some(sampling), Some(output_hex)) = (
        &robr.prompt,
        &robr.weight_measurement_hex,
        &robr.sampling_params,
        &robr.output_token_commit_hex,
    ) {
        let weight = decode_unix_hex32(weight_hex)?;
        let output_commit = decode_unix_hex32(output_hex)?;

        let mut context_entries = Vec::new();
        for e in &entries {
            context_entries.push((e.id.0, e.plaintext.clone()));
        }
        let receipt_wire = store.create_robr_receipt(
            prompt,
            weight,
            sampling.clone(),
            &context_entries,
            output_commit,
        )?;
        use base64::Engine as _;
        robr_receipt_b64 = Some(base64::engine::general_purpose::STANDARD.encode(receipt_wire));
    }

    Ok(serde_json::json!({
        "count": entries.len(),
        "robr_receipt_b64": robr_receipt_b64,
    }))
}

fn forget(
    state: &AppState,
    cap_b64: &str,
    namespace: String,
    name: String,
    mode: String,
    emit_proof: Option<bool>,
) -> Result<serde_json::Value, MnemeError> {
    let cap = cap_from_b64(cap_b64)?;
    validate_logical_key(&namespace, &name)?;
    let forget_mode = if mode == "redact" {
        ForgetMode::Redact
    } else {
        ForgetMode::Shred
    };
    let mut store = lock_unix_store(state, "forget")?;
    let key = LogicalKey { namespace, name };

    let mut proof_cbor_b64 = None;
    let root = if emit_proof.unwrap_or(false) {
        let proven =
            store.forget_with_proof(ForgetTarget::LogicalKey(key), &cap, forget_mode, None)?;
        let proof_bytes = encode_forget_proof(&proven.proof)?;
        use base64::Engine as _;
        proof_cbor_b64 = Some(base64::engine::general_purpose::STANDARD.encode(proof_bytes));
        proven.root
    } else {
        let (_tomb, root) = store.forget(ForgetTarget::LogicalKey(key), &cap, forget_mode)?;
        root
    };

    Ok(serde_json::json!({
        "forgot": true,
        "root_hash_hex": hex::encode(root.preimage_hash),
        "proof_cbor_b64": proof_cbor_b64,
    }))
}

fn forget_proof(
    state: &AppState,
    cap_b64: &str,
    namespace: String,
    name: String,
) -> Result<serde_json::Value, MnemeError> {
    let cap = cap_from_b64(cap_b64)?;
    validate_logical_key(&namespace, &name)?;
    let mut store = lock_unix_store(state, "forget_proof")?;
    let key = LogicalKey { namespace, name };
    let proven =
        store.forget_with_proof(ForgetTarget::LogicalKey(key), &cap, ForgetMode::Shred, None)?;
    let proof_bytes = encode_forget_proof(&proven.proof)?;
    Ok(serde_json::json!({
        "root_hash_hex": hex::encode(proven.root.preimage_hash),
        "proof_version": proven.proof.version,
        "proof_cbor_b64": base64::engine::general_purpose::STANDARD.encode(proof_bytes),
        "root": signed_root_json(&proven.root),
    }))
}

fn prove_absent(
    state: &AppState,
    cap_b64: &str,
    namespace: String,
    name: String,
) -> Result<serde_json::Value, MnemeError> {
    let cap = cap_from_b64(cap_b64)?;
    validate_logical_key(&namespace, &name)?;
    if !cap.permits_read(&namespace, TrustTier::Quarantine) {
        return Err(MnemeError::CapDenied);
    }
    let store = lock_unix_store(state, "prove_absent")?;
    cap.verify(state.operator.as_ref(), store.current_hlc())?;
    let key = LogicalKey { namespace, name };
    let proof = store.prove_absent(&key)?;
    let proof_bytes = mneme_smt::encode_non_membership_wire(&proof);
    Ok(serde_json::json!({
        "absent": true,
        "absence_proof_b64": base64::engine::general_purpose::STANDARD.encode(proof_bytes),
    }))
}

fn signed_root_json(root: &Root) -> serde_json::Value {
    serde_json::json!({
        "version": root.version,
        "preimage_hash_hex": hex::encode(root.preimage_hash),
        "dag_head_root_hex": hex::encode(root.dag_head_root),
        "key_index_root_hex": hex::encode(root.key_index_root),
        "semantic_commit_hex": hex::encode(root.semantic_commit),
        "hlc_max_hex": hex::encode(root.hlc_max),
        "prev_root_hex": hex::encode(root.prev_root),
        "signature_hex": hex::encode(&root.signature),
        "sequence": root.sequence,
    })
}

fn sync_frame(
    state: &AppState,
    cap_b64: &str,
    bytes_b64: String,
) -> Result<serde_json::Value, MnemeError> {
    use base64::Engine;
    let cap = cap_from_b64(cap_b64)?;
    if !cap.permits_read("sync", TrustTier::Quarantine) {
        return Err(MnemeError::CapDenied);
    }
    let msg = decode_unix_sync_frame_b64(&bytes_b64)?;
    let store = lock_unix_store(state, "sync_frame")?;
    cap.verify(state.operator.as_ref(), store.current_hlc())?;
    let out = match msg {
        SyncMessage::Hello { .. } => {
            let root = store.current_root()?;
            encode_sync_message(&SyncMessage::RootProof {
                root,
                consistency_proof: None,
            })?
        }
        SyncMessage::HaveObjects { .. } => {
            let root = store.current_root()?;
            encode_sync_message(&SyncMessage::RootProof {
                root,
                consistency_proof: None,
            })?
        }
        SyncMessage::Bye => encode_sync_message(&SyncMessage::Bye)?,
        other => encode_sync_message(&other)?,
    };
    Ok(serde_json::json!({
        "sync_bytes_b64": base64::engine::general_purpose::STANDARD.encode(out)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    type UnixConnectionJoin = Option<Result<Result<(), std::io::Error>, tokio::task::JoinError>>;

    fn panic_connection_task_boom() {
        panic!("connection task boom");
    }

    fn expect_unix_connection_result_error(
        joined: UnixConnectionJoin,
        context: &str,
    ) -> std::io::Error {
        match observe_connection_result(joined) {
            Ok(()) => panic!("{context}: expected Unix connection result failure"),
            Err(err) => err,
        }
    }

    fn expect_unix_connection_result_success(joined: UnixConnectionJoin, context: &str) {
        observe_connection_result(joined).unwrap_or_else(|err| {
            panic!("{context}: Unix connection result unexpectedly failed: {err}")
        });
    }

    fn expect_encoded_kernel_response(resp: &KernelResponse, context: &str) -> Vec<u8> {
        encode_kernel_response(resp)
            .unwrap_or_else(|err| panic!("{context}: Unix kernel response encoding failed: {err}"))
    }

    fn expect_kernel_response_text(encoded: &[u8], context: &str) -> String {
        std::str::from_utf8(encoded)
            .unwrap_or_else(|err| {
                panic!("{context}: Unix kernel response UTF-8 decode failed: {err}")
            })
            .to_owned()
    }

    #[tokio::test]
    async fn connection_task_panic_surfaces_as_server_error() {
        let mut connections: JoinSet<Result<(), std::io::Error>> = JoinSet::new();
        connections.spawn(async {
            panic_connection_task_boom();
            Ok::<(), std::io::Error>(())
        });

        let err =
            expect_unix_connection_result_error(connections.join_next().await, "connection panic");

        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        assert!(
            err.to_string().contains("connection task panicked"),
            "unexpected panic error: {err}"
        );
    }

    #[test]
    fn connection_io_error_is_observed_not_server_fatal() {
        expect_unix_connection_result_success(
            Some(Ok(Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "client closed",
            )))),
            "per-connection I/O error",
        );
    }

    #[test]
    fn kernel_error_write_classifier_distinguishes_success() {
        assert_eq!(
            classify_kernel_err_write_result(Ok(())),
            KernelErrWriteOutcome::Sent
        );
    }

    #[test]
    fn kernel_error_write_classifier_distinguishes_peer_unavailable() {
        assert_eq!(
            classify_kernel_err_write_result(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "peer closed",
            ))),
            KernelErrWriteOutcome::PeerUnavailable
        );
    }

    #[test]
    fn kernel_error_write_classifier_distinguishes_timeout() {
        assert_eq!(
            classify_kernel_err_write_result(Err(connection_write_timeout_error())),
            KernelErrWriteOutcome::TimedOut
        );
    }

    #[test]
    fn kernel_error_write_classifier_preserves_unexpected_error_kind() {
        assert_eq!(
            classify_kernel_err_write_result(Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "permission denied",
            ))),
            KernelErrWriteOutcome::Failed(std::io::ErrorKind::PermissionDenied)
        );
    }

    #[test]
    fn kernel_response_encoder_preserves_error_response_payload() {
        let encoded = expect_encoded_kernel_response(
            &KernelResponse::Err {
                code: "framing".into(),
                message: "bad frame".into(),
            },
            "kernel error response",
        );

        assert!(
            !encoded.is_empty(),
            "encoded kernel error response must not be empty"
        );
        assert!(
            expect_kernel_response_text(&encoded, "kernel error response").contains("framing"),
            "encoded response should preserve the error code"
        );
    }

    #[test]
    fn kernel_response_encoder_preserves_ok_response_payload() {
        let encoded = expect_encoded_kernel_response(
            &KernelResponse::Ok {
                payload: serde_json::json!({ "sequence": 7 }),
            },
            "kernel ok response",
        );

        assert!(
            !encoded.is_empty(),
            "encoded kernel ok response must not be empty"
        );
        assert!(
            expect_kernel_response_text(&encoded, "kernel ok response").contains("sequence"),
            "encoded response should preserve the payload"
        );
    }

    #[tokio::test]
    async fn aborted_connection_during_shutdown_is_not_server_fatal() {
        let mut connections: JoinSet<Result<(), std::io::Error>> = JoinSet::new();
        connections.spawn(async { std::future::pending::<Result<(), std::io::Error>>().await });
        connections.abort_all();

        expect_unix_connection_result_success(
            connections.join_next().await,
            "shutdown-aborted connection task",
        );
    }

    #[test]
    fn unix_kernel_failure_classifier_preserves_schema_failures() {
        assert_eq!(
            unix_kernel_failure_to_mneme(UnixKernelFailure::InvalidLogicalKey),
            MnemeError::SchemaDrift
        );
        assert_eq!(
            unix_kernel_failure_to_mneme(UnixKernelFailure::BodyBase64Decode),
            MnemeError::SchemaDrift
        );
        assert_eq!(
            unix_kernel_failure_to_mneme(UnixKernelFailure::SyncFrameBase64Decode),
            MnemeError::SchemaDrift
        );
    }

    #[test]
    fn unix_kernel_failure_classifier_preserves_store_unavailable_context() {
        let err = unix_kernel_failure_to_mneme(UnixKernelFailure::StoreUnavailable("head"));

        match err {
            MnemeError::IoFailed { path, kind } => {
                assert_eq!(path, "unix kernel head store");
                assert_eq!(kind, "store lock poisoned");
            }
            other => panic!("expected Unix store-unavailable I/O error, got {other:?}"),
        }
    }
}
