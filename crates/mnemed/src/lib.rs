//! MNEME daemon library — start test/production servers.

mod audit;
pub mod grpc;
pub mod http;
mod observability;
pub mod state;
pub mod sync;
pub mod sync_client;
pub mod unix;

#[cfg(feature = "context_gate")]
pub mod context_gate;

pub use grpc::pb;
pub use observability::{AUDIT_TARGET, init_observability};
pub use state::AppState;

use mneme_core::MnemeError;
use mneme_crypto::{KeyPair, load_or_generate_operator};
use mneme_store::{Store, store_head_entry_exists_no_follow};
use state::{RateLimiter, SharedStore};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

type ServerTaskResult = Result<(), MnemeError>;
type ServerTaskHandle = tokio::task::JoinHandle<ServerTaskResult>;
type ServerTaskJoin = Result<ServerTaskResult, tokio::task::JoinError>;
const TEST_OPERATOR_SEED_HEX: &str =
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

pub const DEFAULT_RATE_LIMIT_PER_MINUTE: u32 = 120;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ShutdownSignalDelivery {
    Delivered,
    NoReceivers,
}

enum ServerTaskShutdownOutcome {
    Completed,
    Failed(MnemeError),
    Panicked(tokio::task::JoinError),
}

pub struct ServerConfig {
    pub http_addr: SocketAddr,
    pub grpc_addr: Option<SocketAddr>,
    pub unix_socket: Option<PathBuf>,
    pub rate_limit_per_minute: u32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            http_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            grpc_addr: None,
            unix_socket: None,
            rate_limit_per_minute: DEFAULT_RATE_LIMIT_PER_MINUTE,
        }
    }
}

pub struct RunningServer {
    pub http_addr: SocketAddr,
    pub grpc_addr: Option<SocketAddr>,
    pub unix_socket: Option<PathBuf>,
    pub state: AppState,
    shutdown: tokio::sync::watch::Sender<()>,
    handles: Vec<ServerTaskHandle>,
}

impl RunningServer {
    pub async fn shutdown(self) {
        match notify_running_server_shutdown(&self.shutdown) {
            ShutdownSignalDelivery::Delivered | ShutdownSignalDelivery::NoReceivers => {}
        }
        for handle in self.handles {
            let task_shutdown = observe_server_task_shutdown(handle).await;
            assert_server_task_shutdown_completed(task_shutdown);
        }
    }
}

fn notify_running_server_shutdown(
    shutdown: &tokio::sync::watch::Sender<()>,
) -> ShutdownSignalDelivery {
    match shutdown.send(()) {
        Ok(()) => ShutdownSignalDelivery::Delivered,
        Err(_) => ShutdownSignalDelivery::NoReceivers,
    }
}

async fn observe_server_task_shutdown(handle: ServerTaskHandle) -> ServerTaskShutdownOutcome {
    classify_server_task_shutdown(handle.await)
}

fn classify_server_task_shutdown(join: ServerTaskJoin) -> ServerTaskShutdownOutcome {
    match join {
        Ok(Ok(())) => ServerTaskShutdownOutcome::Completed,
        Ok(Err(err)) => ServerTaskShutdownOutcome::Failed(err),
        Err(err) => ServerTaskShutdownOutcome::Panicked(err),
    }
}

fn assert_server_task_shutdown_completed(task_shutdown: ServerTaskShutdownOutcome) {
    match task_shutdown {
        ServerTaskShutdownOutcome::Completed => {}
        ServerTaskShutdownOutcome::Failed(err) => {
            panic!("server task failed during shutdown: {err:?}")
        }
        ServerTaskShutdownOutcome::Panicked(err) => {
            panic!("server task panicked during shutdown: {err}")
        }
    }
}

async fn wait_for_running_server_shutdown(mut shutdown_rx: tokio::sync::watch::Receiver<()>) {
    match shutdown_rx.changed().await {
        Ok(()) | Err(_) => {}
    }
}

pub fn test_state(store_path: &Path) -> Result<(AppState, KeyPair, KeyPair), MnemeError> {
    boot_daemon_state_with_operator_seed(store_path, Some(TEST_OPERATOR_SEED_HEX))
}

/// Production boot: open existing store (never recreate on boot) with explicit/sealed
/// operator seed custody.
pub fn boot_daemon_state(store_path: &Path) -> Result<(AppState, KeyPair, KeyPair), MnemeError> {
    boot_daemon_state_with_operator_seed(store_path, None)
}

fn boot_daemon_state_with_operator_seed(
    store_path: &Path,
    seed_hex: Option<&str>,
) -> Result<(AppState, KeyPair, KeyPair), MnemeError> {
    mneme_store::reject_store_path_aliases(store_path)?;
    let operator = load_or_generate_operator(store_path, seed_hex)?;
    let store = if store_head_entry_exists_no_follow(store_path)? {
        Store::open(store_path, operator.clone())?
    } else {
        fs::create_dir_all(store_path).map_err(|e| MnemeError::IoFailed {
            path: store_path.display().to_string(),
            kind: e.to_string(),
        })?;
        Store::create(store_path, operator.clone())?
    };
    let agent = KeyPair::generate();
    let shared: SharedStore = Arc::new(Mutex::new(store));
    let state = AppState {
        store: shared,
        operator: Arc::new(operator.clone()),
        rate_limit: Arc::new(Mutex::new(RateLimiter::new(DEFAULT_RATE_LIMIT_PER_MINUTE))),
    };
    Ok((state, operator, agent))
}

pub fn ensure_http_bind_loopback(addr: SocketAddr) -> Result<(), MnemeError> {
    if !addr.ip().is_loopback() {
        return Err(MnemeError::CapDenied);
    }
    Ok(())
}

pub async fn start(config: ServerConfig, store_path: &Path) -> Result<RunningServer, MnemeError> {
    ensure_http_bind_loopback(config.http_addr)?;
    let (state, _op, _agent) = boot_daemon_state(store_path)?;
    start_with_state(config, state).await
}

pub async fn start_with_state(
    config: ServerConfig,
    state: AppState,
) -> Result<RunningServer, MnemeError> {
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
    let state = AppState {
        store: state.store,
        operator: state.operator,
        rate_limit: Arc::new(Mutex::new(RateLimiter::new(config.rate_limit_per_minute))),
    };

    let http_app = http::router(state.clone()).merge(sync::router(state.clone()));
    let http_listener =
        TcpListener::bind(config.http_addr)
            .await
            .map_err(|e| MnemeError::IoFailed {
                path: config.http_addr.to_string(),
                kind: e.to_string(),
            })?;
    let http_addr = http_listener
        .local_addr()
        .map_err(|e| MnemeError::IoFailed {
            path: config.http_addr.to_string(),
            kind: e.to_string(),
        })?;

    let grpc_bound = if let Some(addr) = config.grpc_addr {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| MnemeError::IoFailed {
                path: addr.to_string(),
                kind: e.to_string(),
            })?;
        let bound = listener.local_addr().map_err(|e| MnemeError::IoFailed {
            path: addr.to_string(),
            kind: e.to_string(),
        })?;
        Some((bound, listener))
    } else {
        None
    };

    let unix_socket = config.unix_socket.clone();
    let unix_bound = if let Some(path) = config.unix_socket {
        Some((
            path.clone(),
            unix::UnixServer::new(path.clone(), state.clone())
                .bind()
                .map_err(|e| MnemeError::IoFailed {
                    path: path.display().to_string(),
                    kind: e.to_string(),
                })?,
        ))
    } else {
        None
    };

    let shutdown_rx_http = shutdown_rx.clone();
    let http_error_path = http_addr.to_string();
    let http_handle = tokio::spawn(async move {
        axum::serve(http_listener, http_app)
            .with_graceful_shutdown(wait_for_running_server_shutdown(shutdown_rx_http))
            .await
            .map_err(|e| MnemeError::IoFailed {
                path: http_error_path,
                kind: e.to_string(),
            })
    });

    let mut handles = vec![http_handle];
    let mut grpc_addr = None;

    if let Some((bound, listener)) = grpc_bound {
        grpc_addr = Some(bound);
        let svc = grpc::service(state.clone());
        let shutdown_rx_grpc = shutdown_rx.clone();
        let grpc_error_path = bound.to_string();
        let grpc_handle = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(svc)
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    wait_for_running_server_shutdown(shutdown_rx_grpc),
                )
                .await
                .map_err(|e| MnemeError::IoFailed {
                    path: grpc_error_path,
                    kind: e.to_string(),
                })
        });
        handles.push(grpc_handle);
    }

    if let Some((path, unix_server)) = unix_bound {
        let shutdown_rx_unix = shutdown_rx.clone();
        let unix_error_path = path.display().to_string();
        let unix_handle = tokio::spawn(async move {
            unix_server
                .serve_until_shutdown(shutdown_rx_unix)
                .await
                .map_err(|e| MnemeError::IoFailed {
                    path: unix_error_path,
                    kind: e.to_string(),
                })
        });
        handles.push(unix_handle);
    }

    Ok(RunningServer {
        http_addr,
        grpc_addr,
        unix_socket,
        state,
        shutdown: shutdown_tx,
        handles,
    })
}

pub fn cap_to_b64(cap: &mneme_cap::Capability) -> Result<String, MnemeError> {
    use base64::Engine;
    let bytes = cap.to_bytes()?;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUNNING_SERVER_SHUTDOWN_HELPER_TIMEOUT: std::time::Duration =
        std::time::Duration::from_secs(1);

    fn panic_server_task_boom() {
        panic!("server task boom");
    }

    fn expect_shutdown_signal_sent(shutdown: &tokio::sync::watch::Sender<()>, context: &str) {
        if shutdown.send(()).is_err() {
            panic!("{context}: shutdown signal send failed");
        }
    }

    async fn expect_running_server_shutdown_helper_exit(
        shutdown_rx: tokio::sync::watch::Receiver<()>,
        context: &str,
    ) {
        tokio::time::timeout(
            RUNNING_SERVER_SHUTDOWN_HELPER_TIMEOUT,
            wait_for_running_server_shutdown(shutdown_rx),
        )
        .await
        .unwrap_or_else(|_| panic!("{context}: shutdown helper did not exit"));
    }

    fn expect_running_server_tempdir(context: &str) -> tempfile::TempDir {
        tempfile::tempdir()
            .unwrap_or_else(|err| panic!("{context}: RunningServer tempdir failed: {err}"))
    }

    fn expect_running_server_test_state(store_path: &Path, context: &str) -> AppState {
        let (state, _, _) = test_state(store_path)
            .unwrap_or_else(|err| panic!("{context}: RunningServer test state failed: {err:?}"));
        state
    }

    #[cfg(unix)]
    fn replace_head_with_dangling_symlink(store_path: &Path) -> PathBuf {
        let head = store_path.join("roots/HEAD");
        let missing = store_path.join("missing-head");
        fs::remove_file(store_path.join("roots/1.root.cbor")).expect("remove genesis checkpoint");
        fs::remove_file(&head).expect("remove real HEAD");
        std::os::unix::fs::symlink(&missing, &head).expect("dangling HEAD symlink");
        assert!(!head.exists(), "fixture should be a dangling symlink");
        missing
    }

    #[cfg(unix)]
    #[test]
    fn daemon_boot_rejects_symlink_store_root_before_operator_custody_resolution() {
        let dir = expect_running_server_tempdir("daemon symlink store root fixture");
        let external = dir.path().join("external-store-target");
        fs::create_dir(&external).expect("external store target");
        let store_link = dir.path().join("store-link");
        std::os::unix::fs::symlink(&external, &store_link).expect("store root symlink");

        match boot_daemon_state_with_operator_seed(&store_link, None) {
            Err(MnemeError::IoFailed { kind, .. }) => {
                assert!(
                    kind.contains("symlink"),
                    "store-root alias rejection should mention symlink, got {kind}"
                );
            }
            Err(err) => panic!("expected IoFailed for symlinked store root, got {err:?}"),
            Ok(_) => panic!("daemon boot accepted a symlinked store root"),
        }

        assert!(
            fs::read_dir(&external)
                .expect("external target readable")
                .next()
                .is_none(),
            "daemon boot must reject the symlinked root before custody or store writes"
        );
    }

    #[test]
    fn running_server_shutdown_notification_reports_delivered_with_receiver() {
        let (shutdown, _shutdown_rx) = tokio::sync::watch::channel(());

        assert_eq!(
            notify_running_server_shutdown(&shutdown),
            ShutdownSignalDelivery::Delivered
        );
    }

    #[test]
    fn running_server_shutdown_notification_reports_no_receivers_after_receiver_drop() {
        let (shutdown, shutdown_rx) = tokio::sync::watch::channel(());

        drop(shutdown_rx);

        assert_eq!(
            notify_running_server_shutdown(&shutdown),
            ShutdownSignalDelivery::NoReceivers
        );
    }

    #[tokio::test]
    async fn running_server_shutdown_signal_helper_observes_send() {
        let (shutdown, shutdown_rx) = tokio::sync::watch::channel(());

        expect_shutdown_signal_sent(&shutdown, "shutdown helper signal test");

        expect_running_server_shutdown_helper_exit(shutdown_rx, "shutdown helper signal test")
            .await;
    }

    #[tokio::test]
    async fn running_server_shutdown_signal_helper_observes_owner_drop() {
        let (shutdown, shutdown_rx) = tokio::sync::watch::channel(());

        drop(shutdown);

        expect_running_server_shutdown_helper_exit(shutdown_rx, "shutdown helper owner-drop test")
            .await;
    }

    #[tokio::test]
    #[should_panic(expected = "server task panicked during shutdown")]
    async fn running_server_shutdown_surfaces_task_panic() {
        let dir = expect_running_server_tempdir("shutdown panic fixture");
        let state = expect_running_server_test_state(dir.path(), "shutdown panic fixture");
        let (shutdown, _shutdown_rx) = tokio::sync::watch::channel(());
        let handle = tokio::spawn(async {
            panic_server_task_boom();
            Ok::<(), MnemeError>(())
        });

        RunningServer {
            http_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            grpc_addr: None,
            unix_socket: None,
            state,
            shutdown,
            handles: vec![handle],
        }
        .shutdown()
        .await;
    }

    #[tokio::test]
    #[should_panic(expected = "server task failed during shutdown")]
    async fn running_server_shutdown_surfaces_task_error() {
        let dir = expect_running_server_tempdir("shutdown task-error fixture");
        let state = expect_running_server_test_state(dir.path(), "shutdown task-error fixture");
        let (shutdown, _shutdown_rx) = tokio::sync::watch::channel(());
        let handle = tokio::spawn(async {
            Err::<(), MnemeError>(MnemeError::IoFailed {
                path: "server".into(),
                kind: "task failed".into(),
            })
        });

        RunningServer {
            http_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            grpc_addr: None,
            unix_socket: None,
            state,
            shutdown,
            handles: vec![handle],
        }
        .shutdown()
        .await;
    }

    #[test]
    fn ensure_http_bind_loopback_accepts_localhost() {
        let addr = "127.0.0.1:7845".parse().expect("loopback parse");
        assert_eq!(ensure_http_bind_loopback(addr), Ok(()));
    }

    #[test]
    fn ensure_http_bind_loopback_rejects_non_loopback_without_tls() {
        let addr = "0.0.0.0:7845".parse().expect("non-loopback parse");
        assert_eq!(ensure_http_bind_loopback(addr), Err(MnemeError::CapDenied));
    }

    #[cfg(unix)]
    #[test]
    fn daemon_boot_rejects_dangling_head_entry_instead_of_recreating_store() {
        let dir = expect_running_server_tempdir("daemon dangling HEAD fixture");
        let (state, _, _) = test_state(dir.path()).expect("initial daemon state");
        drop(state);

        let missing = replace_head_with_dangling_symlink(dir.path());

        match test_state(dir.path()) {
            Err(MnemeError::IoFailed { path, .. }) => {
                assert!(
                    path.ends_with("roots/HEAD"),
                    "unexpected failure path: {path}"
                );
            }
            Err(MnemeError::RootInconsistent) => {}
            Err(err) => panic!("expected dangling HEAD failure, got {err:?}"),
            Ok(_) => panic!("daemon boot recreated a tampered store with dangling HEAD"),
        }

        assert!(
            !missing.exists(),
            "daemon boot must not materialize HEAD symlink target"
        );
        assert!(
            fs::symlink_metadata(dir.path().join("roots/HEAD"))
                .expect("dangling HEAD entry")
                .file_type()
                .is_symlink(),
            "daemon boot must leave the tampered HEAD entry for explicit repair"
        );
        assert!(
            !dir.path().join("roots/1.root.cbor").exists(),
            "daemon boot must not recreate a deleted checkpoint"
        );
    }
}
