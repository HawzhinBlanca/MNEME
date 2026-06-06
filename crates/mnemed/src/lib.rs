//! MNEME daemon library — start test/production servers.

pub mod grpc;
pub mod http;
pub mod state;
pub mod sync;
pub mod sync_client;
pub mod unix;

#[cfg(feature = "context_gate")]
pub mod context_gate;

pub use grpc::pb;
pub use state::AppState;

use mneme_core::MnemeError;
use mneme_crypto::KeyPair;
use mneme_store::Store;
use state::{RateLimiter, SharedStore};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

type ServerTaskResult = Result<(), MnemeError>;
type ServerTaskHandle = tokio::task::JoinHandle<ServerTaskResult>;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ShutdownSignalDelivery {
    Delivered,
    NoReceivers,
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
            rate_limit_per_minute: 120,
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
            handle
                .await
                .expect("server task panicked during shutdown")
                .expect("server task failed during shutdown");
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

async fn wait_for_running_server_shutdown(mut shutdown_rx: tokio::sync::watch::Receiver<()>) {
    match shutdown_rx.changed().await {
        Ok(()) | Err(_) => {}
    }
}

pub fn test_state(store_path: &Path) -> Result<(AppState, KeyPair, KeyPair), MnemeError> {
    let operator = KeyPair::generate();
    let agent = KeyPair::generate();
    let store = Store::create(store_path, operator.clone())?;
    let shared: SharedStore = Arc::new(Mutex::new(store));
    let state = AppState {
        store: shared,
        operator: Arc::new(operator.clone()),
        rate_limit: Arc::new(Mutex::new(RateLimiter::new(120))),
    };
    Ok((state, operator, agent))
}

pub async fn start(config: ServerConfig, store_path: &Path) -> Result<RunningServer, MnemeError> {
    let (state, _op, _agent) = test_state(store_path)?;
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

        shutdown.send(()).expect("send shutdown");

        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            wait_for_running_server_shutdown(shutdown_rx),
        )
        .await
        .expect("shutdown helper exits after signal");
    }

    #[tokio::test]
    async fn running_server_shutdown_signal_helper_observes_owner_drop() {
        let (shutdown, shutdown_rx) = tokio::sync::watch::channel(());

        drop(shutdown);

        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            wait_for_running_server_shutdown(shutdown_rx),
        )
        .await
        .expect("shutdown helper exits after owner drop");
    }

    #[tokio::test]
    #[should_panic(expected = "server task panicked during shutdown")]
    async fn running_server_shutdown_surfaces_task_panic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (state, _, _) = test_state(dir.path()).expect("test_state");
        let (shutdown, _shutdown_rx) = tokio::sync::watch::channel(());
        let handle = tokio::spawn(async {
            panic!("server task boom");
            #[allow(unreachable_code)]
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
        let dir = tempfile::tempdir().expect("tempdir");
        let (state, _, _) = test_state(dir.path()).expect("test_state");
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
}
