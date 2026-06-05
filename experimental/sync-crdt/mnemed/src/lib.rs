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
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

pub struct ServerConfig {
    pub http_addr: SocketAddr,
    pub grpc_addr: Option<SocketAddr>,
    pub rate_limit_per_minute: u32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            http_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            grpc_addr: None,
            rate_limit_per_minute: 120,
        }
    }
}

pub struct RunningServer {
    pub http_addr: SocketAddr,
    pub grpc_addr: Option<SocketAddr>,
    pub state: AppState,
    shutdown: tokio::sync::watch::Sender<()>,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl RunningServer {
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(());
        for h in self.handles {
            let _ = h.await;
        }
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

    let http_app = http::router(state.clone()).merge(sync::router(state.clone()));
    let listener = TcpListener::bind(config.http_addr)
        .await
        .map_err(|e| MnemeError::IoFailed {
            path: config.http_addr.to_string(),
            kind: e.to_string(),
        })?;
    let http_addr = listener.local_addr().map_err(|e| MnemeError::IoFailed {
        path: config.http_addr.to_string(),
        kind: e.to_string(),
    })?;
    let mut shutdown_rx_http = shutdown_rx.clone();
    let http_handle = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, http_app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx_http.changed().await;
            })
            .await
        {
            tracing::error!("http serve failed: {e}");
        }
    });

    let mut handles = vec![http_handle];
    let mut grpc_addr = None;

    if let Some(addr) = config.grpc_addr {
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
        grpc_addr = Some(bound);
        let svc = grpc::service(state.clone());
        let mut shutdown_rx_grpc = shutdown_rx.clone();
        let grpc_handle = tokio::spawn(async move {
            if let Err(e) = tonic::transport::Server::builder()
                .add_service(svc)
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async move {
                        let _ = shutdown_rx_grpc.changed().await;
                    },
                )
                .await
            {
                tracing::error!("grpc serve failed: {e}");
            }
        });
        handles.push(grpc_handle);
    }

    Ok(RunningServer {
        http_addr,
        grpc_addr,
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
