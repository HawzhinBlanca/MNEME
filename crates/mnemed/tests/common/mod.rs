//! Shared test fixtures: store setup, capability issuance, server lifecycle.

use mneme_cap::{Capability, agent_cap, tool_channel_cap};
use mneme_crypto::KeyPair;
use mnemed::{DEFAULT_RATE_LIMIT_PER_MINUTE, ServerConfig, cap_to_b64, start_with_state};
use std::net::SocketAddr;
use std::path::Path;
use tempfile::TempDir;

pub struct TestHarness {
    pub _dir: TempDir,
    #[allow(dead_code)]
    pub operator: KeyPair,
    #[allow(dead_code)]
    pub agent: KeyPair,
    pub agent_cap: Capability,
    pub tool_cap: Capability,
    pub server: mnemed::RunningServer,
}

fn expect_harness_tempdir(context: &str) -> TempDir {
    tempfile::tempdir()
        .unwrap_or_else(|err| panic!("{context}: test harness tempdir failed: {err}"))
}

fn expect_harness_state(store_path: &Path, context: &str) -> (mnemed::AppState, KeyPair, KeyPair) {
    mnemed::test_state(store_path)
        .unwrap_or_else(|err| panic!("{context}: test harness state setup failed: {err:?}"))
}

fn expect_agent_capability(operator: &KeyPair, agent: &KeyPair, context: &str) -> Capability {
    agent_cap(operator, agent.public_key_bytes())
        .unwrap_or_else(|err| panic!("{context}: test harness agent capability failed: {err:?}"))
}

fn expect_tool_capability(operator: &KeyPair, agent: &KeyPair, context: &str) -> Capability {
    tool_channel_cap(operator, agent.public_key_bytes())
        .unwrap_or_else(|err| panic!("{context}: test harness tool capability failed: {err:?}"))
}

fn authorize_harness_tool_writer(
    state: &mnemed::AppState,
    agent: &KeyPair,
    tool_cap: &Capability,
    context: &str,
) {
    let mut store = state
        .store
        .lock()
        .unwrap_or_else(|err| panic!("{context}: test harness store lock failed: {err:?}"));
    let mut trust = store.trust.clone().with_writer(agent.public_key_bytes());
    trust.authorized_writers.push(tool_cap.subject);
    store.trust = trust;
}

fn loopback_test_addr(context: &str) -> SocketAddr {
    "127.0.0.1:0".parse().unwrap_or_else(|err| {
        panic!("{context}: test harness loopback address parse failed: {err}")
    })
}

async fn start_harness_server(
    config: ServerConfig,
    state: mnemed::AppState,
    context: &str,
) -> mnemed::RunningServer {
    start_with_state(config, state)
        .await
        .unwrap_or_else(|err| panic!("{context}: test harness server start failed: {err:?}"))
}

fn expect_harness_grpc_addr(addr: Option<SocketAddr>, context: &str) -> SocketAddr {
    addr.unwrap_or_else(|| panic!("{context}: test harness gRPC address missing"))
}

fn expect_harness_cap_b64(cap: &Capability, context: &str) -> String {
    cap_to_b64(cap)
        .unwrap_or_else(|err| panic!("{context}: test harness capability encoding failed: {err:?}"))
}

impl TestHarness {
    pub async fn new() -> Self {
        let dir = expect_harness_tempdir("TestHarness::new");
        let (state, operator, agent) = expect_harness_state(dir.path(), "TestHarness::new");
        let agent_cap = expect_agent_capability(&operator, &agent, "TestHarness::new");
        let tool_cap = expect_tool_capability(&operator, &agent, "TestHarness::new");
        authorize_harness_tool_writer(&state, &agent, &tool_cap, "TestHarness::new");
        let config = ServerConfig {
            http_addr: loopback_test_addr("TestHarness HTTP listener"),
            grpc_addr: Some(loopback_test_addr("TestHarness gRPC listener")),
            unix_socket: None,
            rate_limit_per_minute: DEFAULT_RATE_LIMIT_PER_MINUTE,
        };
        let server = start_harness_server(config, state, "TestHarness::new").await;
        Self {
            _dir: dir,
            operator,
            agent,
            agent_cap,
            tool_cap,
            server,
        }
    }

    pub fn http_base(&self) -> String {
        format!("http://{}", self.server.http_addr)
    }

    pub fn grpc_endpoint(&self) -> String {
        format!(
            "http://{}",
            expect_harness_grpc_addr(self.server.grpc_addr, "TestHarness::grpc_endpoint")
        )
    }

    pub fn agent_auth_header(&self) -> String {
        format!(
            "Bearer {}",
            expect_harness_cap_b64(&self.agent_cap, "TestHarness::agent_auth_header")
        )
    }

    #[allow(dead_code)]
    pub fn tool_auth_header(&self) -> String {
        format!(
            "Bearer {}",
            expect_harness_cap_b64(&self.tool_cap, "TestHarness::tool_auth_header")
        )
    }

    #[allow(dead_code)]
    pub fn store(&self) -> mnemed::state::SharedStore {
        self.server.state.store.clone()
    }

    pub async fn shutdown(self) {
        self.server.shutdown().await;
    }
}
