//! Shared test fixtures: store setup, capability issuance, server lifecycle.

use mneme_cap::{Capability, agent_cap, tool_channel_cap};
use mneme_crypto::KeyPair;
use mnemed::{ServerConfig, cap_to_b64, start_with_state};
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

impl TestHarness {
    pub async fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let (state, operator, agent) = mnemed::test_state(dir.path()).expect("test_state");
        let agent_cap = agent_cap(&operator, agent.public_key_bytes()).expect("agent cap");
        let tool_cap = tool_channel_cap(&operator, agent.public_key_bytes()).expect("tool cap");
        {
            let mut store = state.store.lock().expect("lock");
            let mut trust = store.trust.clone().with_writer(agent.public_key_bytes());
            trust.authorized_writers.push(tool_cap.subject);
            store.trust = trust;
        }
        let config = ServerConfig {
            http_addr: "127.0.0.1:0".parse().expect("addr"),
            grpc_addr: Some("127.0.0.1:0".parse().expect("addr")),
            unix_socket: None,
            rate_limit_per_minute: 120,
        };
        let server = start_with_state(config, state).await.expect("start");
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
        format!("http://{}", self.server.grpc_addr.expect("grpc"))
    }

    pub fn agent_auth_header(&self) -> String {
        format!("Bearer {}", cap_to_b64(&self.agent_cap).expect("cap b64"))
    }

    #[allow(dead_code)]
    pub fn tool_auth_header(&self) -> String {
        format!("Bearer {}", cap_to_b64(&self.tool_cap).expect("cap b64"))
    }

    #[allow(dead_code)]
    pub fn store(&self) -> mnemed::state::SharedStore {
        self.server.state.store.clone()
    }

    pub async fn shutdown(self) {
        self.server.shutdown().await;
    }
}
