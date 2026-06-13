mod common;
mod unix_ready;

use common::TestHarness;
use mneme_cap::agent_cap;
use mneme_core::{Draft, MemoryKind, ObjectId};
use mnemed::pb::RecallRequest;
use mnemed::pb::memory_service_client::MemoryServiceClient;
use mnemed::unix::{KernelRequest, KernelResponse, UnixServer, request_json};
use serde_json::json;
use std::path::{Path, PathBuf};
use tempfile::tempdir;
use tokio::task::JoinHandle;
use unix_ready::wait_for_unix_socket_accepting;

type RedteamUnixServerResult = Result<(), std::io::Error>;
type RedteamUnixServerJoin = Result<RedteamUnixServerResult, tokio::task::JoinError>;
type TimedRedteamUnixServerJoin = Result<RedteamUnixServerJoin, tokio::time::error::Elapsed>;
type UnixTamperRecallCheck = Result<(), String>;

const REDTEAM_UNIX_SERVER_SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

enum RedteamUnixShutdownSignalDelivery {
    Delivered,
    NoReceivers,
}

enum RedteamUnixServerJoinOutcome {
    Completed(RedteamUnixServerResult),
    JoinFailed(tokio::task::JoinError),
    TimedOut,
}

struct RedteamUnixServer {
    shutdown_tx: tokio::sync::watch::Sender<()>,
    handle: JoinHandle<RedteamUnixServerResult>,
}

impl RedteamUnixServer {
    async fn shutdown(self) {
        let shutdown_signal = observe_redteam_unix_shutdown_signal(&self.shutdown_tx);
        match shutdown_signal {
            RedteamUnixShutdownSignalDelivery::Delivered
            | RedteamUnixShutdownSignalDelivery::NoReceivers => {}
        }
        let shutdown_join = join_redteam_unix_server_shutdown(self.handle).await;
        assert_redteam_unix_shutdown_completed(shutdown_join);
    }
}

fn observe_redteam_unix_shutdown_signal(
    shutdown: &tokio::sync::watch::Sender<()>,
) -> RedteamUnixShutdownSignalDelivery {
    match shutdown.send(()) {
        Ok(()) => RedteamUnixShutdownSignalDelivery::Delivered,
        Err(_) => RedteamUnixShutdownSignalDelivery::NoReceivers,
    }
}

async fn join_redteam_unix_server_shutdown(
    handle: JoinHandle<RedteamUnixServerResult>,
) -> RedteamUnixServerJoinOutcome {
    classify_redteam_unix_server_join(
        tokio::time::timeout(REDTEAM_UNIX_SERVER_SHUTDOWN_TIMEOUT, handle).await,
    )
}

fn classify_redteam_unix_server_join(
    join: TimedRedteamUnixServerJoin,
) -> RedteamUnixServerJoinOutcome {
    match join {
        Ok(Ok(result)) => RedteamUnixServerJoinOutcome::Completed(result),
        Ok(Err(err)) => RedteamUnixServerJoinOutcome::JoinFailed(err),
        Err(_) => RedteamUnixServerJoinOutcome::TimedOut,
    }
}

fn assert_redteam_unix_shutdown_completed(join: RedteamUnixServerJoinOutcome) {
    match join {
        RedteamUnixServerJoinOutcome::Completed(Ok(())) => {}
        RedteamUnixServerJoinOutcome::Completed(Err(err)) => {
            panic!("redteam Unix server returned error: {err}")
        }
        RedteamUnixServerJoinOutcome::JoinFailed(err) => {
            panic!("redteam Unix server task failed to join: {err}")
        }
        RedteamUnixServerJoinOutcome::TimedOut => {
            panic!("redteam Unix server did not exit before shutdown timeout")
        }
    }
}

async fn spawn_redteam_unix_server(sock: PathBuf, state: mnemed::AppState) -> RedteamUnixServer {
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
    let handle = tokio::spawn({
        let sock = sock.clone();
        async move {
            UnixServer::new(sock, state)
                .serve_until_shutdown(shutdown_rx)
                .await
        }
    });
    wait_for_unix_socket_accepting(&sock).await;
    RedteamUnixServer {
        shutdown_tx,
        handle,
    }
}

fn assert_unix_tamper_recall_rejected(resp: KernelResponse) {
    let tamper_recall = expect_unix_tamper_recall_rejected(resp);

    assert_unix_tamper_recall_check_passed(tamper_recall);
}

fn expect_unix_tamper_recall_rejected(resp: KernelResponse) -> UnixTamperRecallCheck {
    match resp {
        KernelResponse::Err { code, message, .. } => {
            if is_unix_tamper_rejection(&code, &message) {
                Ok(())
            } else {
                Err(format!("unexpected unix error: {code} {message}"))
            }
        }
        KernelResponse::Ok { payload } => Err(format!("tampered recall succeeded: {payload}")),
    }
}

fn is_unix_tamper_rejection(code: &str, message: &str) -> bool {
    code.contains("verify") || message.contains("ObjectTampered") || message.contains("tamper")
}

fn assert_unix_tamper_recall_check_passed(tamper_recall: UnixTamperRecallCheck) {
    match tamper_recall {
        Ok(()) => {}
        Err(message) => panic!("{message}"),
    }
}

fn object_id_from_hex(hex_id: &str, context: &str) -> ObjectId {
    let bytes = hex::decode(hex_id)
        .unwrap_or_else(|err| panic!("{context}: object id hex decode failed: {err}"));
    let object_id_bytes: [u8; 32] = bytes.try_into().unwrap_or_else(|bytes: Vec<u8>| {
        panic!(
            "{context}: object id hex decoded to {} bytes, expected 32",
            bytes.len()
        )
    });

    ObjectId(object_id_bytes)
}

fn expect_json_str_field<'a>(body: &'a serde_json::Value, field: &str, context: &str) -> &'a str {
    body[field]
        .as_str()
        .unwrap_or_else(|| panic!("{context}: missing string field `{field}`"))
}

async fn expect_http_response<F>(request: F, context: &str) -> reqwest::Response
where
    F: std::future::Future<Output = Result<reqwest::Response, reqwest::Error>>,
{
    request
        .await
        .unwrap_or_else(|err| panic!("{context}: HTTP request failed: {err}"))
}

async fn expect_json_response(resp: reqwest::Response, context: &str) -> serde_json::Value {
    resp.json::<serde_json::Value>()
        .await
        .unwrap_or_else(|err| panic!("{context}: JSON response decode failed: {err}"))
}

fn expect_cap_b64(cap: &mneme_cap::Capability, context: &str) -> String {
    mnemed::cap_to_b64(cap)
        .unwrap_or_else(|err| panic!("{context}: capability encoding failed: {err:?}"))
}

async fn connect_memory_service(
    endpoint: String,
    context: &str,
) -> MemoryServiceClient<tonic::transport::Channel> {
    MemoryServiceClient::connect(endpoint)
        .await
        .unwrap_or_else(|err| panic!("{context}: gRPC connect failed: {err}"))
}

fn expect_grpc_response<T>(
    response: Result<tonic::Response<T>, tonic::Status>,
    context: &str,
) -> T {
    response
        .unwrap_or_else(|err| panic!("{context}: gRPC request failed: {err}"))
        .into_inner()
}

fn expect_store_lock<T, E: std::fmt::Debug>(lock: Result<T, E>, context: &str) -> T {
    lock.unwrap_or_else(|err| panic!("{context}: store lock failed: {err:?}"))
}

fn tamper_harness_object_bytes(h: &TestHarness, id: &ObjectId, context: &str) {
    expect_store_lock(h.store().lock(), context)
        .tamper_object_bytes(id.as_bytes())
        .unwrap_or_else(|err| panic!("{context}: object tamper failed: {err:?}"));
}

fn expect_tempdir(context: &str) -> tempfile::TempDir {
    tempdir().unwrap_or_else(|err| panic!("{context}: tempdir failed: {err}"))
}

fn expect_test_state(
    store_path: &Path,
    context: &str,
) -> (
    mnemed::AppState,
    mneme_crypto::KeyPair,
    mneme_crypto::KeyPair,
) {
    mnemed::test_state(store_path)
        .unwrap_or_else(|err| panic!("{context}: test state setup failed: {err:?}"))
}

fn expect_agent_cap(
    operator: &mneme_crypto::KeyPair,
    agent: &mneme_crypto::KeyPair,
    context: &str,
) -> mneme_cap::Capability {
    agent_cap(operator, agent.public_key_bytes())
        .unwrap_or_else(|err| panic!("{context}: agent capability creation failed: {err:?}"))
}

fn remember_and_tamper_unix_object(
    state: &mnemed::AppState,
    agent: &mneme_crypto::KeyPair,
    cap: &mneme_cap::Capability,
    context: &str,
) {
    let mut store = expect_store_lock(state.store.lock(), context);
    store.trust = store.trust.clone().with_writer(agent.public_key_bytes());
    let (id, _) = store
        .remember(
            Draft {
                namespace: "unix".into(),
                logical_name: "adb".into(),
                kind: MemoryKind::Episodic,
                body: b"unix honest".to_vec(),
                parent_ids: vec![],
                session: [0xab; 16],
                trust_tier: None,
                embedding: None,
                valid_time_ms: None,
            },
            cap,
        )
        .unwrap_or_else(|err| panic!("{context}: Unix redteam store remember failed: {err:?}"));
    store
        .tamper_object_bytes(id.as_bytes())
        .unwrap_or_else(|err| panic!("{context}: object tamper failed: {err:?}"));
}

async fn expect_unix_response(sock: &PathBuf, cap_b64: String, context: &str) -> KernelResponse {
    request_json(
        sock,
        &KernelRequest::RecallVerified {
            cap_b64,
            namespace: "unix".into(),
            name: "adb".into(),
            prompt: None,
            weight_measurement_hex: None,
            sampling_params: None,
            output_token_commit_hex: None,
        },
    )
    .await
    .unwrap_or_else(|err| panic!("{context}: Unix request failed: {err}"))
}

async fn remember_http(h: &TestHarness) -> ObjectId {
    let resp = expect_http_response(
        reqwest::Client::new()
            .post(format!("{}/v1/memory", h.http_base()))
            .header("Authorization", h.agent_auth_header())
            .json(&json!({"namespace":"redteam","name":"adb-target","kind":"semantic","body":"honest payload"}))
            .send(),
        "HTTP redteam remember",
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = expect_json_response(resp, "HTTP redteam remember response").await;
    let hex_id = expect_json_str_field(&body, "object_id_hex", "HTTP redteam remember response");

    object_id_from_hex(hex_id, "HTTP redteam remember response")
}

#[tokio::test]
async fn redteam_http_recall_rejects_out_of_band_object_tamper() {
    let h = TestHarness::new().await;
    let id = remember_http(&h).await;
    tamper_harness_object_bytes(&h, &id, "HTTP redteam out-of-band object tamper");
    let resp = expect_http_response(
        reqwest::Client::new()
            .get(format!(
                "{}/v1/memory/redteam/adb-target?min_tier=working",
                h.http_base()
            ))
            .header("Authorization", h.agent_auth_header())
            .send(),
        "HTTP redteam recall after tamper",
    )
    .await;
    assert_eq!(resp.status(), 403);
    let body = expect_json_response(resp, "HTTP redteam recall rejection response").await;
    assert_eq!(
        expect_json_str_field(&body, "code", "HTTP redteam recall rejection response"),
        "verify_failed"
    );
    h.shutdown().await;
}

#[tokio::test]
async fn redteam_grpc_recall_rejects_out_of_band_object_tamper() {
    let h = TestHarness::new().await;
    let cap = expect_cap_b64(&h.agent_cap, "gRPC redteam capability");
    let mut client = connect_memory_service(h.grpc_endpoint(), "gRPC redteam memory service").await;
    let remembered = expect_grpc_response(
        client
            .remember(mnemed::pb::RememberRequest {
                capability_b64: cap.clone(),
                namespace: "redteam".into(),
                name: "grpc-adb".into(),
                kind: "semantic".into(),
                body: b"grpc honest".to_vec(),
            })
            .await,
        "gRPC redteam remember",
    );
    let id = object_id_from_hex(&remembered.object_id_hex, "gRPC redteam remember response");
    tamper_harness_object_bytes(&h, &id, "gRPC redteam out-of-band object tamper");
    let err = client
        .recall(RecallRequest {
            capability_b64: cap,
            namespace: "redteam".into(),
            name: "grpc-adb".into(),
            min_tier: "working".into(),
        })
        .await
        .unwrap_err();
    let msg = err.message();
    assert!(
        msg.contains("ObjectTampered") || msg.contains("verify") || msg.contains("tamper"),
        "unexpected gRPC error: {msg}"
    );
    drop(client);
    h.shutdown().await;
}

#[tokio::test]
async fn redteam_unix_recall_verified_rejects_out_of_band_object_tamper() {
    let dir = expect_tempdir("Unix redteam setup");
    let sock: PathBuf = dir.path().join("redteam.sock");
    let (state, operator, agent) = expect_test_state(dir.path(), "Unix redteam setup");
    let cap = expect_agent_cap(&operator, &agent, "Unix redteam capability");
    let cap_b64 = expect_cap_b64(&cap, "Unix redteam capability");
    remember_and_tamper_unix_object(
        &state,
        &agent,
        &cap,
        "Unix redteam out-of-band object tamper",
    );
    let server = spawn_redteam_unix_server(sock.clone(), state).await;
    let resp = expect_unix_response(&sock, cap_b64, "Unix redteam recall after tamper").await;
    assert_unix_tamper_recall_rejected(resp);
    server.shutdown().await;
}
