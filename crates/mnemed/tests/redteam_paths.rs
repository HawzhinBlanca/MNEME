mod common;
use common::TestHarness;
use mneme_cap::agent_cap;
use mneme_core::{Draft, MemoryKind, ObjectId};
use mnemed::pb::memory_service_client::MemoryServiceClient;
use mnemed::pb::RecallRequest;
use mnemed::unix::{KernelRequest, UnixServer, request_json};
use serde_json::json;
use std::path::PathBuf;
use tempfile::tempdir;

async fn remember_http(h: &TestHarness) -> ObjectId {
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/memory", h.http_base()))
        .header("Authorization", h.agent_auth_header())
        .json(&json!({"namespace":"redteam","name":"adb-target","kind":"semantic","body":"honest payload"}))
        .send().await.expect("remember");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    let hex_id = body["object_id_hex"].as_str().expect("object_id_hex");
    ObjectId(hex::decode(hex_id).unwrap().try_into().unwrap())
}

#[tokio::test]
async fn redteam_http_recall_rejects_out_of_band_object_tamper() {
    let h = TestHarness::new().await;
    let id = remember_http(&h).await;
    h.store().lock().unwrap().tamper_object_bytes(id.as_bytes()).unwrap();
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/memory/redteam/adb-target?min_tier=working", h.http_base()))
        .header("Authorization", h.agent_auth_header()).send().await.unwrap();
    assert_eq!(resp.status(), 403);
    assert_eq!(resp.json::<serde_json::Value>().await.unwrap()["code"], "verify_failed");
}

#[tokio::test]
async fn redteam_grpc_recall_rejects_out_of_band_object_tamper() {
    let h = TestHarness::new().await;
    let cap = mnemed::cap_to_b64(&h.agent_cap).unwrap();
    let mut client = MemoryServiceClient::connect(h.grpc_endpoint()).await.unwrap();
    let remembered = client.remember(mnemed::pb::RememberRequest {
        capability_b64: cap.clone(), namespace: "redteam".into(), name: "grpc-adb".into(),
        kind: "semantic".into(), body: b"grpc honest".to_vec(),
    }).await.unwrap().into_inner();
    let id = ObjectId(hex::decode(&remembered.object_id_hex).unwrap().try_into().unwrap());
    h.store().lock().unwrap().tamper_object_bytes(id.as_bytes()).unwrap();
    let err = client.recall(RecallRequest { capability_b64: cap, namespace: "redteam".into(), name: "grpc-adb".into(), min_tier: "working".into() }).await.unwrap_err();
    let msg = err.message();
    assert!(msg.contains("ObjectTampered") || msg.contains("verify") || msg.contains("tamper"), "{msg}");
}

#[tokio::test]
async fn redteam_unix_recall_verified_rejects_out_of_band_object_tamper() {
    let dir = tempdir().unwrap();
    let sock: PathBuf = dir.path().join("redteam.sock");
    let (state, operator, agent) = mnemed::test_state(dir.path()).unwrap();
    let cap = agent_cap(&operator, agent.public_key_bytes()).unwrap();
    let cap_b64 = mnemed::cap_to_b64(&cap).unwrap();
    {
        let mut store = state.store.lock().unwrap();
        store.trust = store.trust.clone().with_writer(agent.public_key_bytes());
        let (id, _) = store.remember(Draft {
            namespace: "unix".into(), logical_name: "adb".into(), kind: MemoryKind::Episodic,
            body: b"unix honest".to_vec(), parent_ids: vec![], session: [0xab; 16],
            trust_tier: None, embedding: None, valid_time_ms: None,
        }, &cap).unwrap();
        store.tamper_object_bytes(id.as_bytes()).unwrap();
    }
    let sock_path = sock.clone();
    let handle = tokio::spawn(async move { UnixServer::new(sock, state).serve().await.ok(); });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    match request_json(&sock_path, &KernelRequest::RecallVerified { cap_b64, namespace: "unix".into(), name: "adb".into() }).await.unwrap() {
        mnemed::unix::KernelResponse::Err { code, message, .. } => {
            assert!(code.contains("verify") || message.contains("ObjectTampered") || message.contains("tamper"));
        }
        mnemed::unix::KernelResponse::Ok { payload } => panic!("tampered recall succeeded: {payload}"),
    }
    handle.abort();
}
