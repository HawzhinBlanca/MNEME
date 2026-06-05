use super::common::TestHarness;
use mnemed::pb::memory_service_client::MemoryServiceClient;
use mnemed::pb::{ForgetRequest, RecallRequest, RememberRequest};

#[tokio::test]
async fn grpc_remember_recall_forget() {
    let h = TestHarness::new().await;
    let mut client = MemoryServiceClient::connect(h.grpc_endpoint())
        .await
        .expect("connect grpc");

    let cap = mnemed::cap_to_b64(&h.agent_cap).expect("cap b64");

    let remembered = client
        .remember(RememberRequest {
            capability_b64: cap.clone(),
            namespace: "grpc".into(),
            name: "note".into(),
            kind: "semantic".into(),
            body: b"hello grpc".to_vec(),
        })
        .await
        .expect("remember")
        .into_inner();
    assert!(!remembered.object_id_hex.is_empty());

    let recalled = client
        .recall(RecallRequest {
            capability_b64: cap.clone(),
            namespace: "grpc".into(),
            name: "note".into(),
            min_tier: "working".into(),
        })
        .await
        .expect("recall")
        .into_inner();
    assert_eq!(recalled.entries.len(), 1);
    assert_eq!(recalled.entries[0].body, b"hello grpc");

    client
        .forget(ForgetRequest {
            capability_b64: cap,
            namespace: "grpc".into(),
            name: "note".into(),
        })
        .await
        .expect("forget");
}

#[tokio::test]
async fn grpc_health_no_auth() {
    let h = TestHarness::new().await;
    let mut client = MemoryServiceClient::connect(h.grpc_endpoint())
        .await
        .expect("connect");
    let resp = client
        .health(mnemed::pb::HealthRequest {})
        .await
        .expect("health")
        .into_inner();
    assert_eq!(resp.status, "ok");
}
