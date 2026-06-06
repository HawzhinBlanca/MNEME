use super::common::TestHarness;
use mneme_core::{Draft, MemoryKind};
use mnemed::grpc::GRPC_MAX_MESSAGE_BYTES;
use mnemed::pb::memory_service_client::MemoryServiceClient;
use mnemed::pb::{ForgetRequest, HeadRequest, ProveAbsentRequest, RecallRequest, RememberRequest};

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
    drop(client);
    h.shutdown().await;
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
    drop(client);
    h.shutdown().await;
}

#[tokio::test]
async fn grpc_malformed_capability_is_unauthenticated_not_internal() {
    let h = TestHarness::new().await;
    let mut client = MemoryServiceClient::connect(h.grpc_endpoint())
        .await
        .expect("connect");

    let err = client
        .head(HeadRequest {
            capability_b64: "oA==".into(),
        })
        .await
        .expect_err("malformed capability must fail closed");

    assert_eq!(err.code(), tonic::Code::Unauthenticated);
    drop(client);
    h.shutdown().await;
}

#[tokio::test]
async fn grpc_oversized_capability_is_rejected_before_decode() {
    let h = TestHarness::new().await;
    let mut client = MemoryServiceClient::connect(h.grpc_endpoint())
        .await
        .expect("connect");

    let err = client
        .head(HeadRequest {
            capability_b64: "A".repeat(mnemed::state::MAX_CAPABILITY_B64_LEN + 1),
        })
        .await
        .expect_err("oversized capability must fail closed");

    assert_eq!(err.code(), tonic::Code::Unauthenticated);
    assert_eq!(err.message(), "capability token too large");
    drop(client);
    h.shutdown().await;
}

#[tokio::test]
async fn grpc_message_limit_rejects_oversized_remember_request() {
    let h = TestHarness::new().await;
    let mut client = MemoryServiceClient::connect(h.grpc_endpoint())
        .await
        .expect("connect")
        .max_encoding_message_size(GRPC_MAX_MESSAGE_BYTES * 2);
    let cap = mnemed::cap_to_b64(&h.agent_cap).expect("cap b64");

    let result = client
        .remember(RememberRequest {
            capability_b64: cap,
            namespace: "grpc".into(),
            name: "oversized-request".into(),
            kind: "semantic".into(),
            body: vec![0x41; GRPC_MAX_MESSAGE_BYTES + 1],
        })
        .await;
    let err = match result {
        Ok(_) => panic!("oversized gRPC request must fail before remember"),
        Err(err) => err,
    };

    assert_eq!(err.code(), tonic::Code::OutOfRange);
    drop(client);
    h.shutdown().await;
}

#[tokio::test]
async fn grpc_message_limit_rejects_oversized_recall_response() {
    let h = TestHarness::new().await;
    {
        let mut store = h.server.state.store.lock().expect("lock");
        store
            .remember(
                Draft {
                    namespace: "grpc".into(),
                    logical_name: "oversized-response".into(),
                    kind: MemoryKind::Semantic,
                    body: vec![0x42; GRPC_MAX_MESSAGE_BYTES + 1],
                    parent_ids: vec![],
                    session: [0xef; 16],
                    trust_tier: None,
                    embedding: None,
                    valid_time_ms: None,
                },
                &h.agent_cap,
            )
            .expect("seed oversized entry");
    }

    let mut client = MemoryServiceClient::connect(h.grpc_endpoint())
        .await
        .expect("connect")
        .max_decoding_message_size(GRPC_MAX_MESSAGE_BYTES * 2);
    let cap = mnemed::cap_to_b64(&h.agent_cap).expect("cap b64");
    let result = client
        .recall(RecallRequest {
            capability_b64: cap,
            namespace: "grpc".into(),
            name: "oversized-response".into(),
            min_tier: "working".into(),
        })
        .await;
    let err = match result {
        Ok(_) => panic!("oversized gRPC response must fail before client receives entry"),
        Err(err) => err,
    };

    assert_eq!(err.code(), tonic::Code::OutOfRange);
    drop(client);
    h.shutdown().await;
}

#[tokio::test]
async fn grpc_key_scoped_requests_reject_empty_logical_key() {
    let h = TestHarness::new().await;
    let cap = mnemed::cap_to_b64(&h.agent_cap).expect("cap b64");
    let mut client = MemoryServiceClient::connect(h.grpc_endpoint())
        .await
        .expect("connect");

    let remember_err = client
        .remember(RememberRequest {
            capability_b64: cap.clone(),
            namespace: "   ".into(),
            name: "note".into(),
            kind: "semantic".into(),
            body: b"invalid".to_vec(),
        })
        .await
        .expect_err("empty namespace must fail before remember");
    assert_eq!(remember_err.code(), tonic::Code::InvalidArgument);

    let recall_err = client
        .recall(RecallRequest {
            capability_b64: cap.clone(),
            namespace: "grpc".into(),
            name: " ".into(),
            min_tier: "working".into(),
        })
        .await
        .expect_err("empty name must fail before recall");
    assert_eq!(recall_err.code(), tonic::Code::InvalidArgument);

    let forget_err = client
        .forget(ForgetRequest {
            capability_b64: cap.clone(),
            namespace: "".into(),
            name: "note".into(),
        })
        .await
        .expect_err("empty namespace must fail before forget");
    assert_eq!(forget_err.code(), tonic::Code::InvalidArgument);

    let prove_absent_err = client
        .prove_absent(ProveAbsentRequest {
            capability_b64: cap,
            namespace: "grpc".into(),
            name: "".into(),
        })
        .await
        .expect_err("empty name must fail before prove-absent");
    assert_eq!(prove_absent_err.code(), tonic::Code::InvalidArgument);
    drop(client);
    h.shutdown().await;
}

#[tokio::test]
async fn grpc_prove_absent_requires_capability() {
    let h = TestHarness::new().await;
    let mut client = MemoryServiceClient::connect(h.grpc_endpoint())
        .await
        .expect("connect");

    let err = client
        .prove_absent(ProveAbsentRequest {
            namespace: "grpc".into(),
            name: "never-seen".into(),
            capability_b64: String::new(),
        })
        .await
        .expect_err("unauthenticated prove-absent must fail closed");

    assert_eq!(err.code(), tonic::Code::Unauthenticated);

    let resp = client
        .prove_absent(ProveAbsentRequest {
            namespace: "grpc".into(),
            name: "never-seen".into(),
            capability_b64: mnemed::cap_to_b64(&h.agent_cap).expect("cap b64"),
        })
        .await
        .expect("authenticated prove absent")
        .into_inner();
    assert!(resp.absent);
    assert!(!resp.root_hash_hex.is_empty());
    drop(client);
    h.shutdown().await;
}
