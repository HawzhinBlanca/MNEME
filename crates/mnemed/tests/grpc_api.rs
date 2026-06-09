use super::common::TestHarness;
use mneme_core::{Draft, MemoryKind};
use mnemed::grpc::GRPC_MAX_MESSAGE_BYTES;
use mnemed::pb::memory_service_client::MemoryServiceClient;
use mnemed::pb::{ForgetRequest, HeadRequest, ProveAbsentRequest, RecallRequest, RememberRequest};

async fn connect_grpc_memory_service(
    endpoint: String,
    context: &str,
) -> MemoryServiceClient<tonic::transport::Channel> {
    MemoryServiceClient::connect(endpoint)
        .await
        .unwrap_or_else(|err| panic!("{context}: gRPC connect failed: {err}"))
}

fn expect_grpc_cap_b64(cap: &mneme_cap::Capability, context: &str) -> String {
    mnemed::cap_to_b64(cap)
        .unwrap_or_else(|err| panic!("{context}: gRPC capability encoding failed: {err:?}"))
}

fn expect_grpc_response<T>(
    response: Result<tonic::Response<T>, tonic::Status>,
    context: &str,
) -> T {
    response
        .unwrap_or_else(|err| panic!("{context}: gRPC request failed: {err}"))
        .into_inner()
}

fn expect_grpc_status_error<T>(
    response: Result<tonic::Response<T>, tonic::Status>,
    context: &str,
) -> tonic::Status {
    match response {
        Ok(_) => panic!("{context}: expected gRPC status error"),
        Err(err) => err,
    }
}

fn expect_grpc_store_lock<T, E: std::fmt::Debug>(lock: Result<T, E>, context: &str) -> T {
    lock.unwrap_or_else(|err| panic!("{context}: gRPC store lock failed: {err:?}"))
}

fn seed_oversized_grpc_recall_entry(h: &TestHarness, context: &str) {
    let mut store = expect_grpc_store_lock(h.server.state.store.lock(), context);
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
        .unwrap_or_else(|err| {
            panic!("{context}: oversized gRPC recall entry seed failed: {err:?}")
        });
}

#[tokio::test]
async fn grpc_remember_recall_forget() {
    let h = TestHarness::new().await;
    let mut client =
        connect_grpc_memory_service(h.grpc_endpoint(), "gRPC remember/recall/forget client").await;

    let cap = expect_grpc_cap_b64(&h.agent_cap, "gRPC remember/recall/forget capability");

    let remembered = expect_grpc_response(
        client
            .remember(RememberRequest {
                capability_b64: cap.clone(),
                namespace: "grpc".into(),
                name: "note".into(),
                kind: "semantic".into(),
                body: b"hello grpc".to_vec(),
            })
            .await,
        "gRPC remember",
    );
    assert!(!remembered.object_id_hex.is_empty());

    let recalled = expect_grpc_response(
        client
            .recall(RecallRequest {
                capability_b64: cap.clone(),
                namespace: "grpc".into(),
                name: "note".into(),
                min_tier: "working".into(),
            })
            .await,
        "gRPC recall",
    );
    assert_eq!(recalled.entries.len(), 1);
    assert_eq!(recalled.entries[0].body, b"hello grpc");

    expect_grpc_response(
        client
            .forget(ForgetRequest {
                capability_b64: cap,
                namespace: "grpc".into(),
                name: "note".into(),
            })
            .await,
        "gRPC forget",
    );
    drop(client);
    h.shutdown().await;
}

#[tokio::test]
async fn grpc_health_no_auth() {
    let h = TestHarness::new().await;
    let mut client = connect_grpc_memory_service(h.grpc_endpoint(), "gRPC health client").await;
    let resp = expect_grpc_response(
        client.health(mnemed::pb::HealthRequest {}).await,
        "gRPC health",
    );
    assert_eq!(resp.status, "ok");
    drop(client);
    h.shutdown().await;
}

#[tokio::test]
async fn grpc_malformed_capability_is_unauthenticated_not_internal() {
    let h = TestHarness::new().await;
    let mut client =
        connect_grpc_memory_service(h.grpc_endpoint(), "gRPC malformed capability client").await;

    let err = expect_grpc_status_error(
        client
            .head(HeadRequest {
                capability_b64: "oA==".into(),
            })
            .await,
        "malformed capability must fail closed",
    );

    assert_eq!(err.code(), tonic::Code::Unauthenticated);
    drop(client);
    h.shutdown().await;
}

#[tokio::test]
async fn grpc_oversized_capability_is_rejected_before_decode() {
    let h = TestHarness::new().await;
    let mut client =
        connect_grpc_memory_service(h.grpc_endpoint(), "gRPC oversized capability client").await;

    let err = expect_grpc_status_error(
        client
            .head(HeadRequest {
                capability_b64: "A".repeat(mnemed::state::MAX_CAPABILITY_B64_LEN + 1),
            })
            .await,
        "oversized capability must fail closed",
    );

    assert_eq!(err.code(), tonic::Code::Unauthenticated);
    assert_eq!(err.message(), "capability token too large");
    drop(client);
    h.shutdown().await;
}

#[tokio::test]
async fn grpc_message_limit_rejects_oversized_remember_request() {
    let h = TestHarness::new().await;
    let mut client =
        connect_grpc_memory_service(h.grpc_endpoint(), "gRPC oversized remember client")
            .await
            .max_encoding_message_size(GRPC_MAX_MESSAGE_BYTES * 2);
    let cap = expect_grpc_cap_b64(&h.agent_cap, "gRPC oversized remember capability");

    let err = expect_grpc_status_error(
        client
            .remember(RememberRequest {
                capability_b64: cap,
                namespace: "grpc".into(),
                name: "oversized-request".into(),
                kind: "semantic".into(),
                body: vec![0x41; GRPC_MAX_MESSAGE_BYTES + 1],
            })
            .await,
        "oversized gRPC request must fail before remember",
    );

    assert_eq!(err.code(), tonic::Code::OutOfRange);
    drop(client);
    h.shutdown().await;
}

#[tokio::test]
async fn grpc_message_limit_rejects_oversized_recall_response() {
    let h = TestHarness::new().await;
    seed_oversized_grpc_recall_entry(&h, "gRPC oversized recall response setup");

    let mut client =
        connect_grpc_memory_service(h.grpc_endpoint(), "gRPC oversized recall response client")
            .await
            .max_decoding_message_size(GRPC_MAX_MESSAGE_BYTES * 2);
    let cap = expect_grpc_cap_b64(&h.agent_cap, "gRPC oversized recall response capability");
    let err = expect_grpc_status_error(
        client
            .recall(RecallRequest {
                capability_b64: cap,
                namespace: "grpc".into(),
                name: "oversized-response".into(),
                min_tier: "working".into(),
            })
            .await,
        "oversized gRPC response must fail before client receives entry",
    );

    assert_eq!(err.code(), tonic::Code::OutOfRange);
    drop(client);
    h.shutdown().await;
}

#[tokio::test]
async fn grpc_key_scoped_requests_reject_empty_logical_key() {
    let h = TestHarness::new().await;
    let cap = expect_grpc_cap_b64(&h.agent_cap, "gRPC empty logical key capability");
    let mut client =
        connect_grpc_memory_service(h.grpc_endpoint(), "gRPC empty logical key client").await;

    let remember_err = expect_grpc_status_error(
        client
            .remember(RememberRequest {
                capability_b64: cap.clone(),
                namespace: "   ".into(),
                name: "note".into(),
                kind: "semantic".into(),
                body: b"invalid".to_vec(),
            })
            .await,
        "empty namespace must fail before remember",
    );
    assert_eq!(remember_err.code(), tonic::Code::InvalidArgument);

    let recall_err = expect_grpc_status_error(
        client
            .recall(RecallRequest {
                capability_b64: cap.clone(),
                namespace: "grpc".into(),
                name: " ".into(),
                min_tier: "working".into(),
            })
            .await,
        "empty name must fail before recall",
    );
    assert_eq!(recall_err.code(), tonic::Code::InvalidArgument);

    let forget_err = expect_grpc_status_error(
        client
            .forget(ForgetRequest {
                capability_b64: cap.clone(),
                namespace: "".into(),
                name: "note".into(),
            })
            .await,
        "empty namespace must fail before forget",
    );
    assert_eq!(forget_err.code(), tonic::Code::InvalidArgument);

    let prove_absent_err = expect_grpc_status_error(
        client
            .prove_absent(ProveAbsentRequest {
                capability_b64: cap,
                namespace: "grpc".into(),
                name: "".into(),
            })
            .await,
        "empty name must fail before prove-absent",
    );
    assert_eq!(prove_absent_err.code(), tonic::Code::InvalidArgument);
    drop(client);
    h.shutdown().await;
}

#[tokio::test]
async fn grpc_prove_absent_requires_capability() {
    let h = TestHarness::new().await;
    let mut client =
        connect_grpc_memory_service(h.grpc_endpoint(), "gRPC prove-absent client").await;

    let err = expect_grpc_status_error(
        client
            .prove_absent(ProveAbsentRequest {
                namespace: "grpc".into(),
                name: "never-seen".into(),
                capability_b64: String::new(),
            })
            .await,
        "unauthenticated prove-absent must fail closed",
    );

    assert_eq!(err.code(), tonic::Code::Unauthenticated);

    let cap = expect_grpc_cap_b64(&h.agent_cap, "gRPC prove-absent capability");
    let resp = expect_grpc_response(
        client
            .prove_absent(ProveAbsentRequest {
                namespace: "grpc".into(),
                name: "never-seen".into(),
                capability_b64: cap,
            })
            .await,
        "authenticated gRPC prove-absent",
    );
    assert!(resp.absent);
    assert!(!resp.root_hash_hex.is_empty());
    drop(client);
    h.shutdown().await;
}
