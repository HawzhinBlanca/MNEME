//! HTTP REST kernel API (blueprint §14 adoption layer transport).

use crate::state::{ApiError, AppState, capability_from_header, check_rate_limit, verify_cap};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use mneme_cap::Capability;
use mneme_core::ObjectId;
use mneme_core::{Draft, ForgetMode, ForgetTarget, LogicalKey, MemoryKind, Query, TrustTier};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (
            status,
            Json(ErrorBody {
                code: self.code,
                message: self.message,
            }),
        )
            .into_response()
    }
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    root_sequence: u64,
}

#[derive(Serialize)]
struct HeadResponse {
    root_hash_hex: String,
    sequence: u64,
    dag_head_root_hex: String,
    key_index_root_hex: String,
}

#[derive(Deserialize)]
struct RememberBody {
    namespace: String,
    name: String,
    kind: String,
    body: String,
}

#[derive(Serialize)]
struct RememberResponse {
    object_id_hex: String,
    root_hash_hex: String,
}

#[derive(Serialize)]
struct RecallResponse {
    entries: Vec<RecallEntryJson>,
}

#[derive(Serialize)]
struct RecallEntryJson {
    object_id_hex: String,
    body: String,
    trust_tier: u8,
}

#[derive(Serialize)]
struct ForgetResponse {
    root_hash_hex: String,
}

#[derive(Serialize)]
struct ProveAbsentResponse {
    root_hash_hex: String,
    absent: bool,
}

#[derive(Deserialize)]
struct PromoteBody {
    object_id_hex: String,
    to_tier: String,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/head", get(head))
        .route("/v1/memory", post(remember))
        .route("/v1/memory/{namespace}/{name}", get(recall))
        .route("/v1/memory/{namespace}/{name}", delete(forget))
        .route("/v1/memory/promote", post(promote))
        .route("/v1/prove-absent/{namespace}/{name}", get(prove_absent))
        .route("/v1/auth/verify", post(auth_verify))
        .with_state(state)
}

async fn health(State(state): State<AppState>) -> Result<Json<HealthResponse>, ApiError> {
    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock poisoned"))?;
    let root = store.current_root();
    Ok(Json(HealthResponse {
        status: "ok",
        root_sequence: root.sequence,
    }))
}

async fn head(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<HeadResponse>, ApiError> {
    let cap = auth_cap(&headers)?;
    check_rate_limit(&state, &cap)?;
    verify_cap(&state, &cap)?;
    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock poisoned"))?;
    let root = store.current_root();
    Ok(Json(HeadResponse {
        root_hash_hex: hex::encode(root.preimage_hash),
        sequence: root.sequence,
        dag_head_root_hex: hex::encode(root.dag_head_root),
        key_index_root_hex: hex::encode(root.key_index_root),
    }))
}

async fn remember(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RememberBody>,
) -> Result<Json<RememberResponse>, ApiError> {
    let cap = auth_cap(&headers)?;
    check_rate_limit(&state, &cap)?;
    verify_cap(&state, &cap)?;
    if body.namespace.trim().is_empty() || body.name.trim().is_empty() {
        return Err(ApiError::bad_request("namespace and name required"));
    }
    let kind = parse_kind(&body.kind)?;
    let mut store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock poisoned"))?;
    let draft = Draft {
        namespace: body.namespace,
        logical_name: body.name,
        kind,
        body: body.body.into_bytes(),
        parent_ids: vec![],
        session: [0xab; 16],
        trust_tier: None,
        embedding: None,
    };
    let (id, root) = store.remember(draft, &cap).map_err(ApiError::from_mneme)?;
    Ok(Json(RememberResponse {
        object_id_hex: hex::encode(id.as_bytes()),
        root_hash_hex: hex::encode(root.preimage_hash),
    }))
}

async fn recall(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((namespace, name)): Path<(String, String)>,
    axum::extract::Query(params): axum::extract::Query<RecallParams>,
) -> Result<Json<RecallResponse>, ApiError> {
    let cap = auth_cap(&headers)?;
    check_rate_limit(&state, &cap)?;
    verify_cap(&state, &cap)?;
    let min_tier = parse_tier(params.min_tier.as_deref().unwrap_or("working"))?;
    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock poisoned"))?;
    let query = Query {
        logical_key: LogicalKey { namespace, name },
        min_tier,
        embedding: None,
    };
    let entries = store
        .recall_verified_default(&query, &cap)
        .map_err(ApiError::from_mneme)?;
    Ok(Json(RecallResponse {
        entries: entries
            .into_iter()
            .map(|e| RecallEntryJson {
                object_id_hex: hex::encode(e.id.as_bytes()),
                body: String::from_utf8_lossy(&e.plaintext).into_owned(),
                trust_tier: e.record.trust_tier,
            })
            .collect(),
    }))
}

#[derive(Deserialize)]
struct RecallParams {
    min_tier: Option<String>,
}

async fn forget(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((namespace, name)): Path<(String, String)>,
) -> Result<Json<ForgetResponse>, ApiError> {
    let cap = auth_cap(&headers)?;
    check_rate_limit(&state, &cap)?;
    verify_cap(&state, &cap)?;
    let mut store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock poisoned"))?;
    let (_tomb, root) = store
        .forget(
            ForgetTarget::LogicalKey(LogicalKey { namespace, name }),
            &cap,
            ForgetMode::Shred,
        )
        .map_err(ApiError::from_mneme)?;
    Ok(Json(ForgetResponse {
        root_hash_hex: hex::encode(root.preimage_hash),
    }))
}

async fn promote(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PromoteBody>,
) -> Result<Json<HeadResponse>, ApiError> {
    let cap = auth_cap(&headers)?;
    check_rate_limit(&state, &cap)?;
    verify_cap(&state, &cap)?;
    let id_bytes = hex::decode(body.object_id_hex.trim())
        .map_err(|_| ApiError::bad_request("invalid object_id_hex"))?;
    let mut id_arr = [0u8; 32];
    if id_bytes.len() != 32 {
        return Err(ApiError::bad_request("object_id must be 32 bytes"));
    }
    id_arr.copy_from_slice(&id_bytes);
    let to = parse_tier(&body.to_tier)?;
    let mut store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock poisoned"))?;
    let root = store
        .promote(&ObjectId(id_arr), to, &cap)
        .map_err(ApiError::from_mneme)?;
    Ok(Json(HeadResponse {
        root_hash_hex: hex::encode(root.preimage_hash),
        sequence: root.sequence,
        dag_head_root_hex: hex::encode(root.dag_head_root),
        key_index_root_hex: hex::encode(root.key_index_root),
    }))
}

async fn prove_absent(
    State(state): State<AppState>,
    Path((namespace, name)): Path<(String, String)>,
) -> Result<Json<ProveAbsentResponse>, ApiError> {
    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock poisoned"))?;
    let key = LogicalKey { namespace, name };
    let proof = store.prove_absent(&key).map_err(ApiError::from_mneme)?;
    let root = store.current_root();
    Ok(Json(ProveAbsentResponse {
        root_hash_hex: hex::encode(proof.root),
        absent: proof.root == root.key_index_root,
    }))
}

#[derive(Deserialize)]
struct AuthVerifyBody {
    capability_b64: String,
}

#[derive(Serialize)]
struct AuthVerifyResponse {
    valid: bool,
    subject_hex: String,
    tier_max: u8,
}

async fn auth_verify(
    State(state): State<AppState>,
    Json(body): Json<AuthVerifyBody>,
) -> Result<Json<AuthVerifyResponse>, ApiError> {
    let cap = parse_capability_b64(&body.capability_b64)?;
    verify_cap(&state, &cap)?;
    Ok(Json(AuthVerifyResponse {
        valid: true,
        subject_hex: hex::encode(cap.subject),
        tier_max: cap.tier_max,
    }))
}

fn auth_cap(headers: &HeaderMap) -> Result<Capability, ApiError> {
    let value = headers
        .get("authorization")
        .or_else(|| headers.get("Authorization"))
        .ok_or_else(|| ApiError::bad_auth("missing Authorization header"))?
        .to_str()
        .map_err(|_| ApiError::bad_auth("invalid Authorization header"))?;
    capability_from_header(value)
}

fn parse_kind(s: &str) -> Result<MemoryKind, ApiError> {
    match s.to_lowercase().as_str() {
        "episodic" => Ok(MemoryKind::Episodic),
        "semantic" => Ok(MemoryKind::Semantic),
        "procedural" => Ok(MemoryKind::Procedural),
        "working" => Ok(MemoryKind::Working),
        "identity" => Ok(MemoryKind::Identity),
        _ => Err(ApiError::bad_request("invalid memory kind")),
    }
}

fn parse_tier(s: &str) -> Result<TrustTier, ApiError> {
    TrustTier::from_u8(match s.to_lowercase().as_str() {
        "quarantine" => 0,
        "working" => 1,
        "trusted" => 2,
        "identity" => 3,
        _ => return Err(ApiError::bad_request("invalid trust tier")),
    })
    .map_err(ApiError::from_mneme)
}

use crate::state::parse_capability_b64;
