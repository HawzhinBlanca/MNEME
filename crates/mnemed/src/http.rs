//! HTTP REST kernel API (blueprint §14 adoption layer transport).

use crate::state::{ApiError, AppState, capability_from_header, check_rate_limit, verify_cap};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use base64::Engine;
use mneme_cap::Capability;
use mneme_core::{
    Draft, Entry, ForgetMode, ForgetTarget, LogicalKey, MemoryKind, Query, Root, TrustTier,
    encode_forget_proof,
};
use mneme_core::{MnemeError, ObjectId};
use serde::{Deserialize, Serialize};

const AUTH_VERIFY_BODY_LIMIT_BYTES: usize = 8 * 1024;
const DEFAULT_RECALL_MIN_TIER: TrustTier = TrustTier::Working;

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    robr_receipt_b64: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    proof_cbor_b64: Option<String>,
}

#[derive(Serialize)]
struct ForgetProofResponse {
    root_hash_hex: String,
    proof_version: u16,
    proof_cbor_b64: String,
    root: SignedRootJson,
}

#[derive(Serialize)]
struct SignedRootJson {
    version: u16,
    preimage_hash_hex: String,
    dag_head_root_hex: String,
    key_index_root_hex: String,
    semantic_commit_hex: String,
    hlc_max_hex: String,
    prev_root_hex: String,
    signature_hex: String,
    sequence: u64,
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
        .route("/v1/forget-proof/{namespace}/{name}", delete(forget_proof))
        .route("/v1/memory/promote", post(promote))
        .route("/v1/prove-absent/{namespace}/{name}", get(prove_absent))
        .route(
            "/v1/auth/verify",
            post(auth_verify).layer(DefaultBodyLimit::max(AUTH_VERIFY_BODY_LIMIT_BYTES)),
        )
        .with_state(state)
}

async fn health(State(state): State<AppState>) -> Result<Json<HealthResponse>, ApiError> {
    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock poisoned"))?;
    let root = store.current_root().map_err(ApiError::from_mneme)?;
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
    let root = store.current_root().map_err(ApiError::from_mneme)?;
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
        valid_time_ms: None,
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
    let min_tier = parse_optional_tier(params.min_tier.as_deref())?;
    // Validate the request shape before doing recall work: an ambiguous half-specified
    // receipt request (some, but not all four, ROBR inputs) is rejected fail-closed.
    let robr_present = [
        params.prompt.is_some(),
        params.weight_measurement_hex.is_some(),
        params.sampling_params.is_some(),
        params.output_token_commit_hex.is_some(),
    ]
    .into_iter()
    .filter(|&p| p)
    .count();
    if robr_present != 0 && robr_present != 4 {
        return Err(ApiError::bad_request(
            "ROBR receipt requires all of prompt, weight_measurement_hex, \
             sampling_params, output_token_commit_hex (or none)",
        ));
    }
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

    let mut robr_receipt_b64 = None;
    if let (Some(prompt), Some(weight_hex), Some(sampling), Some(output_hex)) = (
        &params.prompt,
        &params.weight_measurement_hex,
        &params.sampling_params,
        &params.output_token_commit_hex,
    ) {
        let mut weight = [0u8; 32];
        hex::decode_to_slice(weight_hex, &mut weight)
            .map_err(|_| ApiError::bad_request("invalid weight_measurement_hex"))?;
        let mut output_commit = [0u8; 32];
        hex::decode_to_slice(output_hex, &mut output_commit)
            .map_err(|_| ApiError::bad_request("invalid output_token_commit_hex"))?;

        let mut context_entries = Vec::new();
        for e in &entries {
            context_entries.push((e.id.0, e.plaintext.clone()));
        }
        let receipt_wire = store
            .create_robr_receipt(
                prompt,
                weight,
                sampling.clone(),
                &context_entries,
                output_commit,
            )
            .map_err(ApiError::from_mneme)?;
        use base64::Engine as _;
        robr_receipt_b64 = Some(base64::engine::general_purpose::STANDARD.encode(receipt_wire));
    }

    let entries_json = entries
        .into_iter()
        .map(recall_entry_json)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(RecallResponse {
        entries: entries_json,
        robr_receipt_b64,
    }))
}

#[derive(Deserialize)]
struct RecallParams {
    min_tier: Option<String>,
    prompt: Option<String>,
    weight_measurement_hex: Option<String>,
    sampling_params: Option<String>,
    output_token_commit_hex: Option<String>,
}

#[derive(Deserialize)]
struct ForgetQueryParams {
    emit_proof: Option<bool>,
}

async fn forget(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((namespace, name)): Path<(String, String)>,
    axum::extract::Query(params): axum::extract::Query<ForgetQueryParams>,
) -> Result<Json<ForgetResponse>, ApiError> {
    let cap = auth_cap(&headers)?;
    check_rate_limit(&state, &cap)?;
    verify_cap(&state, &cap)?;
    let mut store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock poisoned"))?;
    let key = LogicalKey { namespace, name };

    let mut proof_cbor_b64 = None;
    let root = if params.emit_proof.unwrap_or(false) {
        let proven = store
            .forget_with_proof(ForgetTarget::LogicalKey(key), &cap, ForgetMode::Shred, None)
            .map_err(ApiError::from_mneme)?;
        let proof_bytes = encode_forget_proof(&proven.proof).map_err(ApiError::from_mneme)?;
        use base64::Engine as _;
        proof_cbor_b64 = Some(base64::engine::general_purpose::STANDARD.encode(proof_bytes));
        proven.root
    } else {
        let (_tomb, root) = store
            .forget(ForgetTarget::LogicalKey(key), &cap, ForgetMode::Shred)
            .map_err(ApiError::from_mneme)?;
        root
    };

    Ok(Json(ForgetResponse {
        root_hash_hex: hex::encode(root.preimage_hash),
        proof_cbor_b64,
    }))
}

async fn forget_proof(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((namespace, name)): Path<(String, String)>,
) -> Result<Json<ForgetProofResponse>, ApiError> {
    let cap = auth_cap(&headers)?;
    check_rate_limit(&state, &cap)?;
    verify_cap(&state, &cap)?;
    let mut store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock poisoned"))?;
    let proven = store
        .forget_with_proof(
            ForgetTarget::LogicalKey(LogicalKey { namespace, name }),
            &cap,
            ForgetMode::Shred,
            None,
        )
        .map_err(ApiError::from_mneme)?;
    let proof_bytes = encode_forget_proof(&proven.proof).map_err(ApiError::from_mneme)?;
    Ok(Json(ForgetProofResponse {
        root_hash_hex: hex::encode(proven.root.preimage_hash),
        proof_version: proven.proof.version,
        proof_cbor_b64: base64::engine::general_purpose::STANDARD.encode(proof_bytes),
        root: SignedRootJson::from_root(&proven.root),
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

impl SignedRootJson {
    fn from_root(root: &Root) -> Self {
        Self {
            version: root.version,
            preimage_hash_hex: hex::encode(root.preimage_hash),
            dag_head_root_hex: hex::encode(root.dag_head_root),
            key_index_root_hex: hex::encode(root.key_index_root),
            semantic_commit_hex: hex::encode(root.semantic_commit),
            hlc_max_hex: hex::encode(root.hlc_max),
            prev_root_hex: hex::encode(root.prev_root),
            signature_hex: hex::encode(&root.signature),
            sequence: root.sequence,
        }
    }
}

async fn prove_absent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((namespace, name)): Path<(String, String)>,
) -> Result<Json<ProveAbsentResponse>, ApiError> {
    let cap = auth_cap(&headers)?;
    check_rate_limit(&state, &cap)?;
    verify_cap(&state, &cap)?;
    if !cap.permits_read(&namespace, TrustTier::Quarantine) {
        return Err(ApiError::from_mneme(MnemeError::CapDenied));
    }
    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock poisoned"))?;
    let key = LogicalKey { namespace, name };
    let proof = store.prove_absent(&key).map_err(ApiError::from_mneme)?;
    let root = store.current_root().map_err(ApiError::from_mneme)?;
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
    check_rate_limit(&state, &cap)?;
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
    match s.to_lowercase().as_str() {
        "quarantine" => Ok(TrustTier::Quarantine),
        "working" => Ok(TrustTier::Working),
        "trusted" => Ok(TrustTier::Trusted),
        "identity" => Ok(TrustTier::Identity),
        _ => Err(ApiError::bad_request("invalid trust tier")),
    }
}

fn parse_optional_tier(s: Option<&str>) -> Result<TrustTier, ApiError> {
    match s {
        Some(tier) => parse_tier(tier),
        None => Ok(DEFAULT_RECALL_MIN_TIER),
    }
}

fn recall_entry_json(entry: Entry) -> Result<RecallEntryJson, ApiError> {
    let trust_tier = TrustTier::from_u8(entry.record.trust_tier).map_err(ApiError::from_mneme)?;
    let body = String::from_utf8(entry.plaintext)
        .map_err(|_| ApiError::from_mneme(MnemeError::SchemaDrift))?;
    Ok(RecallEntryJson {
        object_id_hex: hex::encode(entry.id.as_bytes()),
        body,
        trust_tier: trust_tier.as_u8(),
    })
}

use crate::state::parse_capability_b64;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use mneme_core::{HlcWire, OBJECT_VERSION, ObjectId, ObjectRecord, PayloadEnc};

    fn test_recall_entry_with_trust_tier(trust_tier: u8) -> Entry {
        Entry {
            id: ObjectId::from_bytes([0x11; 32]),
            record: ObjectRecord {
                version: OBJECT_VERSION,
                kind: MemoryKind::Semantic as u8,
                parent_ids: vec![],
                writer: [0x22; 32],
                session: [0x33; 16],
                hlc: HlcWire {
                    wall_ms: 1,
                    counter: 0,
                    node_id: [0x44; 16],
                },
                trust_tier,
                payload_enc: PayloadEnc {
                    alg: 0,
                    key_id: None,
                    nonce: None,
                    body: b"hello".to_vec(),
                },
                embedding_commit: None,
                redaction_slot: None,
                ext: None,
            },
            plaintext: b"hello".to_vec(),
        }
    }

    fn test_recall_entry_with_plaintext(plaintext: Vec<u8>) -> Entry {
        Entry {
            plaintext,
            ..test_recall_entry_with_trust_tier(TrustTier::Working.as_u8())
        }
    }

    #[test]
    fn recall_entry_json_preserves_valid_trust_tier() {
        let entry = test_recall_entry_with_trust_tier(TrustTier::Working.as_u8());
        let json =
            recall_entry_json(entry).unwrap_or_else(|err| panic!("valid tier rejected: {err:?}"));

        assert_eq!(json.body, "hello");
        assert_eq!(json.trust_tier, TrustTier::Working.as_u8());
    }

    #[test]
    fn recall_entry_json_rejects_invalid_trust_tier() {
        let entry = test_recall_entry_with_trust_tier(7);
        let err = match recall_entry_json(entry) {
            Ok(_) => panic!("invalid trust tier unexpectedly serialized"),
            Err(err) => err,
        };

        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.code, "kernel_error");
        assert_eq!(err.message, "schema drift");
    }

    #[test]
    fn recall_entry_json_rejects_non_utf8_plaintext() {
        let entry = test_recall_entry_with_plaintext(vec![0xff, 0xfe]);
        let err = match recall_entry_json(entry) {
            Ok(_) => panic!("invalid UTF-8 plaintext unexpectedly serialized"),
            Err(err) => err,
        };

        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.code, "kernel_error");
        assert_eq!(err.message, "schema drift");
    }
}
