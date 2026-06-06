//! gRPC MemoryService (tonic) mirroring HTTP kernel API.

use crate::state::{ApiError, AppState, check_rate_limit, parse_capability_b64, verify_cap};
use mneme_core::{Draft, ForgetMode, ForgetTarget, LogicalKey, MemoryKind, Query, TrustTier};
use tonic::{Request, Response, Status};

pub mod pb {
    tonic::include_proto!("mneme.v1");
}

use pb::memory_service_server::{MemoryService, MemoryServiceServer};
use pb::{
    ForgetRequest, ForgetResponse, HeadRequest, HeadResponse, HealthRequest, HealthResponse,
    ProveAbsentRequest, ProveAbsentResponse, RecallEntry, RecallRequest, RecallResponse,
    RememberRequest, RememberResponse,
};

pub const GRPC_MAX_MESSAGE_BYTES: usize = 1024 * 1024;

pub fn service(state: AppState) -> MemoryServiceServer<GrpcMemoryService> {
    MemoryServiceServer::new(GrpcMemoryService { state })
        .max_decoding_message_size(GRPC_MAX_MESSAGE_BYTES)
        .max_encoding_message_size(GRPC_MAX_MESSAGE_BYTES)
}

pub struct GrpcMemoryService {
    state: AppState,
}

#[tonic::async_trait]
impl MemoryService for GrpcMemoryService {
    async fn health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        let store = self.state.store.lock().map_err(grpc_internal)?;
        Ok(Response::new(HealthResponse {
            status: "ok".into(),
            root_sequence: store.current_root().map_err(grpc_status_mneme)?.sequence,
        }))
    }

    async fn head(&self, request: Request<HeadRequest>) -> Result<Response<HeadResponse>, Status> {
        let req = request.into_inner();
        let cap = parse_capability_b64(&req.capability_b64).map_err(grpc_status)?;
        check_rate_limit(&self.state, &cap).map_err(grpc_status)?;
        verify_cap(&self.state, &cap).map_err(grpc_status)?;
        let store = self.state.store.lock().map_err(grpc_internal)?;
        let root = store.current_root().map_err(grpc_status_mneme)?;
        Ok(Response::new(HeadResponse {
            root_hash_hex: hex::encode(root.preimage_hash),
            sequence: root.sequence,
        }))
    }

    async fn remember(
        &self,
        request: Request<RememberRequest>,
    ) -> Result<Response<RememberResponse>, Status> {
        let req = request.into_inner();
        let cap = parse_capability_b64(&req.capability_b64).map_err(grpc_status)?;
        check_rate_limit(&self.state, &cap).map_err(grpc_status)?;
        verify_cap(&self.state, &cap).map_err(grpc_status)?;
        validate_logical_key_grpc(&req.namespace, &req.name)?;
        let kind = parse_kind_grpc(&req.kind)?;
        let mut store = self.state.store.lock().map_err(grpc_internal)?;
        let draft = Draft {
            namespace: req.namespace,
            logical_name: req.name,
            kind,
            body: req.body,
            parent_ids: vec![],
            session: [0xcd; 16],
            trust_tier: None,
            embedding: None,
            valid_time_ms: None,
        };
        let (id, root) = store.remember(draft, &cap).map_err(grpc_status_mneme)?;
        Ok(Response::new(RememberResponse {
            object_id_hex: hex::encode(id.as_bytes()),
            root_hash_hex: hex::encode(root.preimage_hash),
        }))
    }

    async fn recall(
        &self,
        request: Request<RecallRequest>,
    ) -> Result<Response<RecallResponse>, Status> {
        let req = request.into_inner();
        let cap = parse_capability_b64(&req.capability_b64).map_err(grpc_status)?;
        check_rate_limit(&self.state, &cap).map_err(grpc_status)?;
        verify_cap(&self.state, &cap).map_err(grpc_status)?;
        validate_logical_key_grpc(&req.namespace, &req.name)?;
        let min_tier = parse_tier_grpc(&req.min_tier)?;
        let store = self.state.store.lock().map_err(grpc_internal)?;
        let query = Query {
            logical_key: LogicalKey {
                namespace: req.namespace,
                name: req.name,
            },
            min_tier,
            embedding: None,
        };
        let entries = store
            .recall_verified_default(&query, &cap)
            .map_err(grpc_status_mneme)?;
        Ok(Response::new(RecallResponse {
            entries: entries
                .into_iter()
                .map(|e| RecallEntry {
                    object_id_hex: hex::encode(e.id.as_bytes()),
                    body: e.plaintext,
                    trust_tier: e.record.trust_tier as u32,
                })
                .collect(),
        }))
    }

    async fn forget(
        &self,
        request: Request<ForgetRequest>,
    ) -> Result<Response<ForgetResponse>, Status> {
        let req = request.into_inner();
        let cap = parse_capability_b64(&req.capability_b64).map_err(grpc_status)?;
        check_rate_limit(&self.state, &cap).map_err(grpc_status)?;
        verify_cap(&self.state, &cap).map_err(grpc_status)?;
        validate_logical_key_grpc(&req.namespace, &req.name)?;
        let mut store = self.state.store.lock().map_err(grpc_internal)?;
        let (_tomb, root) = store
            .forget(
                ForgetTarget::LogicalKey(LogicalKey {
                    namespace: req.namespace,
                    name: req.name,
                }),
                &cap,
                ForgetMode::Shred,
            )
            .map_err(grpc_status_mneme)?;
        Ok(Response::new(ForgetResponse {
            root_hash_hex: hex::encode(root.preimage_hash),
        }))
    }

    async fn prove_absent(
        &self,
        request: Request<ProveAbsentRequest>,
    ) -> Result<Response<ProveAbsentResponse>, Status> {
        let req = request.into_inner();
        if req.capability_b64.trim().is_empty() {
            return Err(Status::unauthenticated("missing capability"));
        }
        let cap = parse_capability_b64(&req.capability_b64).map_err(grpc_status)?;
        check_rate_limit(&self.state, &cap).map_err(grpc_status)?;
        verify_cap(&self.state, &cap).map_err(grpc_status)?;
        validate_logical_key_grpc(&req.namespace, &req.name)?;
        if !cap.permits_read(&req.namespace, TrustTier::Quarantine) {
            return Err(grpc_status_mneme(mneme_core::MnemeError::CapDenied));
        }
        let store = self.state.store.lock().map_err(grpc_internal)?;
        let key = LogicalKey {
            namespace: req.namespace,
            name: req.name,
        };
        let proof = store.prove_absent(&key).map_err(grpc_status_mneme)?;
        Ok(Response::new(ProveAbsentResponse {
            root_hash_hex: hex::encode(proof.root),
            absent: true,
        }))
    }
}

fn grpc_status(err: ApiError) -> Status {
    Status::new(
        match err.status {
            400 => tonic::Code::InvalidArgument,
            401 => tonic::Code::Unauthenticated,
            403 => tonic::Code::PermissionDenied,
            404 => tonic::Code::NotFound,
            410 => tonic::Code::NotFound,
            429 => tonic::Code::ResourceExhausted,
            _ => tonic::Code::Internal,
        },
        err.message,
    )
}

fn grpc_status_mneme(err: mneme_core::MnemeError) -> Status {
    grpc_status(ApiError::from_mneme(err))
}

fn grpc_internal(_: impl std::fmt::Display) -> Status {
    Status::internal("store lock poisoned")
}

fn validate_logical_key_grpc(namespace: &str, name: &str) -> Result<(), Status> {
    if namespace.trim().is_empty() || name.trim().is_empty() {
        return Err(Status::invalid_argument("namespace and name required"));
    }
    Ok(())
}

fn parse_kind_grpc(s: &str) -> Result<MemoryKind, Status> {
    match s.to_lowercase().as_str() {
        "episodic" => Ok(MemoryKind::Episodic),
        "semantic" => Ok(MemoryKind::Semantic),
        "procedural" => Ok(MemoryKind::Procedural),
        "working" => Ok(MemoryKind::Working),
        "identity" => Ok(MemoryKind::Identity),
        _ => Err(Status::invalid_argument("invalid memory kind")),
    }
}

fn parse_tier_grpc(s: &str) -> Result<TrustTier, Status> {
    TrustTier::from_u8(match s.to_lowercase().as_str() {
        "quarantine" => 0,
        "working" => 1,
        "trusted" => 2,
        "identity" => 3,
        _ => return Err(Status::invalid_argument("invalid trust tier")),
    })
    .map_err(grpc_status_mneme)
}

pub async fn serve_grpc(
    state: AppState,
    addr: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tonic::transport::Server::builder()
        .add_service(service(state))
        .serve(addr)
        .await?;
    Ok(())
}

// silence unused Arc if not needed - actually remove Arc import
