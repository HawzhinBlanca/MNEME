//! Unix domain socket kernel API + §11 sync frames (local-first).

use crate::state::{AppState, capability_from_header};
use mneme_core::{
    Draft, ForgetMode, ForgetTarget, LogicalKey, MemoryKind, MnemeError, Query, SyncMessage,
    TrustTier,
};
use mneme_crdt::{decode_sync_message, encode_sync_message};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

const MAX_FRAME: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum KernelRequest {
    Head {
        cap_b64: String,
    },
    Remember {
        cap_b64: String,
        namespace: String,
        name: String,
        body_b64: String,
    },
    RecallVerified {
        cap_b64: String,
        namespace: String,
        name: String,
    },
    Forget {
        cap_b64: String,
        namespace: String,
        name: String,
        mode: String,
    },
    ProveAbsent {
        namespace: String,
        name: String,
    },
    SyncFrame {
        bytes_b64: String,
    },
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum KernelResponse {
    Ok { payload: serde_json::Value },
    Err { code: String, message: String },
}

pub struct UnixServer {
    path: PathBuf,
    state: AppState,
}

impl UnixServer {
    pub fn new(path: PathBuf, state: AppState) -> Self {
        Self { path, state }
    }

    pub async fn serve(self) -> Result<(), std::io::Error> {
        if self.path.exists() {
            let _ = std::fs::remove_file(&self.path);
        }
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let listener = UnixListener::bind(&self.path)?;
        loop {
            let (stream, _) = listener.accept().await?;
            let state = self.state.clone();
            tokio::spawn(async move {
                let _ = handle_connection(stream, state).await;
            });
        }
    }
}

pub async fn request_json(
    path: &PathBuf,
    req: &KernelRequest,
) -> Result<KernelResponse, std::io::Error> {
    let mut stream = UnixStream::connect(path).await?;
    let frame = serde_json::to_vec(req).map_err(std::io::Error::other)?;
    let len = (frame.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(&frame).await?;
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; resp_len];
    stream.read_exact(&mut buf).await?;
    serde_json::from_slice(&buf).map_err(std::io::Error::other)
}

async fn write_kernel_err(
    stream: &mut UnixStream,
    code: &str,
    message: &str,
) -> Result<(), std::io::Error> {
    let resp = KernelResponse::Err {
        code: code.into(),
        message: message.into(),
    };
    let out = serde_json::to_vec(&resp).unwrap_or_default();
    let frame_len = (out.len() as u32).to_be_bytes();
    stream.write_all(&frame_len).await?;
    stream.write_all(&out).await?;
    Ok(())
}

async fn handle_connection(mut stream: UnixStream, state: AppState) -> Result<(), std::io::Error> {
    let mut len_buf = [0u8; 4];
    if stream.read_exact(&mut len_buf).await.is_err() {
        let _ = write_kernel_err(
            &mut stream,
            "framing",
            "incomplete length header on Unix kernel frame",
        )
        .await;
        return Ok(());
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        let _ = write_kernel_err(
            &mut stream,
            "framing",
            "frame length exceeds MAX_FRAME on Unix kernel API",
        )
        .await;
        return Ok(());
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    let resp = dispatch(&state, &buf);
    let out = serde_json::to_vec(&resp).unwrap_or_default();
    let frame_len = (out.len() as u32).to_be_bytes();
    stream.write_all(&frame_len).await?;
    stream.write_all(&out).await?;
    Ok(())
}

fn dispatch(state: &AppState, frame: &[u8]) -> KernelResponse {
    let req: KernelRequest = match serde_json::from_slice(frame) {
        Ok(r) => r,
        Err(e) => {
            return KernelResponse::Err {
                code: "usage".into(),
                message: e.to_string(),
            };
        }
    };
    match dispatch_inner(state, req) {
        Ok(v) => KernelResponse::Ok { payload: v },
        Err(e) => KernelResponse::Err {
            code: format!("{e:?}"),
            message: e.to_string(),
        },
    }
}

fn dispatch_inner(state: &AppState, req: KernelRequest) -> Result<serde_json::Value, MnemeError> {
    match req {
        KernelRequest::Head { cap_b64 } => head(state, &cap_b64),
        KernelRequest::Remember {
            cap_b64,
            namespace,
            name,
            body_b64,
        } => remember(state, &cap_b64, namespace, name, body_b64),
        KernelRequest::RecallVerified {
            cap_b64,
            namespace,
            name,
        } => recall(state, &cap_b64, namespace, name),
        KernelRequest::Forget {
            cap_b64,
            namespace,
            name,
            mode,
        } => forget(state, &cap_b64, namespace, name, mode),
        KernelRequest::ProveAbsent { namespace, name } => prove_absent(state, namespace, name),
        KernelRequest::SyncFrame { bytes_b64 } => sync_frame(state, bytes_b64),
    }
}

fn cap_from_b64(b64: &str) -> Result<mneme_cap::Capability, MnemeError> {
    capability_from_header(b64).map_err(|_| MnemeError::CapDenied)
}

fn head(state: &AppState, cap_b64: &str) -> Result<serde_json::Value, MnemeError> {
    let cap = cap_from_b64(cap_b64)?;
    let store = state.store.lock().map_err(|_| MnemeError::SchemaDrift)?;
    cap.verify(state.operator.as_ref(), store.current_hlc())?;
    let root = store.current_root()?;
    Ok(serde_json::json!({
        "preimage_hash": hex::encode(root.preimage_hash),
        "sequence": root.sequence,
    }))
}

fn remember(
    state: &AppState,
    cap_b64: &str,
    namespace: String,
    name: String,
    body_b64: String,
) -> Result<serde_json::Value, MnemeError> {
    let cap = cap_from_b64(cap_b64)?;
    let body = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, body_b64.trim())
        .map_err(|_| MnemeError::SchemaDrift)?;
    let mut store = state.store.lock().map_err(|_| MnemeError::SchemaDrift)?;
    let draft = Draft {
        namespace,
        logical_name: name,
        kind: MemoryKind::Episodic,
        body,
        parent_ids: vec![],
        session: [0xab; 16],
        trust_tier: None,
        embedding: None,
    };
    let (id, root) = store.remember(draft, &cap)?;
    Ok(serde_json::json!({
        "object_id": hex::encode(id.as_bytes()),
        "root": hex::encode(root.preimage_hash),
    }))
}

fn recall(
    state: &AppState,
    cap_b64: &str,
    namespace: String,
    name: String,
) -> Result<serde_json::Value, MnemeError> {
    let cap = cap_from_b64(cap_b64)?;
    let store = state.store.lock().map_err(|_| MnemeError::SchemaDrift)?;
    let query = Query {
        logical_key: LogicalKey { namespace, name },
        min_tier: TrustTier::Working,
        embedding: None,
    };
    let entries = store.recall_verified_default(&query, &cap)?;
    Ok(serde_json::json!({ "count": entries.len() }))
}

fn forget(
    state: &AppState,
    cap_b64: &str,
    namespace: String,
    name: String,
    mode: String,
) -> Result<serde_json::Value, MnemeError> {
    let cap = cap_from_b64(cap_b64)?;
    let forget_mode = if mode == "redact" {
        ForgetMode::Redact
    } else {
        ForgetMode::Shred
    };
    let mut store = state.store.lock().map_err(|_| MnemeError::SchemaDrift)?;
    let key = LogicalKey { namespace, name };
    store.forget(ForgetTarget::LogicalKey(key), &cap, forget_mode)?;
    Ok(serde_json::json!({ "forgot": true }))
}

fn prove_absent(
    state: &AppState,
    namespace: String,
    name: String,
) -> Result<serde_json::Value, MnemeError> {
    let store = state.store.lock().map_err(|_| MnemeError::SchemaDrift)?;
    let key = LogicalKey { namespace, name };
    let _proof = store.prove_absent(&key)?;
    Ok(serde_json::json!({ "absent": true }))
}

fn sync_frame(state: &AppState, bytes_b64: String) -> Result<serde_json::Value, MnemeError> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(bytes_b64.trim())
        .map_err(|_| MnemeError::SchemaDrift)?;
    let msg = decode_sync_message(&bytes)?;
    let store = state.store.lock().map_err(|_| MnemeError::SchemaDrift)?;
    let out = match msg {
        SyncMessage::Hello { .. } => {
            let root = store.current_root()?;
            encode_sync_message(&SyncMessage::RootProof {
                root,
                consistency_proof: None,
            })?
        }
        SyncMessage::HaveObjects { .. } => {
            let root = store.current_root()?;
            encode_sync_message(&SyncMessage::RootProof {
                root,
                consistency_proof: None,
            })?
        }
        SyncMessage::Bye => encode_sync_message(&SyncMessage::Bye)?,
        other => encode_sync_message(&other)?,
    };
    Ok(serde_json::json!({
        "sync_bytes_b64": base64::engine::general_purpose::STANDARD.encode(out)
    }))
}
