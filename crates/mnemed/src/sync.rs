//! Sync protocol WebSocket surface (blueprint §11 wire format).
//!
//! Two anti-entropy dialects share this endpoint:
//!
//! * The **canonical §11 [`SyncMessage`] protocol** (blueprint tags `0x03 DiffReq`,
//!   `0x04 DiffResp`, `0x05 WantObjects`, `0x06 HaveObjects`), framed by the shared
//!   `mneme-crdt` codec ([`encode_sync_message`]/[`decode_sync_message`]). This is the
//!   cross-host object-transfer protocol: a requester diffs MST roots, fetches only the
//!   object delta it lacks, re-hashes every received object (INV-1 / A-NET) and merges
//!   through the verified CRDT path. Implemented by [`handle_diff_req`] /
//!   [`handle_want_objects`] (server) and the `encode_diff_request` / `decode_diff_response`
//!   / `encode_want_objects_canonical` / `decode_have_objects_canonical` client helpers.
//! * A pre-existing snapshot/manifest dialect (tags `0x10`–`0x15`) kept for back-compat.
//!
//! Neither dialect can cause a write that bypasses the kernel's verified merge: every
//! ingested object is re-hashed and its writer re-authorized inside `apply_peer_snapshot`.

use crate::state::{
    ApiError, AppState, capability_from_header, check_rate_limit, parse_capability_b64, verify_cap,
};
use axum::{
    Router,
    extract::{
        Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::HeaderMap,
    response::IntoResponse,
    routing::get,
};
use mneme_cap::Capability;
use mneme_core::{MnemeError, SyncMessage, TrustTier, hash_obj};
use mneme_crdt::{decode_sync_message, encode_sync_message};
use mneme_smt::TOMBSTONE;
use mneme_store::SyncSnapshot;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::{HashMap, HashSet};

pub const SYNC_MAX_FRAME: usize = 4 * 1024 * 1024;
const MSG_HELLO: u8 = 0x01;
const MSG_ROOT_PROOF: u8 = 0x02;
/// §11 canonical: MST-diff request (peer announces its local key-index root).
const MSG_DIFF_REQ: u8 = SyncMessage::DIFF_REQ;
/// §11 canonical: object-delta request (`WantObjects { ids }`).
const MSG_WANT_OBJECTS_V11: u8 = SyncMessage::WANT_OBJECTS;
const MSG_BYE: u8 = 0x07;
/// §11 anti-entropy: peer requests this node's authenticated structure snapshot.
pub const MSG_SNAPSHOT_REQ: u8 = 0x10;
/// §11 anti-entropy: CBOR-serialized [`mneme_store::SyncSnapshot`] response.
pub const MSG_SNAPSHOT: u8 = 0x11;
/// §11 INCREMENTAL anti-entropy: peer requests the structure manifest (no bytes).
pub const MSG_MANIFEST_REQ: u8 = 0x12;
/// CBOR-serialized [`mneme_store::SyncManifest`] response.
pub const MSG_MANIFEST: u8 = 0x13;
/// Peer requests a delta of object bytes by id (CBOR `Vec<[u8;32]>`).
pub const MSG_WANT_OBJECTS: u8 = 0x14;
/// Delta of object bytes (CBOR `Vec<Vec<u8>>`).
pub const MSG_HAVE_OBJECTS: u8 = 0x15;

#[derive(Serialize, Deserialize)]
struct Hello {
    proto_ver: u16,
    node_id: [u8; 16],
    head_root: [u8; 32],
    head_sig: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct RootProof {
    root_hash: [u8; 32],
    sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SyncFrameError {
    #[error("canonical sync message encode failed: {0}")]
    CanonicalEncode(MnemeError),
    #[error("canonical sync message decode failed: {0}")]
    CanonicalDecode(MnemeError),
    #[error("sync frame carried an unexpected canonical message type")]
    UnexpectedMessageType,
    #[error("sync frame tag mismatch: expected 0x{expected:02x}, got 0x{got:02x}")]
    UnexpectedTag { expected: u8, got: u8 },
    #[error("empty sync frame; expected tag 0x{expected:02x}")]
    EmptyFrame { expected: u8 },
    #[error("tagged CBOR sync frame encode failed")]
    TaggedCborEncode,
    #[error("tagged CBOR sync frame decode failed")]
    TaggedCborDecode,
    #[error("canonical sync object tampered (content hash mismatch)")]
    ObjectTampered,
    #[error("sync store lock unavailable")]
    StoreUnavailable,
    #[error("sync root unavailable: {0}")]
    RootUnavailable(MnemeError),
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/sync", get(ws_handler))
        .with_state(state)
}

#[derive(Default, Deserialize)]
struct SyncAuthQuery {
    cap: Option<String>,
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<SyncAuthQuery>,
) -> Result<impl IntoResponse, ApiError> {
    authorize_sync(&state, &headers, &params)?;
    Ok(ws
        .max_message_size(SYNC_MAX_FRAME)
        .max_frame_size(SYNC_MAX_FRAME)
        .on_upgrade(move |socket| handle_sync(socket, state)))
}

fn authorize_sync(
    state: &AppState,
    headers: &HeaderMap,
    params: &SyncAuthQuery,
) -> Result<(), ApiError> {
    let cap = sync_cap(headers, params)?;
    check_rate_limit(state, &cap)?;
    verify_cap(state, &cap)?;
    if !cap.permits_read("sync", TrustTier::Quarantine) {
        return Err(ApiError::from_mneme(MnemeError::CapDenied));
    }
    Ok(())
}

fn sync_cap(headers: &HeaderMap, params: &SyncAuthQuery) -> Result<Capability, ApiError> {
    if let Some(cap) = params.cap.as_deref() {
        return parse_capability_b64(cap);
    }
    let value = headers
        .get("authorization")
        .or_else(|| headers.get("Authorization"))
        .ok_or_else(|| ApiError::bad_auth("missing Authorization header"))?
        .to_str()
        .map_err(|_| ApiError::bad_auth("invalid Authorization header"))?;
    capability_from_header(value)
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SyncReceiveStatus {
    Message,
    Closed,
    Failed,
}

enum SyncReceiveOutcome {
    Message(Message),
    Closed,
    Failed,
}

#[cfg(test)]
impl SyncReceiveOutcome {
    fn status(&self) -> SyncReceiveStatus {
        match self {
            SyncReceiveOutcome::Message(_) => SyncReceiveStatus::Message,
            SyncReceiveOutcome::Closed => SyncReceiveStatus::Closed,
            SyncReceiveOutcome::Failed => SyncReceiveStatus::Failed,
        }
    }
}

fn classify_sync_receive(received: Option<Result<Message, axum::Error>>) -> SyncReceiveOutcome {
    match received {
        Some(Ok(msg)) => SyncReceiveOutcome::Message(msg),
        Some(Err(err)) => {
            tracing::debug!("sync websocket receive failed: {err}");
            SyncReceiveOutcome::Failed
        }
        None => SyncReceiveOutcome::Closed,
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SyncSendStatus {
    Sent,
    Failed,
}

enum SyncSendOutcome {
    Sent,
    Failed,
}

#[cfg(test)]
impl SyncSendOutcome {
    fn status(&self) -> SyncSendStatus {
        match self {
            SyncSendOutcome::Sent => SyncSendStatus::Sent,
            SyncSendOutcome::Failed => SyncSendStatus::Failed,
        }
    }
}

fn classify_sync_send(result: Result<(), axum::Error>) -> SyncSendOutcome {
    match result {
        Ok(()) => SyncSendOutcome::Sent,
        Err(err) => {
            tracing::debug!("sync websocket response send failed: {err}");
            SyncSendOutcome::Failed
        }
    }
}

async fn send_sync_response(socket: &mut WebSocket, bytes: Vec<u8>) -> SyncSendOutcome {
    classify_sync_send(socket.send(Message::Binary(bytes.into())).await)
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SyncResponseBuildStatus {
    Response,
    NoResponse,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SyncNoResponseReason {
    ClientBye,
    UnsupportedTag,
    MalformedRequest,
    UnsupportedMessageType,
    StoreUnavailable,
    RootUnavailable,
    EncodeFailed,
}

enum SyncResponseBuildOutcome {
    Response(Vec<u8>),
    NoResponse {
        context: &'static str,
        reason: SyncNoResponseReason,
    },
}

impl SyncResponseBuildOutcome {
    fn into_response(self) -> Option<Vec<u8>> {
        match self {
            SyncResponseBuildOutcome::Response(bytes) => Some(bytes),
            SyncResponseBuildOutcome::NoResponse { context, reason } => {
                if !matches!(reason, SyncNoResponseReason::ClientBye) {
                    tracing::debug!(%context, ?reason, "sync websocket response suppressed");
                }
                None
            }
        }
    }

    #[cfg(test)]
    fn status(&self) -> SyncResponseBuildStatus {
        match self {
            SyncResponseBuildOutcome::Response(_) => SyncResponseBuildStatus::Response,
            SyncResponseBuildOutcome::NoResponse { .. } => SyncResponseBuildStatus::NoResponse,
        }
    }
}

fn sync_no_response(
    context: &'static str,
    reason: SyncNoResponseReason,
) -> SyncResponseBuildOutcome {
    SyncResponseBuildOutcome::NoResponse { context, reason }
}

fn sync_message_response(message: SyncMessage, context: &'static str) -> SyncResponseBuildOutcome {
    match encode_sync_message(&message) {
        Ok(bytes) => SyncResponseBuildOutcome::Response(bytes),
        Err(err) => {
            tracing::debug!("{context}: canonical sync message encode failed: {err:?}");
            sync_no_response(context, SyncNoResponseReason::EncodeFailed)
        }
    }
}

fn sync_tagged_cbor_response<T: Serialize>(
    tag: u8,
    value: &T,
    context: &'static str,
) -> SyncResponseBuildOutcome {
    match encode_tagged_cbor_frame(tag, value) {
        Ok(out) => SyncResponseBuildOutcome::Response(out),
        Err(err) => {
            tracing::debug!("{context}: tagged CBOR response encode failed: {err}");
            sync_no_response(context, SyncNoResponseReason::EncodeFailed)
        }
    }
}

async fn handle_sync(mut socket: WebSocket, state: AppState) {
    loop {
        let msg = match classify_sync_receive(socket.recv().await) {
            SyncReceiveOutcome::Message(msg) => msg,
            SyncReceiveOutcome::Closed | SyncReceiveOutcome::Failed => break,
        };
        match msg {
            Message::Binary(data) => {
                if data.is_empty() {
                    continue;
                }
                if data.len() > SYNC_MAX_FRAME {
                    break;
                }
                let response = match data[0] {
                    MSG_HELLO => handle_hello(&state, &data[1..]).await,
                    // Canonical §11 object-transfer protocol (mneme-crdt codec).
                    MSG_DIFF_REQ => handle_diff_req(&state, &data),
                    MSG_WANT_OBJECTS_V11 => handle_want_objects(&state, &data),
                    MSG_SNAPSHOT_REQ => encode_snapshot(&state),
                    MSG_MANIFEST_REQ => encode_manifest(&state),
                    MSG_WANT_OBJECTS => encode_have_objects(&state, &data[1..]),
                    MSG_BYE => sync_no_response("sync bye frame", SyncNoResponseReason::ClientBye),
                    // Fail closed: an unrecognized tag (incl. server→client RESPONSE
                    // tags replayed by an A-NET probe) gets no reply, not a volunteered
                    // root proof. Real clients use the explicit request tags above.
                    _ => sync_no_response(
                        "sync unknown frame tag",
                        SyncNoResponseReason::UnsupportedTag,
                    ),
                };
                if let Some(bytes) = response.into_response() {
                    match send_sync_response(&mut socket, bytes).await {
                        SyncSendOutcome::Sent => {}
                        SyncSendOutcome::Failed => break,
                    }
                }
                if data[0] == MSG_BYE {
                    break;
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
}

async fn handle_hello(state: &AppState, payload: &[u8]) -> SyncResponseBuildOutcome {
    let _hello: Hello = match ciborium::from_reader(payload) {
        Ok(hello) => hello,
        Err(err) => {
            tracing::debug!("sync hello decode failed: {err}");
            return sync_no_response("sync hello decode", SyncNoResponseReason::MalformedRequest);
        }
    };
    let root = {
        let store = match state.store.lock() {
            Ok(store) => store,
            Err(err) => {
                tracing::debug!("sync hello store lock failed: {err}");
                return sync_no_response(
                    "sync hello store lock",
                    SyncNoResponseReason::StoreUnavailable,
                );
            }
        };
        match store.current_root() {
            Ok(root) => root,
            Err(err) => {
                tracing::debug!("sync hello current root failed: {err:?}");
                return sync_no_response(
                    "sync hello current root",
                    SyncNoResponseReason::RootUnavailable,
                );
            }
        }
    };
    let proof = RootProof {
        root_hash: root.preimage_hash,
        sequence: root.sequence,
    };
    sync_tagged_cbor_response(MSG_ROOT_PROOF, &proof, "sync root proof encode")
}

// --- §11 canonical object-transfer protocol (DiffReq/DiffResp/WantObjects/HaveObjects) ---

/// Self-describing leaf bundle carried inside `HaveObjects { objects }`.
///
/// The frozen [`SyncMessage::HaveObjects`] field is `objects: Vec<Vec<u8>>` of opaque
/// CBOR blobs; the canonical object record alone cannot reconstruct the MST leaf
/// (`key_hash → object_id`) or the logical-key binding (those live outside the object,
/// for payload confidentiality). Each `HaveObjects` blob is therefore the dCBOR of this
/// bundle: the peer's *claimed* `(key_hash, object_id)` leaf, its logical key, and the
/// ciphertext `object` record. The receiver re-hashes `object` and rejects it unless
/// `hash_obj(object) == object_id` (INV-1 / A-NET), so a blob mutated in transit fails
/// closed before it can reach the verified merge.
#[derive(Serialize, Deserialize)]
struct LeafBundle {
    key_hash: [u8; 32],
    object_id: [u8; 32],
    namespace: String,
    name: String,
    object: Vec<u8>,
}

/// Answer `DiffReq { mst_root_local }` with `DiffResp { divergent_subtree_summaries }`.
///
/// Coarse (single-level) MST diff: when the requester's key-index root already equals
/// ours the summary set is empty (converged fast-path); otherwise we return the object
/// ids backing our live leaves so the requester can subtract what it already holds and
/// fetch only the delta. `depth_hint` is accepted and reserved for future recursive
/// subtree narrowing.
fn handle_diff_req(state: &AppState, frame: &[u8]) -> SyncResponseBuildOutcome {
    let mst_root_local = match decode_sync_message(frame) {
        Ok(SyncMessage::DiffReq { mst_root_local, .. }) => mst_root_local,
        Ok(_) => {
            return sync_no_response(
                "sync diff request message type",
                SyncNoResponseReason::UnsupportedMessageType,
            );
        }
        Err(err) => {
            tracing::debug!("sync diff request decode failed: {err:?}");
            return sync_no_response(
                "sync diff request decode",
                SyncNoResponseReason::MalformedRequest,
            );
        }
    };
    let (root, snapshot) = {
        let store = match state.store.lock() {
            Ok(store) => store,
            Err(err) => {
                tracing::debug!("sync diff request store lock failed: {err}");
                return sync_no_response(
                    "sync diff request store lock",
                    SyncNoResponseReason::StoreUnavailable,
                );
            }
        };
        let root = match store.current_root() {
            Ok(root) => root,
            Err(err) => {
                tracing::debug!("sync diff request current root failed: {err:?}");
                return sync_no_response(
                    "sync diff request current root",
                    SyncNoResponseReason::RootUnavailable,
                );
            }
        };
        (root, store.export_sync_snapshot())
    };
    let summaries: Vec<[u8; 32]> = if mst_root_local == root.key_index_root {
        Vec::new()
    } else {
        let mut seen = HashSet::new();
        snapshot
            .leaves
            .iter()
            .map(|(_key_hash, object_id)| *object_id)
            .filter(|object_id| *object_id != TOMBSTONE && seen.insert(*object_id))
            .collect()
    };
    sync_message_response(
        SyncMessage::DiffResp {
            divergent_subtree_summaries: summaries,
        },
        "sync diff response encode",
    )
}

/// Answer `WantObjects { ids }` with `HaveObjects { objects }`: for each requested id
/// that is a live leaf here, emit a [`LeafBundle`] (leaf binding + logical key +
/// ciphertext). Unknown/forgotten ids are skipped — the receiver re-hashes on ingest.
fn handle_want_objects(state: &AppState, frame: &[u8]) -> SyncResponseBuildOutcome {
    let ids = match decode_sync_message(frame) {
        Ok(SyncMessage::WantObjects { ids }) => ids,
        Ok(_) => {
            return sync_no_response(
                "sync want-objects message type",
                SyncNoResponseReason::UnsupportedMessageType,
            );
        }
        Err(err) => {
            tracing::debug!("sync want-objects decode failed: {err:?}");
            return sync_no_response(
                "sync want-objects decode",
                SyncNoResponseReason::MalformedRequest,
            );
        }
    };
    let snapshot = {
        let store = match state.store.lock() {
            Ok(store) => store,
            Err(err) => {
                tracing::debug!("sync want-objects store lock failed: {err}");
                return sync_no_response(
                    "sync want-objects store lock",
                    SyncNoResponseReason::StoreUnavailable,
                );
            }
        };
        store.export_sync_snapshot()
    };

    let want: HashSet<[u8; 32]> = ids.into_iter().collect();
    let object_bytes: HashMap<[u8; 32], &Vec<u8>> =
        snapshot.objects.iter().map(|b| (hash_obj(b), b)).collect();
    let logical_keys: HashMap<[u8; 32], (&str, &str)> = snapshot
        .object_keys
        .iter()
        .map(|(id, ns, name)| (*id, (ns.as_str(), name.as_str())))
        .collect();

    let mut bundles: Vec<Vec<u8>> = Vec::new();
    for (key_hash, object_id) in &snapshot.leaves {
        if *object_id == TOMBSTONE || !want.contains(object_id) {
            continue;
        }
        let (Some(object), Some((namespace, name))) = (
            object_bytes.get(object_id),
            logical_keys.get(object_id).copied(),
        ) else {
            continue;
        };
        let bundle = LeafBundle {
            key_hash: *key_hash,
            object_id: *object_id,
            namespace: namespace.to_string(),
            name: name.to_string(),
            object: (*object).clone(),
        };
        let mut blob = Vec::new();
        if let Err(err) = ciborium::into_writer(&bundle, &mut blob) {
            tracing::debug!("sync have-objects leaf bundle encode failed: {err}");
            return sync_no_response(
                "sync have-objects leaf bundle encode",
                SyncNoResponseReason::EncodeFailed,
            );
        }
        bundles.push(blob);
    }
    sync_message_response(
        SyncMessage::HaveObjects { objects: bundles },
        "sync have-objects encode",
    )
}

/// Build a canonical §11 `DiffReq` frame announcing the local key-index root.
pub fn encode_diff_request(mst_root_local: [u8; 32]) -> Result<Vec<u8>, SyncFrameError> {
    encode_canonical_sync_frame(&SyncMessage::DiffReq {
        mst_root_local,
        depth_hint: 0,
    })
}

/// Decode a `DiffResp` frame into the peer's divergent leaf-object summaries.
pub fn decode_diff_response(frame: &[u8]) -> Result<Vec<[u8; 32]>, SyncFrameError> {
    match decode_canonical_sync_frame(frame)? {
        SyncMessage::DiffResp {
            divergent_subtree_summaries,
        } => Ok(divergent_subtree_summaries),
        _ => Err(SyncFrameError::UnexpectedMessageType),
    }
}

/// Build a canonical §11 `WantObjects` frame requesting the given object ids.
pub fn encode_want_objects_canonical(ids: &[[u8; 32]]) -> Result<Vec<u8>, SyncFrameError> {
    encode_canonical_sync_frame(&SyncMessage::WantObjects { ids: ids.to_vec() })
}

/// Decode a canonical §11 `HaveObjects` frame into a verified [`SyncSnapshot`].
///
/// **Fail-closed (A-NET):** every bundle's object is re-hashed; a blob whose
/// recomputed content hash does not match its claimed `object_id` is rejected
/// with typed tamper rather than silently dropped. The returned snapshot is safe
/// to feed to `Store::merge_from_snapshot`, which re-verifies independently.
pub fn decode_have_objects_canonical(frame: &[u8]) -> Result<SyncSnapshot, SyncFrameError> {
    let objects = match decode_canonical_sync_frame(frame)? {
        SyncMessage::HaveObjects { objects } => objects,
        _ => return Err(SyncFrameError::UnexpectedMessageType),
    };
    let mut snapshot = SyncSnapshot::default();
    for blob in objects {
        let bundle: LeafBundle =
            ciborium::from_reader(blob.as_slice()).map_err(|_| SyncFrameError::TaggedCborDecode)?;
        if hash_obj(&bundle.object) != bundle.object_id {
            return Err(SyncFrameError::ObjectTampered);
        }
        snapshot.leaves.push((bundle.key_hash, bundle.object_id));
        snapshot
            .object_keys
            .push((bundle.object_id, bundle.namespace, bundle.name));
        snapshot.objects.push(bundle.object);
    }
    Ok(snapshot)
}

/// Test-support (A-NET): encode a canonical `HaveObjects` frame from explicit leaf parts.
///
/// `LeafBundle` is private, so adversarial tests cannot otherwise construct a *structurally
/// valid* bundle whose `object` bytes disagree with the claimed `object_id`. This builds one
/// deterministically so the re-hash rejection gate in [`decode_have_objects_canonical`] is
/// exercised directly (rather than via fragile raw-byte surgery on ciphertext, where a flip
/// usually corrupts the inner CBOR integer-array first and trips `SchemaDrift`). It performs
/// no verification and is never invoked on a production path.
#[doc(hidden)]
pub fn encode_have_objects_canonical_for_test(
    key_hash: [u8; 32],
    object_id: [u8; 32],
    namespace: &str,
    name: &str,
    object: &[u8],
) -> Result<Vec<u8>, SyncFrameError> {
    let bundle = LeafBundle {
        key_hash,
        object_id,
        namespace: namespace.to_string(),
        name: name.to_string(),
        object: object.to_vec(),
    };
    let mut blob = Vec::new();
    ciborium::into_writer(&bundle, &mut blob).map_err(|_| SyncFrameError::TaggedCborEncode)?;
    encode_canonical_sync_frame(&SyncMessage::HaveObjects {
        objects: vec![blob],
    })
}

fn encode_canonical_sync_frame(message: &SyncMessage) -> Result<Vec<u8>, SyncFrameError> {
    encode_sync_message(message).map_err(SyncFrameError::CanonicalEncode)
}

fn decode_canonical_sync_frame(frame: &[u8]) -> Result<SyncMessage, SyncFrameError> {
    decode_sync_message(frame).map_err(SyncFrameError::CanonicalDecode)
}

fn encode_tagged_cbor_frame<T: Serialize + ?Sized>(
    tag: u8,
    value: &T,
) -> Result<Vec<u8>, SyncFrameError> {
    let mut body = Vec::new();
    ciborium::into_writer(value, &mut body).map_err(|_| SyncFrameError::TaggedCborEncode)?;
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(tag);
    out.extend(body);
    Ok(out)
}

fn decode_tagged_cbor_frame<T: DeserializeOwned>(
    frame: &[u8],
    expected: u8,
) -> Result<T, SyncFrameError> {
    match frame.split_first() {
        Some((&got, body)) if got == expected => {
            ciborium::from_reader(body).map_err(|_| SyncFrameError::TaggedCborDecode)
        }
        Some((&got, _)) => Err(SyncFrameError::UnexpectedTag { expected, got }),
        None => Err(SyncFrameError::EmptyFrame { expected }),
    }
}

/// Serialize this node's [`mneme_store::SyncSnapshot`] as a `MSG_SNAPSHOT` frame.
fn encode_snapshot(state: &AppState) -> SyncResponseBuildOutcome {
    let store = match state.store.lock() {
        Ok(store) => store,
        Err(err) => {
            tracing::debug!("sync snapshot store lock failed: {err}");
            return sync_no_response(
                "sync snapshot store lock",
                SyncNoResponseReason::StoreUnavailable,
            );
        }
    };
    // B4: serve the sealed snapshot — the vault-key bundle is AEAD-encrypted under the
    // operator channel key, so a same-operator peer recalls plaintext while an A-NET
    // observer or a different-operator peer recovers only the ciphertext objects.
    let snapshot = store.export_sync_snapshot_sealed();
    drop(store);
    sync_tagged_cbor_response(MSG_SNAPSHOT, &snapshot, "sync snapshot encode")
}

/// Build a bare `MSG_SNAPSHOT_REQ` frame (peer/client driver helper).
pub fn encode_snapshot_request() -> Vec<u8> {
    vec![MSG_SNAPSHOT_REQ]
}

/// Decode a `MSG_SNAPSHOT` frame into a [`mneme_store::SyncSnapshot`].
pub fn decode_snapshot(frame: &[u8]) -> Result<mneme_store::SyncSnapshot, SyncFrameError> {
    decode_tagged_cbor_frame(frame, MSG_SNAPSHOT)
}

// --- §11 incremental anti-entropy (manifest + delta) ---

/// Serialize this node's [`mneme_store::SyncManifest`] (structure, no object bytes).
fn encode_manifest(state: &AppState) -> SyncResponseBuildOutcome {
    let store = match state.store.lock() {
        Ok(store) => store,
        Err(err) => {
            tracing::debug!("sync manifest store lock failed: {err}");
            return sync_no_response(
                "sync manifest store lock",
                SyncNoResponseReason::StoreUnavailable,
            );
        }
    };
    let manifest = store.export_sync_manifest();
    drop(store);
    sync_tagged_cbor_response(MSG_MANIFEST, &manifest, "sync manifest encode")
}

/// Answer a `MSG_WANT_OBJECTS` request (CBOR `Vec<[u8;32]>`) with the object bytes
/// this node holds for those ids (`MSG_HAVE_OBJECTS`, CBOR `Vec<Vec<u8>>`).
fn encode_have_objects(state: &AppState, payload: &[u8]) -> SyncResponseBuildOutcome {
    let ids: Vec<[u8; 32]> = match ciborium::from_reader(payload) {
        Ok(ids) => ids,
        Err(err) => {
            tracing::debug!("sync legacy want-objects decode failed: {err}");
            return sync_no_response(
                "sync legacy want-objects decode",
                SyncNoResponseReason::MalformedRequest,
            );
        }
    };
    let objects = {
        let store = match state.store.lock() {
            Ok(store) => store,
            Err(err) => {
                tracing::debug!("sync legacy have-objects store lock failed: {err}");
                return sync_no_response(
                    "sync legacy have-objects store lock",
                    SyncNoResponseReason::StoreUnavailable,
                );
            }
        };
        store.export_objects(&ids)
    };
    sync_tagged_cbor_response(
        MSG_HAVE_OBJECTS,
        &objects,
        "sync legacy have-objects encode",
    )
}

/// Bare `MSG_MANIFEST_REQ` frame (client driver helper).
pub fn encode_manifest_request() -> Vec<u8> {
    vec![MSG_MANIFEST_REQ]
}

/// Decode a `MSG_MANIFEST` frame into a [`mneme_store::SyncManifest`].
pub fn decode_manifest(frame: &[u8]) -> Result<mneme_store::SyncManifest, SyncFrameError> {
    decode_tagged_cbor_frame(frame, MSG_MANIFEST)
}

/// Build a `MSG_WANT_OBJECTS` frame requesting the given object ids.
pub fn encode_want_objects(ids: &[[u8; 32]]) -> Result<Vec<u8>, SyncFrameError> {
    encode_tagged_cbor_frame(MSG_WANT_OBJECTS, ids)
}

/// Decode a `MSG_HAVE_OBJECTS` frame into the delta object byte vectors.
pub fn decode_have_objects(frame: &[u8]) -> Result<Vec<Vec<u8>>, SyncFrameError> {
    decode_tagged_cbor_frame(frame, MSG_HAVE_OBJECTS)
}

pub fn encode_hello(state: &AppState, node_id: [u8; 16]) -> Result<Vec<u8>, SyncFrameError> {
    let root = {
        let store = state
            .store
            .lock()
            .map_err(|_| SyncFrameError::StoreUnavailable)?;
        store
            .current_root()
            .map_err(SyncFrameError::RootUnavailable)?
    };
    let hello = Hello {
        proto_ver: 1,
        node_id,
        head_root: root.preimage_hash,
        head_sig: root.signature.clone(),
    };
    encode_tagged_cbor_frame(MSG_HELLO, &hello)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_receive_classifier_marks_clean_close() {
        assert_eq!(
            classify_sync_receive(None).status(),
            SyncReceiveStatus::Closed
        );
    }

    #[test]
    fn sync_receive_classifier_preserves_messages() {
        let outcome = classify_sync_receive(Some(Ok(Message::Close(None))));

        assert_eq!(outcome.status(), SyncReceiveStatus::Message);
        assert!(matches!(
            outcome,
            SyncReceiveOutcome::Message(Message::Close(None))
        ));
    }

    #[test]
    fn sync_send_classifier_marks_success() {
        assert_eq!(classify_sync_send(Ok(())).status(), SyncSendStatus::Sent);
    }

    #[test]
    fn sync_send_outcome_status_marks_failure() {
        assert_eq!(SyncSendOutcome::Failed.status(), SyncSendStatus::Failed);
    }

    #[test]
    fn sync_response_build_outcome_preserves_response_bytes() {
        let response = SyncResponseBuildOutcome::Response(vec![MSG_ROOT_PROOF, 0xaa]);

        assert_eq!(response.status(), SyncResponseBuildStatus::Response);
        assert_eq!(response.into_response(), Some(vec![MSG_ROOT_PROOF, 0xaa]));
    }

    #[test]
    fn sync_response_build_outcome_preserves_no_response_reason() {
        let response = sync_no_response(
            "test malformed frame",
            SyncNoResponseReason::MalformedRequest,
        );

        assert_eq!(response.status(), SyncResponseBuildStatus::NoResponse);
        assert!(response.into_response().is_none());
    }

    #[test]
    fn sync_frame_decode_diff_response_preserves_unexpected_message_type() {
        let frame = match encode_sync_message(&SyncMessage::Bye) {
            Ok(frame) => frame,
            Err(err) => panic!("test Bye frame encode failed: {err:?}"),
        };
        let err = match decode_diff_response(&frame) {
            Ok(_) => panic!("Bye frame unexpectedly decoded as DiffResp"),
            Err(err) => err,
        };

        assert_eq!(err, SyncFrameError::UnexpectedMessageType);
    }

    #[test]
    fn sync_frame_decode_manifest_preserves_unexpected_tag() {
        let err = match decode_manifest(&[MSG_HAVE_OBJECTS]) {
            Ok(_) => panic!("HaveObjects tag unexpectedly decoded as manifest"),
            Err(err) => err,
        };

        assert_eq!(
            err,
            SyncFrameError::UnexpectedTag {
                expected: MSG_MANIFEST,
                got: MSG_HAVE_OBJECTS,
            }
        );
    }

    #[test]
    fn sync_frame_decode_have_objects_canonical_preserves_unexpected_message_type() {
        let frame = match encode_sync_message(&SyncMessage::Bye) {
            Ok(frame) => frame,
            Err(err) => panic!("test Bye frame encode failed: {err:?}"),
        };
        let err = match decode_have_objects_canonical(&frame) {
            Ok(_) => panic!("Bye frame unexpectedly decoded as canonical HaveObjects"),
            Err(err) => err,
        };

        assert_eq!(err, SyncFrameError::UnexpectedMessageType);
    }

    #[test]
    fn sync_frame_decode_have_objects_canonical_preserves_bundle_decode_failure() {
        let frame = match encode_sync_message(&SyncMessage::HaveObjects {
            objects: vec![vec![0xff]],
        }) {
            Ok(frame) => frame,
            Err(err) => panic!("malformed-bundle frame encode failed: {err:?}"),
        };
        let err = match decode_have_objects_canonical(&frame) {
            Ok(_) => panic!("malformed bundle unexpectedly decoded as canonical HaveObjects"),
            Err(err) => err,
        };

        assert_eq!(err, SyncFrameError::TaggedCborDecode);
    }
}
