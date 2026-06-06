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
use serde::{Deserialize, Serialize};
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
                    MSG_BYE => None,
                    // Fail closed: an unrecognized tag (incl. server→client RESPONSE
                    // tags replayed by an A-NET probe) gets no reply, not a volunteered
                    // root proof. Real clients use the explicit request tags above.
                    _ => None,
                };
                if let Some(bytes) = response {
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

async fn handle_hello(state: &AppState, payload: &[u8]) -> Option<Vec<u8>> {
    let _hello: Hello = ciborium::from_reader(payload).ok()?;
    let store = state.store.lock().ok()?;
    let root = store.current_root().ok()?;
    drop(store);
    let proof = RootProof {
        root_hash: root.preimage_hash,
        sequence: root.sequence,
    };
    let mut body = Vec::new();
    ciborium::into_writer(&proof, &mut body).ok()?;
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(MSG_ROOT_PROOF);
    out.extend(body);
    Some(out)
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
fn handle_diff_req(state: &AppState, frame: &[u8]) -> Option<Vec<u8>> {
    let mst_root_local = match decode_sync_message(frame).ok()? {
        SyncMessage::DiffReq { mst_root_local, .. } => mst_root_local,
        _ => return None,
    };
    let store = state.store.lock().ok()?;
    let root = store.current_root().ok()?;
    let snapshot = store.export_sync_snapshot();
    drop(store);
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
    encode_sync_message(&SyncMessage::DiffResp {
        divergent_subtree_summaries: summaries,
    })
    .ok()
}

/// Answer `WantObjects { ids }` with `HaveObjects { objects }`: for each requested id
/// that is a live leaf here, emit a [`LeafBundle`] (leaf binding + logical key +
/// ciphertext). Unknown/forgotten ids are skipped — the receiver re-hashes on ingest.
fn handle_want_objects(state: &AppState, frame: &[u8]) -> Option<Vec<u8>> {
    let ids = match decode_sync_message(frame).ok()? {
        SyncMessage::WantObjects { ids } => ids,
        _ => return None,
    };
    let store = state.store.lock().ok()?;
    let snapshot = store.export_sync_snapshot();
    drop(store);

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
        ciborium::into_writer(&bundle, &mut blob).ok()?;
        bundles.push(blob);
    }
    encode_sync_message(&SyncMessage::HaveObjects { objects: bundles }).ok()
}

/// Build a canonical §11 `DiffReq` frame announcing the local key-index root.
pub fn encode_diff_request(mst_root_local: [u8; 32]) -> Option<Vec<u8>> {
    encode_sync_message(&SyncMessage::DiffReq {
        mst_root_local,
        depth_hint: 0,
    })
    .ok()
}

/// Decode a `DiffResp` frame into the peer's divergent leaf-object summaries.
pub fn decode_diff_response(frame: &[u8]) -> Option<Vec<[u8; 32]>> {
    match decode_sync_message(frame).ok()? {
        SyncMessage::DiffResp {
            divergent_subtree_summaries,
        } => Some(divergent_subtree_summaries),
        _ => None,
    }
}

/// Build a canonical §11 `WantObjects` frame requesting the given object ids.
pub fn encode_want_objects_canonical(ids: &[[u8; 32]]) -> Option<Vec<u8>> {
    encode_sync_message(&SyncMessage::WantObjects { ids: ids.to_vec() }).ok()
}

/// Decode a canonical §11 `HaveObjects` frame into a verified [`SyncSnapshot`].
///
/// **Fail-closed (A-NET):** every bundle's object is re-hashed; a blob whose recomputed
/// content hash does not match its claimed `object_id` is rejected with a typed
/// [`MnemeError::ObjectTampered`] rather than silently dropped. The returned snapshot is
/// safe to feed to `Store::merge_from_snapshot`, which re-verifies independently.
pub fn decode_have_objects_canonical(frame: &[u8]) -> Result<SyncSnapshot, MnemeError> {
    let objects = match decode_sync_message(frame)? {
        SyncMessage::HaveObjects { objects } => objects,
        _ => return Err(MnemeError::SchemaDrift),
    };
    let mut snapshot = SyncSnapshot::default();
    for blob in objects {
        let bundle: LeafBundle =
            ciborium::from_reader(blob.as_slice()).map_err(|_| MnemeError::SchemaDrift)?;
        if hash_obj(&bundle.object) != bundle.object_id {
            return Err(MnemeError::ObjectTampered);
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
) -> Option<Vec<u8>> {
    let bundle = LeafBundle {
        key_hash,
        object_id,
        namespace: namespace.to_string(),
        name: name.to_string(),
        object: object.to_vec(),
    };
    let mut blob = Vec::new();
    ciborium::into_writer(&bundle, &mut blob).ok()?;
    encode_sync_message(&SyncMessage::HaveObjects {
        objects: vec![blob],
    })
    .ok()
}

/// Serialize this node's [`mneme_store::SyncSnapshot`] as a `MSG_SNAPSHOT` frame.
fn encode_snapshot(state: &AppState) -> Option<Vec<u8>> {
    let store = state.store.lock().ok()?;
    // B4: serve the sealed snapshot — the vault-key bundle is AEAD-encrypted under the
    // operator channel key, so a same-operator peer recalls plaintext while an A-NET
    // observer or a different-operator peer recovers only the ciphertext objects.
    let snapshot = store.export_sync_snapshot_sealed();
    drop(store);
    let mut body = Vec::new();
    ciborium::into_writer(&snapshot, &mut body).ok()?;
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(MSG_SNAPSHOT);
    out.extend(body);
    Some(out)
}

/// Build a bare `MSG_SNAPSHOT_REQ` frame (peer/client driver helper).
pub fn encode_snapshot_request() -> Vec<u8> {
    vec![MSG_SNAPSHOT_REQ]
}

/// Decode a `MSG_SNAPSHOT` frame into a [`mneme_store::SyncSnapshot`].
pub fn decode_snapshot(frame: &[u8]) -> Option<mneme_store::SyncSnapshot> {
    match frame.split_first() {
        Some((&MSG_SNAPSHOT, body)) => ciborium::from_reader(body).ok(),
        _ => None,
    }
}

// --- §11 incremental anti-entropy (manifest + delta) ---

/// Serialize this node's [`mneme_store::SyncManifest`] (structure, no object bytes).
fn encode_manifest(state: &AppState) -> Option<Vec<u8>> {
    let store = state.store.lock().ok()?;
    let manifest = store.export_sync_manifest();
    drop(store);
    let mut body = Vec::new();
    ciborium::into_writer(&manifest, &mut body).ok()?;
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(MSG_MANIFEST);
    out.extend(body);
    Some(out)
}

/// Answer a `MSG_WANT_OBJECTS` request (CBOR `Vec<[u8;32]>`) with the object bytes
/// this node holds for those ids (`MSG_HAVE_OBJECTS`, CBOR `Vec<Vec<u8>>`).
fn encode_have_objects(state: &AppState, payload: &[u8]) -> Option<Vec<u8>> {
    let ids: Vec<[u8; 32]> = ciborium::from_reader(payload).ok()?;
    let store = state.store.lock().ok()?;
    let objects = store.export_objects(&ids);
    drop(store);
    let mut body = Vec::new();
    ciborium::into_writer(&objects, &mut body).ok()?;
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(MSG_HAVE_OBJECTS);
    out.extend(body);
    Some(out)
}

/// Bare `MSG_MANIFEST_REQ` frame (client driver helper).
pub fn encode_manifest_request() -> Vec<u8> {
    vec![MSG_MANIFEST_REQ]
}

/// Decode a `MSG_MANIFEST` frame into a [`mneme_store::SyncManifest`].
pub fn decode_manifest(frame: &[u8]) -> Option<mneme_store::SyncManifest> {
    match frame.split_first() {
        Some((&MSG_MANIFEST, body)) => ciborium::from_reader(body).ok(),
        _ => None,
    }
}

/// Build a `MSG_WANT_OBJECTS` frame requesting the given object ids.
pub fn encode_want_objects(ids: &[[u8; 32]]) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    ciborium::into_writer(&ids, &mut body).ok()?;
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(MSG_WANT_OBJECTS);
    out.extend(body);
    Some(out)
}

/// Decode a `MSG_HAVE_OBJECTS` frame into the delta object byte vectors.
pub fn decode_have_objects(frame: &[u8]) -> Option<Vec<Vec<u8>>> {
    match frame.split_first() {
        Some((&MSG_HAVE_OBJECTS, body)) => ciborium::from_reader(body).ok(),
        _ => None,
    }
}

pub fn encode_hello(state: &AppState, node_id: [u8; 16]) -> Option<Vec<u8>> {
    let store = state.store.lock().ok()?;
    let root = store.current_root().ok()?;
    let hello = Hello {
        proto_ver: 1,
        node_id,
        head_root: root.preimage_hash,
        head_sig: root.signature.clone(),
    };
    let mut body = Vec::new();
    ciborium::into_writer(&hello, &mut body)
        .map_err(|_| ())
        .ok()?;
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(MSG_HELLO);
    out.extend(body);
    Some(out)
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
}
