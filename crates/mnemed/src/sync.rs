//! Sync protocol WebSocket surface (blueprint §11 wire format).

use crate::state::AppState;
use axum::{
    Router,
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::IntoResponse,
    routing::get,
};
use serde::{Deserialize, Serialize};

const MSG_HELLO: u8 = 0x01;
const MSG_ROOT_PROOF: u8 = 0x02;
/// Explicit "send me your signed root proof" request (replaces the old catch-all).
pub const MSG_ROOT_PROOF_REQ: u8 = 0x03;
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

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_sync(socket, state))
}

async fn handle_sync(mut socket: WebSocket, state: AppState) {
    while let Some(Ok(msg)) = socket.recv().await {
        match msg {
            Message::Binary(data) => {
                if data.is_empty() {
                    continue;
                }
                let response = match data[0] {
                    MSG_HELLO => handle_hello(&state, &data[1..]).await,
                    MSG_ROOT_PROOF_REQ => encode_root_proof(&state),
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
                    if socket.send(Message::Binary(bytes.into())).await.is_err() {
                        break;
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

fn encode_root_proof(state: &AppState) -> Option<Vec<u8>> {
    let store = state.store.lock().ok()?;
    let root = store.current_root().ok()?;
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

/// Serialize this node's [`mneme_store::SyncSnapshot`] as a `MSG_SNAPSHOT` frame.
fn encode_snapshot(state: &AppState) -> Option<Vec<u8>> {
    let store = state.store.lock().ok()?;
    let snapshot = store.export_sync_snapshot();
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
