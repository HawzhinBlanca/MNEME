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
const MSG_BYE: u8 = 0x07;

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
                    MSG_BYE => None,
                    _ => encode_root_proof(&state),
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
