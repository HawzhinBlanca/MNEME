//! Unix socket RPC smoke test (remember / head / sync hello).

use mneme_cap::agent_cap;
use mneme_core::{NodeId, SyncMessage};
use mneme_crdt::encode_sync_message;
use mnemed::{
    cap_to_b64, test_state,
    unix::{KernelRequest, UnixServer, request_json},
};
use std::path::PathBuf;
use tempfile::tempdir;
use tokio::task::JoinHandle;

async fn spawn_unix(path: PathBuf, state: mnemed::AppState) -> JoinHandle<()> {
    tokio::spawn(async move {
        let server = UnixServer::new(path, state);
        let _ = server.serve().await;
    })
}

#[tokio::test]
async fn unix_remember_and_head_roundtrip() {
    let dir = tempdir().expect("tempdir");
    let sock = dir.path().join("mneme.sock");
    let (state, operator, agent) = test_state(dir.path());
    let cap = agent_cap(&operator, agent.public_key_bytes()).expect("cap");
    let cap_b64 = cap_to_b64(&cap);
    {
        let mut store = state.store.lock().expect("lock");
        store.trust = store.trust.clone().with_writer(agent.public_key_bytes());
    }
    let handle = spawn_unix(sock.clone(), state).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let remember = request_json(
        &sock,
        &KernelRequest::Remember {
            cap_b64: cap_b64.clone(),
            namespace: "unix".into(),
            name: "key".into(),
            body_b64: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                b"payload",
            ),
        },
    )
    .await
    .expect("connect");
    match remember {
        mnemed::unix::KernelResponse::Ok { payload } => {
            assert!(payload.get("object_id").is_some());
        }
        mnemed::unix::KernelResponse::Err { message, .. } => panic!("remember failed: {message}"),
    }

    let head = request_json(
        &sock,
        &KernelRequest::Head {
            cap_b64: cap_b64.clone(),
        },
    )
    .await
    .expect("head");
    match head {
        mnemed::unix::KernelResponse::Ok { payload } => {
            assert_eq!(payload["sequence"].as_u64(), Some(2));
        }
        mnemed::unix::KernelResponse::Err { message, .. } => panic!("head failed: {message}"),
    }

    handle.abort();
}

#[tokio::test]
async fn unix_sync_hello_returns_root_proof() {
    let dir = tempdir().expect("tempdir");
    let sock = dir.path().join("sync.sock");
    let (state, _operator, _agent) = test_state(dir.path());
    let handle = spawn_unix(sock.clone(), state).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let hello = SyncMessage::Hello {
        proto_ver: 1,
        node_id: NodeId([0x01; 16]),
        head_root: [0u8; 32],
        head_sig: vec![],
    };
    let wire = encode_sync_message(&hello).expect("encode");
    let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, wire);
    let resp = request_json(&sock, &KernelRequest::SyncFrame { bytes_b64: b64 })
        .await
        .expect("sync");
    match resp {
        mnemed::unix::KernelResponse::Ok { payload } => {
            assert!(payload.get("sync_bytes_b64").is_some());
        }
        mnemed::unix::KernelResponse::Err { message, .. } => panic!("sync failed: {message}"),
    }
    handle.abort();
}
