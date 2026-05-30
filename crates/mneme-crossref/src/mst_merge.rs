//! MST merge convergence — reference path for Appendix B item 7.

use crate::key::logical_key_hash;
use crate::object_fixture::{mst_agent_object_bytes, object_id};
use crate::smt::SparseMerkleTree;
use std::collections::BTreeMap;

pub struct PeerSnapshot {
    pub key_index: SparseMerkleTree,
    pub key_to_object: BTreeMap<[u8; 32], [u8; 32]>,
}

pub fn mst_agent_snapshot(label: &str) -> Result<PeerSnapshot, crate::error::CrossrefError> {
    let seed = match label {
        "A" => 0x0a,
        "B" => 0x0b,
        "C" => 0x0c,
        other => panic!("unknown MST fixture agent {other}"),
    };
    let name = label.to_ascii_lowercase();
    let key_hash = logical_key_hash("mst", &name);
    let bytes = mst_agent_object_bytes(seed)?;
    let id = object_id(&bytes);
    let mut key_index = SparseMerkleTree::new();
    key_index.upsert(key_hash, id);
    Ok(PeerSnapshot {
        key_index,
        key_to_object: BTreeMap::from([(key_hash, id)]),
    })
}

pub fn apply_peer_snapshot(local: &mut PeerSnapshot, peer: &PeerSnapshot) {
    for (key, value) in peer.key_index.iter_leaves() {
        local.key_index.upsert(key, value);
        local.key_to_object.insert(key, value);
    }
}

pub fn mst_root_for_order(order: &[&str]) -> Result<[u8; 32], crate::error::CrossrefError> {
    let mut local = PeerSnapshot {
        key_index: SparseMerkleTree::new(),
        key_to_object: BTreeMap::new(),
    };
    for label in order {
        let peer = mst_agent_snapshot(label)?;
        apply_peer_snapshot(&mut local, &peer);
    }
    Ok(local.key_index.root())
}
