//! Per-kind CRDT value semantics (blueprint §9.4).

use mneme_core::object::{MemoryKind, ObjectRecord};
use mneme_core::{MnemeError, from_bytes_strict, hash_obj};
use mneme_forget::verify_object_identity;

/// Resolved winner for a logical-key conflict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeWinner {
    pub object_id: [u8; 32],
    pub canonical_bytes: Vec<u8>,
    /// OR-Set: additional object ids retained in the store (Episodic/Semantic).
    pub retained_alternatives: Vec<([u8; 32], Vec<u8>)>,
}

/// Pick merged value for two live object versions at the same logical key.
pub fn merge_object_versions(
    local_id: [u8; 32],
    local_bytes: &[u8],
    peer_id: [u8; 32],
    peer_bytes: &[u8],
) -> Result<MergeWinner, MnemeError> {
    if local_id == peer_id {
        return Ok(MergeWinner {
            object_id: local_id,
            canonical_bytes: local_bytes.to_vec(),
            retained_alternatives: Vec::new(),
        });
    }
    let local: ObjectRecord = from_bytes_strict(local_bytes)?;
    let peer: ObjectRecord = from_bytes_strict(peer_bytes)?;
    let kind = MemoryKind::try_from(local.kind)?;

    match kind {
        MemoryKind::Working => Ok(MergeWinner {
            object_id: local_id,
            canonical_bytes: local_bytes.to_vec(),
            retained_alternatives: Vec::new(),
        }),
        MemoryKind::Identity | MemoryKind::Procedural => {
            let winner = lww_pick(&local, local_id, local_bytes, &peer, peer_id, peer_bytes)?;
            Ok(MergeWinner {
                object_id: winner.0,
                canonical_bytes: winner.1,
                retained_alternatives: Vec::new(),
            })
        }
        MemoryKind::Episodic | MemoryKind::Semantic => {
            let (winner_id, winner_bytes) =
                lww_pick(&local, local_id, local_bytes, &peer, peer_id, peer_bytes)?;
            let mut retained = Vec::new();
            if winner_id == local_id {
                retained.push((peer_id, peer_bytes.to_vec()));
            } else {
                retained.push((local_id, local_bytes.to_vec()));
            }
            Ok(MergeWinner {
                object_id: winner_id,
                canonical_bytes: winner_bytes,
                retained_alternatives: retained,
            })
        }
    }
}

fn lww_pick(
    local: &ObjectRecord,
    local_id: [u8; 32],
    local_bytes: &[u8],
    peer: &ObjectRecord,
    peer_id: [u8; 32],
    peer_bytes: &[u8],
) -> Result<([u8; 32], Vec<u8>), MnemeError> {
    let local_hlc = hlc_wire_cmp(&local.hlc);
    let peer_hlc = hlc_wire_cmp(&peer.hlc);
    if peer_hlc > local_hlc {
        return Ok((peer_id, peer_bytes.to_vec()));
    }
    if local_hlc > peer_hlc {
        return Ok((local_id, local_bytes.to_vec()));
    }
    if peer_id > local_id {
        Ok((peer_id, peer_bytes.to_vec()))
    } else {
        Ok((local_id, local_bytes.to_vec()))
    }
}

fn hlc_wire_cmp(h: &mneme_core::object::HlcWire) -> (u64, u32, [u8; 16]) {
    (h.wall_ms, h.counter, h.node_id)
}

/// Verify content address (INV-1) before apply.
pub fn verify_object_bytes(id: &[u8; 32], bytes: &[u8]) -> Result<(), MnemeError> {
    if hash_obj(bytes) != *id {
        return Err(MnemeError::ObjectTampered);
    }
    let record: ObjectRecord = from_bytes_strict(bytes)?;
    record.validate_invariants()?;
    verify_object_identity(bytes, id)
}

/// Compare object ids for deterministic tie-break (INV-10).
pub fn object_id_max(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    if a >= b { *a } else { *b }
}
