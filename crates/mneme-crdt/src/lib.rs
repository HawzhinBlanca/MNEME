//! Merkle-Search-Tree CRDT merge and anti-entropy sync (blueprint §9.4, §11).

#![forbid(unsafe_code)]

mod crdt;
mod merge;
mod wire;

pub use crdt::{MergeWinner, merge_object_versions, object_id_max, verify_object_bytes};
pub use merge::{
    MergeApplyResult, MstDiff, PeerSnapshot, WriterTrust, apply_peer_snapshot, mst_diff,
    peer_object_ids_to_fetch,
};
pub use wire::{decode_sync_message, encode_sync_message, fuzz_sync_parse};

#[cfg(test)]
mod tests;
