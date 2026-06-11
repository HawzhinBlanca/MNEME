//! Merkle-Search-Tree CRDT merge and anti-entropy sync (blueprint §9.4, §11).

#![forbid(unsafe_code)]

mod crdt;
mod merge;
mod wire;

#[cfg(feature = "convergence_cert")]
mod cert;
#[cfg(feature = "convergence_cert")]
mod mset;

pub use crdt::{MergeWinner, merge_object_versions, object_id_max, verify_object_bytes};
pub use merge::{
    MergeApplyResult, MstDiff, PeerSnapshot, WriterTrust, apply_peer_snapshot, mst_diff,
    peer_object_ids_to_fetch,
};
pub use wire::{decode_sync_message, encode_sync_message, fuzz_sync_parse};

#[cfg(feature = "convergence_cert")]
pub use cert::{
    CONV_CERT_HONESTY, CONV_CERT_VERSION, ConvergenceCert, ConvergenceVerify,
    decode_convergence_cert, encode_convergence_cert, verify_convergence,
};
#[cfg(feature = "convergence_cert")]
pub use mset::{MSET_COMMIT_LEN, ObjectMultiset, decompress_commitment, hash_object_to_group};

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "convergence_cert"))]
mod convergence_cert_tests;
