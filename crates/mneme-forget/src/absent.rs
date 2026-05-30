//! Verifiable absence via SMT non-membership / tombstone proofs (§9.5).

use mneme_core::{LogicalKey, MnemeError, Root};
use mneme_crypto::{TrustConfig, public_key_from_bytes, verify_signature_bytes};
use mneme_root::{check_replay, verify_root_chain};
use mneme_smt::{NonMembershipProof, SparseMerkleTree};

/// Issue a non-membership or tombstone proof for `logical_key` (live keys rejected).
pub fn prove_absent(
    key_index: &SparseMerkleTree,
    logical_key: &LogicalKey,
) -> Result<NonMembershipProof, MnemeError> {
    let key_hash = logical_key.hash();
    if key_index.contains_live(&key_hash) {
        return Err(MnemeError::TombstoneConflict);
    }
    key_index.prove_non_membership(key_hash)
}

/// Verify a proof of absence (tombstone or empty slot).
pub fn verify_absence(proof: &NonMembershipProof) -> Result<(), MnemeError> {
    SparseMerkleTree::verify_non_membership(proof)
}

/// Signed root still verifies after forget (structure intact; bytes may be unreadable).
pub fn verify_signed_root(
    root: &Root,
    trust: &TrustConfig,
    previous: Option<&Root>,
) -> Result<(), MnemeError> {
    let pk_bytes = trust
        .operator_keys
        .first()
        .ok_or(MnemeError::RootSigInvalid)?;
    let pk = public_key_from_bytes(pk_bytes)?;
    verify_signature_bytes(&pk, &root.preimage_hash, &root.signature)?;
    verify_root_chain(root, previous)?;
    check_replay(root, trust.last_seen_hlc)?;
    Ok(())
}
