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

#[cfg(test)]
mod tests {
    use super::*;
    use mneme_smt::SparseMerkleTree;

    fn sample_key() -> LogicalKey {
        LogicalKey {
            namespace: "test".to_string(),
            name: "doc".to_string(),
        }
    }

    /// ABSENT-1: prove_absent rejects a live key — this is the primary fail-closed invariant.
    /// A live key in the SMT MUST NOT produce a non-membership proof (that would allow
    /// forged deletion evidence while the key is still active).
    #[test]
    fn prove_absent_rejects_live_key_with_tombstone_conflict() {
        let key = sample_key();
        let mut smt = SparseMerkleTree::new();
        let dummy_object_id = [0x01u8; 32];
        smt.upsert(key.hash(), dummy_object_id);
        let result = prove_absent(&smt, &key);
        assert_eq!(
            result.unwrap_err(),
            MnemeError::TombstoneConflict,
            "prove_absent must fail closed for live keys — TombstoneConflict"
        );
    }

    /// ABSENT-2: prove_absent succeeds for a tombstoned key and produces a verifiable proof.
    #[test]
    fn prove_absent_succeeds_for_tombstoned_key() {
        let key = sample_key();
        let dummy_object_id = [0x01u8; 32];
        let mut smt = SparseMerkleTree::new();
        smt.upsert(key.hash(), dummy_object_id);
        smt.tombstone(key.hash());
        let proof =
            prove_absent(&smt, &key).expect("tombstoned key must produce non-membership proof");
        assert!(
            verify_absence(&proof).is_ok(),
            "tombstone non-membership proof must verify"
        );
    }

    /// ABSENT-3: prove_absent succeeds for a key not in the SMT (empty slot).
    #[test]
    fn prove_absent_succeeds_for_absent_key() {
        let key = sample_key();
        let smt = SparseMerkleTree::new();
        let proof = prove_absent(&smt, &key).expect("absent key must produce non-membership proof");
        assert!(
            verify_absence(&proof).is_ok(),
            "empty-slot non-membership proof must verify"
        );
    }
}
