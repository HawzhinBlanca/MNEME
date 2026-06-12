//! ROBR-1 (Receipt-Object Binding Relation - Level 1) offline verification.
//! Proves that returned memory objects match the deterministic `RunDigest` signed/committed in the receipt.

use blake3::Hasher;
use mneme_core::{Entry, MnemeError, ObjectId};

/// Verification check for ROBR-1: recompute the deterministic hash of the objects'
/// content-addressed digests sorted canonically, and verify it matches the committed `RunDigest`.
///
/// Honesty Label (ROBR-1):
/// "Replay-verified (no TEE) proves that the retrieved objects match the exact deterministic
/// trace signed by the operator, but does NOT prove that the computation was run inside
/// attested hardware (which requires ROBR-4 TEE attestation)."
pub fn verify_replay_binding(
    expected_run_digest: &[u8; 32],
    objects: &[Entry],
) -> Result<(), MnemeError> {
    let computed = compute_run_digest(objects);
    if &computed != expected_run_digest {
        return Err(MnemeError::RetrievalDominanceFailed);
    }
    Ok(())
}

/// Helper function to compute the RunDigest for a set of objects.
pub fn compute_run_digest(objects: &[Entry]) -> [u8; 32] {
    let ids: Vec<ObjectId> = objects.iter().map(|e| e.id).collect();
    compute_run_digest_from_ids(&ids)
}

/// Compute the RunDigest for a set of object IDs.
pub fn compute_run_digest_from_ids(ids: &[ObjectId]) -> [u8; 32] {
    let mut raw_ids: Vec<[u8; 32]> = ids.iter().map(|id| id.0).collect();
    raw_ids.sort_unstable();

    let mut hasher = Hasher::new();
    // Domain separation tag for ROBR-1
    hasher.update(b"MNEME-ROBR-v1\x00");
    for id in &raw_ids {
        hasher.update(id);
    }
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mneme_core::{MemoryKind, ObjectId, ObjectRecord};

    fn make_test_entry(id_bytes: [u8; 32]) -> Entry {
        let record = ObjectRecord::fixture(MemoryKind::Episodic);
        Entry {
            id: ObjectId(id_bytes),
            record,
            plaintext: vec![],
        }
    }

    #[test]
    fn test_robr_binding_success() {
        let entry1 = make_test_entry([0x01; 32]);
        let entry2 = make_test_entry([0x02; 32]);
        let objects = vec![entry1, entry2];

        let digest = compute_run_digest(&objects);
        assert!(verify_replay_binding(&digest, &objects).is_ok());
    }

    #[test]
    fn test_robr_binding_mismatch() {
        let entry1 = make_test_entry([0x01; 32]);
        let entry2 = make_test_entry([0x02; 32]);
        let objects = vec![entry1, entry2];

        let mut bad_digest = compute_run_digest(&objects);
        bad_digest[0] ^= 1; // Corrupt the digest

        assert!(verify_replay_binding(&bad_digest, &objects).is_err());
    }
}
