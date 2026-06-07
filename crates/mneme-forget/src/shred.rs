//! Crypto-shred + SMT tombstone (§13.2 default forget path).

use mneme_core::{LogicalKey, MnemeError, ObjectRecord, from_bytes_strict, hash_obj};
use mneme_crypto::{
    KeyVault, PAYLOAD_ALG_XCHACHA20_POLY1305, open_payload, shred_payload_key, types::KeyId,
};
use mneme_smt::{SparseMerkleTree, TOMBSTONE};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShredPayloadFailure {
    PayloadStillDecrypts,
}

fn shred_payload_failure_to_mneme(failure: ShredPayloadFailure) -> MnemeError {
    match failure {
        ShredPayloadFailure::PayloadStillDecrypts => MnemeError::SchemaDrift,
    }
}

fn payload_still_decrypts_after_shred_error() -> MnemeError {
    shred_payload_failure_to_mneme(ShredPayloadFailure::PayloadStillDecrypts)
}

/// Inputs for a single logical-key shred forget (store kernel calls inside INV-8 txn).
pub struct ShredForgetInput<'a> {
    pub logical_key: &'a LogicalKey,
    pub key_index: &'a mut SparseMerkleTree,
    pub vault: &'a mut dyn KeyVault,
    /// Canonical object bytes for the live mapping (if known); used to shred alg=1 keys.
    pub object_bytes: Option<&'a [u8]>,
}

/// BLAKE3 commit over a completed shred forget (Phase III P3-2 witness).
///
/// Binds `key_hash`, `object_id`, and optional destroyed payload `KeyId`.
/// Provisional domain tag until the Phase III seam is frozen.
pub fn shred_witness_commit(outcome: &ShredOutcome) -> [u8; 32] {
    use blake3::Hasher;
    let mut h = Hasher::new();
    h.update(b"MNEME-shred-witness-v1\x00");
    h.update(&outcome.key_hash);
    h.update(&outcome.object_id);
    if let Some(id) = outcome.shredded_key_id {
        h.update(&[1u8]);
        h.update(&id);
    } else {
        h.update(&[0u8]);
    }
    *h.finalize().as_bytes()
}

/// Result of `apply_shred_forget`: tombstone recorded, optional vault key destroyed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShredOutcome {
    pub key_hash: [u8; 32],
    pub object_id: [u8; 32],
    pub shredded_key_id: Option<KeyId>,
}

/// Associated data for per-object AEAD: logical key hash (deterministic, INV-10).
pub fn payload_aad(logical_key: &LogicalKey) -> Vec<u8> {
    logical_key.hash().to_vec()
}

/// Resolve live object id for a logical key before tombstoning.
pub fn object_id_for_key(
    key_index: &SparseMerkleTree,
    key_hash: &[u8; 32],
) -> Result<[u8; 32], MnemeError> {
    let value = key_index
        .get(key_hash)
        .ok_or(MnemeError::IndexPathInvalid)?;
    if value == TOMBSTONE {
        return Err(MnemeError::Forgotten);
    }
    Ok(value)
}

/// Content address of `object_bytes` still matches committed id (structure intact).
pub fn structure_intact(object_bytes: &[u8], object_id: &[u8; 32]) -> Result<(), MnemeError> {
    if hash_obj(object_bytes) != *object_id {
        return Err(MnemeError::ObjectTampered);
    }
    Ok(())
}

/// Ciphertext remains but decryption fails closed after shred.
pub fn payload_unreadable(
    vault: &dyn KeyVault,
    object_bytes: &[u8],
    logical_key: &LogicalKey,
) -> Result<(), MnemeError> {
    let record: ObjectRecord = from_bytes_strict(object_bytes)?;
    let aad = payload_aad(logical_key);
    match open_payload(vault, &record.payload_enc, &aad) {
        Err(MnemeError::Forgotten) => Ok(()),
        Ok(_) => Err(payload_still_decrypts_after_shred_error()),
        Err(e) => Err(e),
    }
}

/// Destroy per-object vault key (if encrypted) and tombstone the logical key in the SMT (§13.2).
pub fn forget_shred(input: ShredForgetInput<'_>) -> Result<ShredOutcome, MnemeError> {
    let key_hash = input.logical_key.hash();
    if !input.key_index.contains_live(&key_hash) {
        return Err(MnemeError::Forgotten);
    }

    let object_id = object_id_for_key(input.key_index, &key_hash)?;
    let shredded_key_id = if let Some(bytes) = input.object_bytes {
        structure_intact(bytes, &object_id)?;
        shred_encrypted_payload_key(input.vault, bytes)?
    } else {
        None
    };

    input.key_index.tombstone(key_hash);

    Ok(ShredOutcome {
        key_hash,
        object_id,
        shredded_key_id,
    })
}

/// Alias retained for store/kernel call sites.
pub fn apply_shred_forget(input: ShredForgetInput<'_>) -> Result<ShredOutcome, MnemeError> {
    forget_shred(input)
}

fn shred_encrypted_payload_key(
    vault: &mut dyn KeyVault,
    object_bytes: &[u8],
) -> Result<Option<KeyId>, MnemeError> {
    let record: ObjectRecord = from_bytes_strict(object_bytes)?;
    if record.payload_enc.alg != PAYLOAD_ALG_XCHACHA20_POLY1305 {
        return Ok(None);
    }
    let key_id = shred_payload_key(vault, &record.payload_enc)?;
    Ok(Some(key_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mneme_core::{MemoryKind, to_bytes_canonical};
    use mneme_crypto::{MemoryKeyVault, seal_payload};

    fn source_between_markers<'a>(
        source: &'a str,
        start_marker: &str,
        end_marker: &str,
        context: &str,
    ) -> &'a str {
        let start = source
            .find(start_marker)
            .unwrap_or_else(|| panic!("{context} should contain start marker `{start_marker}`"));
        let end_offset = source[start..]
            .find(end_marker)
            .unwrap_or_else(|| panic!("{context} should contain end marker `{end_marker}`"));
        &source[start..start + end_offset]
    }

    fn encrypted_record(body_plain: &[u8], vault: &mut MemoryKeyVault) -> (Vec<u8>, LogicalKey) {
        let key = LogicalKey {
            namespace: "gdpr".into(),
            name: "email".into(),
        };
        let aad = payload_aad(&key);
        let mut record = ObjectRecord::fixture(MemoryKind::Semantic);
        record.payload_enc = seal_payload(vault, body_plain, &aad).expect("seal");
        let bytes = to_bytes_canonical(&record).expect("canonical");
        from_bytes_strict::<ObjectRecord>(&bytes).expect("roundtrip");
        (bytes, key)
    }

    #[test]
    fn shred_payload_failures_are_classified_not_schema_drift_collapsed() {
        let source = include_str!("shred.rs");
        let section = source_between_markers(
            source,
            "use mneme_core",
            "#[cfg(test)]",
            "shred production section",
        );

        for forbidden in [
            "Ok(_) => Err(MnemeError::SchemaDrift)",
            "Err(MnemeError::SchemaDrift)",
            "return Err(MnemeError::SchemaDrift)",
        ] {
            assert!(
                !section.contains(forbidden),
                "shred payload checks should route `{forbidden}` through named classifiers"
            );
        }

        for required in [
            "enum ShredPayloadFailure",
            "fn shred_payload_failure_to_mneme(",
            "fn payload_still_decrypts_after_shred_error(",
            "ShredPayloadFailure::PayloadStillDecrypts",
        ] {
            assert!(
                section.contains(required),
                "shred payload failure classification should include `{required}`"
            );
        }
    }

    #[test]
    fn shred_payload_failure_classifier_preserves_public_schema_drift() {
        assert_eq!(
            shred_payload_failure_to_mneme(ShredPayloadFailure::PayloadStillDecrypts),
            MnemeError::SchemaDrift
        );
        assert_eq!(
            payload_still_decrypts_after_shred_error(),
            MnemeError::SchemaDrift
        );
    }

    #[test]
    fn payload_unreadable_rejects_still_decryptable_payload() {
        let mut vault = MemoryKeyVault::new();
        let (bytes, key) = encrypted_record(b"still live", &mut vault);

        assert_eq!(
            payload_unreadable(&vault, &bytes, &key),
            Err(MnemeError::SchemaDrift)
        );
    }
}
