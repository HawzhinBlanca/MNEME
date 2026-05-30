//! Crypto-shred + SMT tombstone (§13.2 default forget path).

use mneme_core::{LogicalKey, MnemeError, ObjectRecord, from_bytes_strict, hash_obj};
use mneme_crypto::{
    KeyVault, PAYLOAD_ALG_XCHACHA20_POLY1305, open_payload, shred_payload_key, types::KeyId,
};
use mneme_smt::{SparseMerkleTree, TOMBSTONE};

/// Inputs for a single logical-key shred forget (store kernel calls inside INV-8 txn).
pub struct ShredForgetInput<'a> {
    pub logical_key: &'a LogicalKey,
    pub key_index: &'a mut SparseMerkleTree,
    pub vault: &'a mut dyn KeyVault,
    /// Canonical object bytes for the live mapping (if known); used to shred alg=1 keys.
    pub object_bytes: Option<&'a [u8]>,
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
        Ok(_) => Err(MnemeError::SchemaDrift),
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
