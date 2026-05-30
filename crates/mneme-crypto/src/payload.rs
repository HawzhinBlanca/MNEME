use mneme_core::{MnemeError, PayloadEnc};

use crate::aead::{open, random_nonce, seal};
use crate::types::{KeyId, PAYLOAD_ALG_PLAINTEXT, PAYLOAD_ALG_XCHACHA20_POLY1305};
use crate::vault::KeyVault;

/// Encrypt a draft body into PayloadEnc alg=1 using the vault.
pub fn seal_payload(
    vault: &mut dyn KeyVault,
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<PayloadEnc, MnemeError> {
    let (key, key_id) = vault.new_key()?;
    let nonce = random_nonce();
    let body = seal(&key, &nonce, plaintext, associated_data)?;
    Ok(PayloadEnc {
        alg: PAYLOAD_ALG_XCHACHA20_POLY1305,
        key_id: Some(key_id),
        nonce: Some(nonce),
        body,
    })
}

/// Decrypt PayloadEnc; missing/shredded keys fail closed.
pub fn open_payload(
    vault: &dyn KeyVault,
    payload: &PayloadEnc,
    associated_data: &[u8],
) -> Result<Vec<u8>, MnemeError> {
    match payload.alg {
        PAYLOAD_ALG_PLAINTEXT => Ok(payload.body.clone()),
        PAYLOAD_ALG_XCHACHA20_POLY1305 => {
            let key_id = payload.key_id.ok_or(MnemeError::SchemaDrift)?;
            let nonce = payload.nonce.ok_or(MnemeError::SchemaDrift)?;
            let key = vault.get(&key_id)?;
            open(&key, &nonce, &payload.body, associated_data)
        }
        _ => Err(MnemeError::UnsupportedVersion {
            got: payload.alg as u16,
        }),
    }
}

/// Shred the per-object key referenced by an encrypted payload.
pub fn shred_payload_key(
    vault: &mut dyn KeyVault,
    payload: &PayloadEnc,
) -> Result<KeyId, MnemeError> {
    if payload.alg != PAYLOAD_ALG_XCHACHA20_POLY1305 {
        return Err(MnemeError::SchemaDrift);
    }
    let key_id = payload.key_id.ok_or(MnemeError::SchemaDrift)?;
    vault.shred(&key_id)?;
    Ok(key_id)
}
