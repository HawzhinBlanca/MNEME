//! Time-lock encryption and decryption support using the drand network.

use mneme_core::MnemeError;

/// The public key for the default drand mainnet ("quicknet").
pub const DRAND_QUICKNET_PUBLIC_KEY: &str = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";

/// Time-lock encrypts a 16-byte key for a specific drand round.
pub fn encrypt_embargo(
    key: &[u8; 16],
    round: u64,
    public_key: &[u8],
) -> Result<Vec<u8>, MnemeError> {
    let mut ciphertext = Vec::new();
    tlock::encrypt(&mut ciphertext, &key[..], public_key, round).map_err(|e| {
        MnemeError::IoFailed {
            path: "tlock_encrypt".to_string(),
            kind: e.to_string(),
        }
    })?;
    Ok(ciphertext)
}

/// Time-lock decrypts the key ciphertext using the threshold signature at that round.
pub fn decrypt_embargo(ciphertext: &[u8], signature: &[u8]) -> Result<[u8; 16], MnemeError> {
    let mut decrypted = Vec::new();
    tlock::decrypt(&mut decrypted, ciphertext, signature).map_err(|e| MnemeError::IoFailed {
        path: "tlock_decrypt".to_string(),
        kind: e.to_string(),
    })?;
    let mut out = [0u8; 16];
    if decrypted.len() != 16 {
        return Err(MnemeError::IoFailed {
            path: "tlock_decrypt".to_string(),
            kind: format!("decrypted key length mismatch: got {}", decrypted.len()),
        });
    }
    out.copy_from_slice(&decrypted);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embargo_stub() {
        // Simple test to ensure quick validation compiles
        assert_eq!(DRAND_QUICKNET_PUBLIC_KEY.len(), 192);
    }

    #[test]
    fn test_embargo_roundtrip() {
        let key = [0x42; 16];
        let pubkey = hex::decode(DRAND_QUICKNET_PUBLIC_KEY).unwrap();
        let ct = encrypt_embargo(&key, 1, &pubkey).unwrap();
        let sig = hex::decode("b55e7cb2d5c613ee0b2e28d6750aabbb78c39dcc96bd9d38c2c2e12198df95571de8e8e402a0cc48871c7089a2b3af4b").unwrap();
        let decrypted = decrypt_embargo(&ct, &sig).unwrap();
        assert_eq!(decrypted, key);
    }
}
