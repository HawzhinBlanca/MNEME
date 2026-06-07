use mneme_core::{MnemeError, PayloadEnc};

use crate::aead::{open, random_nonce, seal};
use crate::types::{KeyId, PAYLOAD_ALG_PLAINTEXT, PAYLOAD_ALG_XCHACHA20_POLY1305};
use crate::vault::KeyVault;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PayloadFailure {
    MissingKeyId,
    MissingNonce,
    ShredNonEncrypted,
    MissingShredKeyId,
    UnsupportedAlgorithm(u16),
}

fn payload_failure_to_mneme(failure: PayloadFailure) -> MnemeError {
    match failure {
        PayloadFailure::MissingKeyId
        | PayloadFailure::MissingNonce
        | PayloadFailure::ShredNonEncrypted
        | PayloadFailure::MissingShredKeyId => MnemeError::SchemaDrift,
        PayloadFailure::UnsupportedAlgorithm(got) => MnemeError::UnsupportedVersion { got },
    }
}

fn missing_payload_key_id_error() -> MnemeError {
    payload_failure_to_mneme(PayloadFailure::MissingKeyId)
}

fn missing_payload_nonce_error() -> MnemeError {
    payload_failure_to_mneme(PayloadFailure::MissingNonce)
}

fn shred_non_encrypted_payload_error() -> MnemeError {
    payload_failure_to_mneme(PayloadFailure::ShredNonEncrypted)
}

fn missing_shred_payload_key_id_error() -> MnemeError {
    payload_failure_to_mneme(PayloadFailure::MissingShredKeyId)
}

fn unsupported_payload_algorithm_error(got: u16) -> MnemeError {
    payload_failure_to_mneme(PayloadFailure::UnsupportedAlgorithm(got))
}

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
            let key_id = payload.key_id.ok_or_else(missing_payload_key_id_error)?;
            let nonce = payload.nonce.ok_or_else(missing_payload_nonce_error)?;
            let key = vault.get(&key_id)?;
            open(&key, &nonce, &payload.body, associated_data)
        }
        _ => Err(unsupported_payload_algorithm_error(payload.alg as u16)),
    }
}

/// Shred the per-object key referenced by an encrypted payload.
pub fn shred_payload_key(
    vault: &mut dyn KeyVault,
    payload: &PayloadEnc,
) -> Result<KeyId, MnemeError> {
    if payload.alg != PAYLOAD_ALG_XCHACHA20_POLY1305 {
        return Err(shred_non_encrypted_payload_error());
    }
    let key_id = payload
        .key_id
        .ok_or_else(missing_shred_payload_key_id_error)?;
    vault.shred(&key_id)?;
    Ok(key_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::MemoryKeyVault;

    const TEST_AAD: &[u8] = b"payload-metadata-failure";

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

    #[test]
    fn payload_failures_are_classified_not_schema_drift_collapsed() {
        let source = include_str!("payload.rs");
        let section = source_between_markers(
            source,
            "pub fn seal_payload",
            "#[cfg(test)]",
            "payload metadata handlers",
        );

        for forbidden in [
            "ok_or(MnemeError::SchemaDrift)",
            "Err(MnemeError::SchemaDrift)",
            "return Err(MnemeError::SchemaDrift)",
        ] {
            assert!(
                !section.contains(forbidden),
                "payload metadata handlers should route `{forbidden}` through named classifiers"
            );
        }

        for required in [
            "enum PayloadFailure",
            "fn payload_failure_to_mneme(",
            "fn missing_payload_key_id_error(",
            "fn missing_payload_nonce_error(",
            "fn shred_non_encrypted_payload_error(",
            "fn missing_shred_payload_key_id_error(",
            "PayloadFailure::MissingKeyId",
            "PayloadFailure::MissingNonce",
            "PayloadFailure::ShredNonEncrypted",
            "PayloadFailure::MissingShredKeyId",
        ] {
            assert!(
                source.contains(required),
                "payload metadata failure classification should include `{required}`"
            );
        }
    }

    #[test]
    fn payload_algorithm_failures_are_classified_not_unsupported_version_collapsed() {
        let source = include_str!("payload.rs");
        let section = source_between_markers(
            source,
            "pub fn open_payload",
            "/// Shred the per-object key",
            "payload algorithm handler",
        );

        for forbidden in [
            "Err(MnemeError::UnsupportedVersion",
            "return Err(MnemeError::UnsupportedVersion",
        ] {
            assert!(
                !section.contains(forbidden),
                "payload algorithm handler should route `{forbidden}` through a named classifier"
            );
        }

        for required in [
            "PayloadFailure::UnsupportedAlgorithm",
            "fn unsupported_payload_algorithm_error(",
        ] {
            assert!(
                source.contains(required),
                "payload algorithm failure classification should include `{required}`"
            );
        }
    }

    #[test]
    fn payload_failure_classifier_preserves_public_schema_drift() {
        for failure in [
            PayloadFailure::MissingKeyId,
            PayloadFailure::MissingNonce,
            PayloadFailure::ShredNonEncrypted,
            PayloadFailure::MissingShredKeyId,
        ] {
            assert_eq!(payload_failure_to_mneme(failure), MnemeError::SchemaDrift);
        }

        assert_eq!(missing_payload_key_id_error(), MnemeError::SchemaDrift);
        assert_eq!(missing_payload_nonce_error(), MnemeError::SchemaDrift);
        assert_eq!(shred_non_encrypted_payload_error(), MnemeError::SchemaDrift);
        assert_eq!(
            missing_shred_payload_key_id_error(),
            MnemeError::SchemaDrift
        );
    }

    #[test]
    fn payload_failure_classifier_preserves_public_unsupported_version() {
        assert_eq!(
            payload_failure_to_mneme(PayloadFailure::UnsupportedAlgorithm(77)),
            MnemeError::UnsupportedVersion { got: 77 }
        );
        assert_eq!(
            unsupported_payload_algorithm_error(88),
            MnemeError::UnsupportedVersion { got: 88 }
        );
    }

    #[test]
    fn encrypted_payload_without_key_id_fails_closed() {
        let mut vault = MemoryKeyVault::new();
        let mut payload = seal_payload(&mut vault, b"secret", TEST_AAD).expect("seal payload");
        payload.key_id = None;

        assert_eq!(
            open_payload(&vault, &payload, TEST_AAD),
            Err(MnemeError::SchemaDrift)
        );
    }

    #[test]
    fn encrypted_payload_without_nonce_fails_closed() {
        let mut vault = MemoryKeyVault::new();
        let mut payload = seal_payload(&mut vault, b"secret", TEST_AAD).expect("seal payload");
        payload.nonce = None;

        assert_eq!(
            open_payload(&vault, &payload, TEST_AAD),
            Err(MnemeError::SchemaDrift)
        );
    }

    #[test]
    fn shred_plaintext_payload_fails_closed() {
        let mut vault = MemoryKeyVault::new();
        let payload = PayloadEnc {
            alg: PAYLOAD_ALG_PLAINTEXT,
            key_id: None,
            nonce: None,
            body: b"cleartext".to_vec(),
        };

        assert_eq!(
            shred_payload_key(&mut vault, &payload),
            Err(MnemeError::SchemaDrift)
        );
    }

    #[test]
    fn shred_encrypted_payload_without_key_id_fails_closed() {
        let mut vault = MemoryKeyVault::new();
        let payload = PayloadEnc {
            alg: PAYLOAD_ALG_XCHACHA20_POLY1305,
            key_id: None,
            nonce: Some([0x11; 24]),
            body: vec![0x22; 32],
        };

        assert_eq!(
            shred_payload_key(&mut vault, &payload),
            Err(MnemeError::SchemaDrift)
        );
    }
}
