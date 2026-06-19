use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use mneme_core::MnemeError;

use crate::types::ED25519_SIG_LEN;

pub fn sign_message(signing_key: &SigningKey, msg: &[u8]) -> [u8; ED25519_SIG_LEN] {
    signing_key.sign(msg).to_bytes()
}

pub fn verify_signature(
    pk: &VerifyingKey,
    msg: &[u8],
    sig: &[u8; ED25519_SIG_LEN],
) -> Result<(), MnemeError> {
    let signature = Signature::from_bytes(sig);
    pk.verify(msg, &signature)
        .map_err(|_| MnemeError::RootSigInvalid)
}

/// Verify a signature from a byte slice; rejects non-64-byte inputs fail-closed.
pub fn verify_signature_bytes(pk: &VerifyingKey, msg: &[u8], sig: &[u8]) -> Result<(), MnemeError> {
    let sig_bytes: [u8; ED25519_SIG_LEN] =
        sig.try_into().map_err(|_| MnemeError::RootSigInvalid)?;
    verify_signature(pk, msg, &sig_bytes)
}

/// Verify a batch of signatures, messages, and verifying keys using ed25519-dalek batch verification.
/// Rejects fail-closed if there is a signature mismatch, or if the slice lengths do not match.
pub fn verify_signatures_batch(
    msgs: &[&[u8]],
    sigs: &[[u8; ED25519_SIG_LEN]],
    pks: &[VerifyingKey],
) -> Result<(), MnemeError> {
    if msgs.len() != sigs.len() || msgs.len() != pks.len() {
        return Err(MnemeError::RootSigInvalid);
    }
    if msgs.is_empty() {
        return Ok(());
    }

    let parsed_sigs: Vec<Signature> = sigs.iter().map(Signature::from_bytes).collect();

    ed25519_dalek::verify_batch(msgs, &parsed_sigs, pks).map_err(|_| MnemeError::RootSigInvalid)
}

/// Parse an Ed25519 verifying key; invalid points fail closed.
pub fn verifying_key_from_bytes(bytes: &[u8; 32]) -> Result<VerifyingKey, MnemeError> {
    VerifyingKey::from_bytes(bytes).map_err(|_| MnemeError::RootSigInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn keypair(seed: u8) -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    /// SIGN-1: sign + verify roundtrip succeeds for an arbitrary message.
    #[test]
    fn sign_verify_roundtrip() {
        let (sk, vk) = keypair(0x01);
        let msg = b"mneme sign test";
        let sig = sign_message(&sk, msg);
        verify_signature(&vk, msg, &sig).expect("fresh signature must verify");
    }

    /// SIGN-2: A signature verified against a different public key must fail.
    #[test]
    fn verify_signature_rejects_wrong_key() {
        let (sk, _) = keypair(0x01);
        let (_, vk2) = keypair(0x02);
        let msg = b"signed by key 1";
        let sig = sign_message(&sk, msg);
        assert!(
            verify_signature(&vk2, msg, &sig).is_err(),
            "signature must be rejected when verified against a different public key"
        );
    }

    /// SIGN-3: verify_signature_bytes rejects a wrong-length (non-64-byte) input.
    #[test]
    fn verify_signature_bytes_rejects_wrong_length() {
        let (_, vk) = keypair(0x03);
        let short = [0u8; 32]; // 32 bytes, not 64
        assert!(
            verify_signature_bytes(&vk, b"msg", &short).is_err(),
            "32-byte input must be rejected as wrong length"
        );
        let long = [0u8; 65];
        assert!(
            verify_signature_bytes(&vk, b"msg", &long).is_err(),
            "65-byte input must be rejected as wrong length"
        );
    }

    /// SIGN-4: verify_signatures_batch succeeds for a valid batch.
    #[test]
    fn batch_verify_succeeds_for_valid_batch() {
        let (sk1, vk1) = keypair(0x10);
        let (sk2, vk2) = keypair(0x20);
        let msg1 = b"message one";
        let msg2 = b"message two";
        let sig1 = sign_message(&sk1, msg1);
        let sig2 = sign_message(&sk2, msg2);
        let msgs: Vec<&[u8]> = vec![msg1, msg2];
        let sigs = vec![sig1, sig2];
        let pks = vec![vk1, vk2];
        verify_signatures_batch(&msgs, &sigs, &pks).expect("valid batch must verify");
    }

    /// SIGN-5: verify_signatures_batch rejects a batch with a wrong key.
    #[test]
    fn batch_verify_rejects_wrong_key_in_batch() {
        let (sk1, _vk1) = keypair(0x10);
        let (_, vk2) = keypair(0x20); // vk2 doesn't match sk1
        let msg = b"msg";
        let sig = sign_message(&sk1, msg);
        let msgs: Vec<&[u8]> = vec![msg];
        let sigs = vec![sig];
        let pks = vec![vk2]; // wrong verifying key
        assert!(
            verify_signatures_batch(&msgs, &sigs, &pks).is_err(),
            "batch must be rejected when public key doesn't match"
        );
    }

    /// SIGN-6: verify_signatures_batch rejects mismatched slice lengths.
    #[test]
    fn batch_verify_rejects_mismatched_lengths() {
        let (sk, vk) = keypair(0x30);
        let msg = b"msg";
        let sig = sign_message(&sk, msg);
        let msgs: Vec<&[u8]> = vec![msg, msg];
        let sigs = vec![sig]; // only one sig for two msgs
        let pks = vec![vk, vk];
        assert!(
            verify_signatures_batch(&msgs, &sigs, &pks).is_err(),
            "mismatched lengths must be rejected"
        );
    }

    /// SIGN-7: verifying_key_from_bytes round-trips a real keypair's public bytes.
    #[test]
    fn verifying_key_from_bytes_roundtrips_real_pubkey() {
        let (sk, vk) = keypair(0x77);
        let pk_bytes = vk.to_bytes();
        let parsed = verifying_key_from_bytes(&pk_bytes)
            .expect("real public key bytes must parse successfully");
        // The parsed key must verify a signature made by the original keypair.
        let msg = b"roundtrip check";
        let sig = sign_message(&sk, msg);
        verify_signature(&parsed, msg, &sig).expect("parsed key must verify original signature");
    }
}
