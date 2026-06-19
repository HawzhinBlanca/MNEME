use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use mneme_core::MnemeError;
use zeroize::Zeroize;

pub type PublicKeyBytes = [u8; 32];

#[derive(Clone)]
pub struct KeyPair {
    signing: SigningKey,
    verifying: VerifyingKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        Self::generate_with_seed().0
    }

    pub fn generate_with_seed() -> (Self, [u8; 32]) {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        (Self::from_seed(seed), seed)
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(&seed);
        let verifying = signing.verifying_key();
        Self { signing, verifying }
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }

    pub fn public_key_bytes(&self) -> PublicKeyBytes {
        self.verifying.to_bytes()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.verifying
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing
    }

    /// Derive the symmetric channel key used to AEAD-seal vault (payload-decryption)
    /// keys for transfer to a **same-trust-domain** peer over an untrusted §11 sync
    /// channel (B4). Domain-separated BLAKE3 over the operator signing seed:
    /// peers that share the operator key derive the identical key, so the recipient
    /// can decrypt and import the sender's per-object keys and recall its entries as
    /// plaintext. An A-NET adversary (no operator key) and a *different* operator
    /// derive a different key and therefore cannot open the sealed bundle — the
    /// confidentiality boundary of the keyless snapshot is preserved for everyone
    /// outside the trust domain. The signing key is never used directly as an
    /// encryption key (no Ed25519/X-key reuse); this is a one-way derived secret.
    pub fn vault_channel_key(&self) -> crate::types::ObjectKey {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"mneme-vault-sync-channel-v1");
        hasher.update(&self.signing.to_bytes());
        let mut out = [0u8; crate::types::OBJECT_KEY_LEN];
        out.copy_from_slice(&hasher.finalize().as_bytes()[..crate::types::OBJECT_KEY_LEN]);
        out
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        let mut seed = self.signing.to_bytes();
        seed.zeroize();
    }
}

#[derive(Clone, Debug)]
pub struct TrustConfig {
    pub operator_keys: Vec<PublicKeyBytes>,
    pub authorized_writers: Vec<PublicKeyBytes>,
    pub last_seen_hlc: Option<[u8; 14]>,
    pub last_root_hash: Option<[u8; 32]>,
}

impl TrustConfig {
    pub fn new(operator: PublicKeyBytes) -> Self {
        Self {
            operator_keys: vec![operator],
            authorized_writers: vec![operator],
            last_seen_hlc: None,
            last_root_hash: None,
        }
    }

    pub fn with_writer(mut self, writer: PublicKeyBytes) -> Self {
        if !self.authorized_writers.contains(&writer) {
            self.authorized_writers.push(writer);
        }
        self
    }

    /// Authorize the capability subject for `verify_recall` writer checks (BLAKE3(subject)).
    pub fn authorize_capability_subject(&mut self, subject: PublicKeyBytes) {
        if !self.authorized_writers.contains(&subject) {
            self.authorized_writers.push(subject);
        }
    }

    pub fn trusts_operator(&self, key: &PublicKeyBytes) -> bool {
        self.operator_keys.contains(key)
    }

    pub fn trusts_writer(&self, key: &[u8; 32]) -> bool {
        self.authorized_writers.iter().any(|k| {
            let hash = blake3::hash(k);
            hash.as_bytes() == key
        })
    }
}

/// Parse an Ed25519 verifying key from raw bytes.
pub fn public_key_from_bytes(bytes: &[u8; 32]) -> Result<VerifyingKey, MnemeError> {
    crate::sign::verifying_key_from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_signature;

    /// KEYS-1: from_seed is deterministic — same seed → same public key every time.
    /// A non-deterministic keygen would silently produce a different keypair on each
    /// run, breaking any stored public key reference.
    #[test]
    fn keypair_from_seed_is_deterministic() {
        let seed = [0xA1u8; 32];
        let kp1 = KeyPair::from_seed(seed);
        let kp2 = KeyPair::from_seed(seed);
        assert_eq!(
            kp1.public_key_bytes(),
            kp2.public_key_bytes(),
            "same seed must always produce the same public key"
        );
    }

    /// KEYS-2: sign + verify roundtrip succeeds for an arbitrary message.
    #[test]
    fn keypair_sign_verify_roundtrip() {
        let kp = KeyPair::from_seed([0x42u8; 32]);
        let msg = b"hello mneme security test";
        let sig = kp.sign(msg);
        let pk = public_key_from_bytes(&kp.public_key_bytes()).expect("valid pubkey");
        assert!(
            verify_signature(&pk, msg, &sig).is_ok(),
            "a freshly signed message must verify against its own public key"
        );
    }

    /// KEYS-3: A signature verified against the wrong public key must fail.
    /// This guards the core non-repudiation property — a signature is bound to one key.
    #[test]
    fn signature_rejected_for_wrong_public_key() {
        let signer = KeyPair::from_seed([0x11u8; 32]);
        let wrong = KeyPair::from_seed([0x22u8; 32]);
        let msg = b"message signed by signer, not wrong";
        let sig = signer.sign(msg);
        let wrong_pk = public_key_from_bytes(&wrong.public_key_bytes()).expect("valid pubkey");
        assert!(
            verify_signature(&wrong_pk, msg, &sig).is_err(),
            "signature must be rejected when verified against a different public key"
        );
    }

    /// KEYS-4: vault_channel_key is deterministic for the same seed.
    #[test]
    fn vault_channel_key_is_deterministic() {
        let kp = KeyPair::from_seed([0xBBu8; 32]);
        let k1 = kp.vault_channel_key();
        let k2 = kp.vault_channel_key();
        assert_eq!(k1, k2, "vault_channel_key must be deterministic");
        assert_ne!(k1, [0u8; 32], "vault_channel_key must not be all-zeros");
    }

    /// KEYS-5: vault_channel_key differs between two different keypairs.
    #[test]
    fn vault_channel_key_differs_between_keypairs() {
        let kp_a = KeyPair::from_seed([0x01u8; 32]);
        let kp_b = KeyPair::from_seed([0x02u8; 32]);
        assert_ne!(
            kp_a.vault_channel_key(),
            kp_b.vault_channel_key(),
            "distinct keypairs must produce distinct vault_channel_keys"
        );
    }

    /// KEYS-6: TrustConfig.trusts_operator and trusts_writer behave correctly.
    #[test]
    fn trust_config_operator_and_writer_checks() {
        let op = KeyPair::from_seed([0xCCu8; 32]);
        let other = KeyPair::from_seed([0xDDu8; 32]);
        let trust = TrustConfig::new(op.public_key_bytes());

        assert!(
            trust.trusts_operator(&op.public_key_bytes()),
            "operator key must be trusted"
        );
        assert!(
            !trust.trusts_operator(&other.public_key_bytes()),
            "non-operator key must not be trusted"
        );

        // trusts_writer checks BLAKE3(pubkey) against stored BLAKE3(pubkey) hashes
        let op_hash = *blake3::hash(&op.public_key_bytes()).as_bytes();
        assert!(
            trust.trusts_writer(&op_hash),
            "operator's writer hash must be trusted"
        );
        let other_hash = *blake3::hash(&other.public_key_bytes()).as_bytes();
        assert!(
            !trust.trusts_writer(&other_hash),
            "non-operator writer hash must not be trusted"
        );
    }
}
