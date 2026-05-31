use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use mneme_core::MnemeError;

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
