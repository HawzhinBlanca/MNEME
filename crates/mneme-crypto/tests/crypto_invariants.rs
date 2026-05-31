use mneme_core::MnemeError;
use mneme_crypto::{
    KeyPair, KeyVault, MemoryKeyVault, PAYLOAD_ALG_XCHACHA20_POLY1305, open, open_payload,
    public_key_from_bytes, seal, seal_payload, shred_payload_key, sign_message, verify_signature,
    verify_signature_bytes,
};

const TEST_AAD: &[u8] = b"mneme-payload-v1";

#[test]
fn ed25519_sign_verify_roundtrip() {
    let kp = KeyPair::from_seed([0x42; 32]);
    let msg = b"MNEME root preimage";
    let sig = kp.sign(msg);
    verify_signature(&kp.verifying_key(), msg, &sig).expect("valid signature");
}

/// §18 `crypto` lane: fault-injection hook (expand to full matrix in Wave 1).
#[test]
fn fault_injection_ed25519_rejects_tampered_message() {
    let kp = KeyPair::from_seed([0x11; 32]);
    let sig = kp.sign(b"original");
    let err = verify_signature(&kp.verifying_key(), b"tampered", &sig).unwrap_err();
    assert_eq!(err, MnemeError::RootSigInvalid);
}

#[test]
fn ed25519_rejects_wrong_public_key() {
    let kp = KeyPair::from_seed([0x22; 32]);
    let other = KeyPair::from_seed([0x33; 32]);
    let sig = kp.sign(b"msg");
    let err = verify_signature(&other.verifying_key(), b"msg", &sig).unwrap_err();
    assert_eq!(err, MnemeError::RootSigInvalid);
}

#[test]
fn ed25519_rejects_malformed_signature_length() {
    let kp = KeyPair::from_seed([0x44; 32]);
    let pk = public_key_from_bytes(&kp.public_key_bytes()).expect("valid pk");
    let err = verify_signature_bytes(&pk, b"msg", &[0u8; 32]).unwrap_err();
    assert_eq!(err, MnemeError::RootSigInvalid);
}

#[test]
fn ed25519_sign_message_matches_keypair_sign() {
    let kp = KeyPair::from_seed([0x55; 32]);
    let msg = b"cap token";
    assert_eq!(sign_message(kp.signing_key(), msg), kp.sign(msg));
}

#[test]
fn aead_seal_open_roundtrip() {
    let key = [0x77u8; 32];
    let nonce = [0x01u8; 24];
    let plaintext = b"agent memory body";
    let ciphertext = seal(&key, &nonce, plaintext, TEST_AAD).expect("seal");
    let opened = open(&key, &nonce, &ciphertext, TEST_AAD).expect("open");
    assert_eq!(opened, plaintext);
}

#[test]
fn aead_rejects_tampered_ciphertext() {
    let key = [0x88u8; 32];
    let nonce = [0x02u8; 24];
    let mut ciphertext = seal(&key, &nonce, b"secret", TEST_AAD).expect("seal");
    if let Some(byte) = ciphertext.first_mut() {
        *byte ^= 0xff;
    }
    let err = open(&key, &nonce, &ciphertext, TEST_AAD).unwrap_err();
    assert_eq!(err, MnemeError::ObjectTampered);
}

#[test]
fn aead_rejects_wrong_key() {
    let key = [0x99u8; 32];
    let wrong = [0x00u8; 32];
    let nonce = [0x03u8; 24];
    let ciphertext = seal(&key, &nonce, b"secret", TEST_AAD).expect("seal");
    let err = open(&wrong, &nonce, &ciphertext, TEST_AAD).unwrap_err();
    assert_eq!(err, MnemeError::ObjectTampered);
}

#[test]
fn aead_rejects_wrong_nonce() {
    let key = [0xaau8; 32];
    let nonce = [0x04u8; 24];
    let other_nonce = [0x05u8; 24];
    let ciphertext = seal(&key, &nonce, b"secret", TEST_AAD).expect("seal");
    let err = open(&key, &other_nonce, &ciphertext, TEST_AAD).unwrap_err();
    assert_eq!(err, MnemeError::ObjectTampered);
}

#[test]
fn vault_new_key_get_roundtrip() {
    let mut vault = MemoryKeyVault::new();
    let (key, key_id) = vault.new_key().expect("new key");
    assert_eq!(vault.get(&key_id).expect("get"), key);
}

#[test]
fn vault_missing_key_returns_key_vault_missing() {
    let vault = MemoryKeyVault::new();
    let missing = [0xdeu8; 16];
    let err = vault.get(&missing).unwrap_err();
    assert_eq!(err, MnemeError::KeyVaultMissing);
}

#[test]
fn vault_shred_key_returns_forgotten_on_get() {
    let mut vault = MemoryKeyVault::new();
    let (_, key_id) = vault.new_key().expect("new key");
    vault.shred(&key_id).expect("shred");
    let err = vault.get(&key_id).unwrap_err();
    assert_eq!(err, MnemeError::Forgotten);
}

#[test]
fn payload_encrypt_decrypt_roundtrip() {
    let mut vault = MemoryKeyVault::new();
    let plaintext = b"quarantine tool output";
    let payload = seal_payload(&mut vault, plaintext, TEST_AAD).expect("seal payload");
    assert_eq!(payload.alg, PAYLOAD_ALG_XCHACHA20_POLY1305);
    assert!(payload.key_id.is_some());
    assert!(payload.nonce.is_some());
    let opened = open_payload(&vault, &payload, TEST_AAD).expect("open payload");
    assert_eq!(opened, plaintext);
}

#[test]
fn payload_decrypt_after_shred_returns_forgotten() {
    let mut vault = MemoryKeyVault::new();
    let payload = seal_payload(&mut vault, b"to forget", TEST_AAD).expect("seal");
    shred_payload_key(&mut vault, &payload).expect("shred");
    let err = open_payload(&vault, &payload, TEST_AAD).unwrap_err();
    assert_eq!(err, MnemeError::Forgotten);
}

#[test]
fn file_vault_persists_and_shreds_keys() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut vault = mneme_crypto::FileKeyVault::new(dir.path()).expect("file vault");
    let (key, key_id) = vault.new_key().expect("new key");
    drop(vault);

    let vault = mneme_crypto::FileKeyVault::new(dir.path()).expect("reopen");
    assert_eq!(vault.get(&key_id).expect("get persisted"), key);

    let mut vault = mneme_crypto::FileKeyVault::new(dir.path()).expect("reopen mut");
    vault.shred(&key_id).expect("shred");
    let err = vault.get(&key_id).unwrap_err();
    assert_eq!(err, MnemeError::Forgotten);
}

#[test]
fn vault_batch_journal_roundtrips_durably_without_per_key_files() {
    use mneme_crypto::FileKeyVault;
    let dir = tempfile::tempdir().expect("tempdir");
    let mut ids = Vec::new();
    {
        let mut vault = FileKeyVault::new(dir.path()).expect("vault");
        vault.begin_batch();
        for _ in 0..50 {
            let (_key, id) = vault.new_key().expect("new_key");
            ids.push(id);
            // mid-batch get works (key is live in memory before flush)
            assert!(vault.get(&id).is_ok());
        }
        // Before flush: no per-key files written (batched in memory).
        let vault_dir = dir.path().join("keys/vault");
        let files = std::fs::read_dir(&vault_dir)
            .map(|rd| rd.count())
            .unwrap_or(0);
        assert_eq!(
            files, 0,
            "batched keys must not write per-key files before flush"
        );
        vault.flush_batch().expect("flush");
        // After flush: exactly one journal file, no per-key files.
        let names: Vec<_> = std::fs::read_dir(&vault_dir)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect();
        assert_eq!(names, vec!["vault.journal".to_string()]);
    }
    // Reopen from disk: every batched key replays from the journal and decrypts.
    let reopened = mneme_crypto::FileKeyVault::new(dir.path()).expect("reopen");
    for id in &ids {
        assert!(
            reopened.get(id).is_ok(),
            "journal key {id:?} must survive reopen"
        );
    }
}

#[test]
fn vault_channel_key_is_deterministic_domain_separated_and_not_the_seed() {
    let seed = [0x42u8; 32];
    let a = KeyPair::from_seed(seed);
    let b = KeyPair::from_seed(seed);
    let other = KeyPair::from_seed([0x99u8; 32]);

    // Same operator seed → identical channel key (so same-domain peers converge).
    assert_eq!(
        a.vault_channel_key(),
        b.vault_channel_key(),
        "same operator must derive the same B4 channel key"
    );
    // Different operator seed → different channel key (cross-domain cannot decrypt).
    assert_ne!(
        a.vault_channel_key(),
        other.vault_channel_key(),
        "different operators must derive different channel keys"
    );
    // The channel key must NOT equal the raw signing seed (no key reuse).
    assert_ne!(
        a.vault_channel_key(),
        seed,
        "channel key must be a derived secret, not the signing seed"
    );

    // The derived channel key actually works as an AEAD key (seal/open round-trip).
    let key = a.vault_channel_key();
    let nonce = mneme_crypto::random_nonce();
    let ct = seal(&key, &nonce, b"bundle", b"mneme-vault-sync-v1").expect("seal");
    let pt = open(&key, &nonce, &ct, b"mneme-vault-sync-v1").expect("open");
    assert_eq!(pt, b"bundle");
    // A foreign operator's key cannot open it.
    assert!(
        open(
            &other.vault_channel_key(),
            &nonce,
            &ct,
            b"mneme-vault-sync-v1"
        )
        .is_err(),
        "foreign channel key must fail AEAD open"
    );
}
