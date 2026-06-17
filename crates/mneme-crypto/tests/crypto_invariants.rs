use mneme_core::MnemeError;
use mneme_crypto::{
    EnvelopeKeyVault, KeyPair, KeyVault, MemoryKeyVault, PAYLOAD_ALG_XCHACHA20_POLY1305, open,
    open_payload, public_key_from_bytes, seal, seal_payload, shred_payload_key, sign_message,
    verify_signature, verify_signature_bytes,
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
        vault.begin_batch().expect("begin batch");
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

/// Drive a fixed sequence of [`KeyVault`] operations and record every observable
/// outcome as a string. Used to assert FileKeyVault and MemoryKeyVault are
/// behaviourally identical (B6 pluggability parity): same keys retrievable, same
/// typed errors on missing/shredded ids, same idempotent-import and batch semantics.
fn run_vault_parity_scenario(vault: &mut dyn KeyVault) -> Vec<String> {
    let mut log = Vec::new();
    let id_a = [0xa1u8; 16];
    let key_a = [0x11u8; 32];
    let id_b = [0xb2u8; 16];
    let key_b = [0x22u8; 32];
    let missing = [0xffu8; 16];

    // new_key: bytes are random per vault so they cannot match across backends, but
    // the *behaviour* must — a fresh key is retrievable and reported present.
    let (gen_key, gen_id) = vault.new_key().expect("new_key");
    log.push(format!(
        "new_key_get_matches={}",
        vault.get(&gen_id).map(|g| g == gen_key).unwrap_or(false)
    ));
    log.push(format!("new_key_contains={}", vault.contains(&gen_id)));

    // Empty / missing id.
    log.push(format!("get_missing={:?}", vault.get(&missing)));
    log.push(format!("contains_missing={}", vault.contains(&missing)));
    log.push(format!("shred_missing={:?}", vault.shred(&missing)));

    // Import known material, then read it back.
    log.push(format!("import_a={:?}", vault.import_key(&id_a, &key_a)));
    log.push(format!("get_a={:?}", vault.get(&id_a)));
    log.push(format!("contains_a={}", vault.contains(&id_a)));

    // Re-import is idempotent (no error, value unchanged).
    log.push(format!("reimport_a={:?}", vault.import_key(&id_a, &key_a)));
    log.push(format!("get_a_again={:?}", vault.get(&id_a)));

    // Shred A; B stays live.
    log.push(format!("import_b={:?}", vault.import_key(&id_b, &key_b)));
    log.push(format!("shred_a={:?}", vault.shred(&id_a)));
    log.push(format!("get_a_after_shred={:?}", vault.get(&id_a)));
    log.push(format!("contains_a_after_shred={}", vault.contains(&id_a)));
    log.push(format!("get_b_still_live={:?}", vault.get(&id_b)));

    // Re-importing a shredded id must fail closed with Forgotten on both backends.
    log.push(format!(
        "reimport_shredded_a={:?}",
        vault.import_key(&id_a, &key_a)
    ));

    // Batch window ops succeed on both (FileKeyVault journals, MemoryKeyVault no-ops).
    log.push(format!("begin_batch={:?}", vault.begin_batch()));
    log.push(format!("flush_batch={:?}", vault.flush_batch()));
    vault.cancel_batch();
    log
}

#[test]
fn envelope_vault_roundtrip_and_shred() {
    let master = [0xcd; 32];
    let dir = tempfile::tempdir().expect("tempdir");
    let mut vault = EnvelopeKeyVault::from_master(dir.path(), master).expect("envelope");
    let (key, id) = vault.new_key().expect("new");
    assert_eq!(vault.get(&id).expect("get"), key);
    vault.shred(&id).expect("shred");
    assert_eq!(vault.get(&id), Err(MnemeError::Forgotten));
    // Re-open from disk: shred tombstone survives.
    let reopened = EnvelopeKeyVault::from_master(dir.path(), master).expect("reopen");
    assert_eq!(reopened.get(&id), Err(MnemeError::Forgotten));
}

#[test]
fn envelope_and_memory_vaults_have_identical_behaviour() {
    let master = [0xee; 32];
    let mut memory = MemoryKeyVault::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let mut envelope = EnvelopeKeyVault::from_master(dir.path(), master).expect("envelope");
    let memory_log = run_vault_parity_scenario(&mut memory);
    let envelope_log = run_vault_parity_scenario(&mut envelope);
    assert_eq!(
        memory_log, envelope_log,
        "EnvelopeKeyVault must match MemoryKeyVault observable behaviour"
    );
}

#[test]
fn file_and_memory_vaults_have_identical_behaviour() {
    let mut memory = MemoryKeyVault::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let mut file = mneme_crypto::FileKeyVault::new(dir.path()).expect("file vault");

    let memory_log = run_vault_parity_scenario(&mut memory);
    let file_log = run_vault_parity_scenario(&mut file);

    assert_eq!(
        memory_log, file_log,
        "FileKeyVault and MemoryKeyVault must produce identical observable behaviour"
    );
}

#[test]
fn memory_vault_import_after_shred_is_forgotten() {
    let mut vault = MemoryKeyVault::new();
    let (_, key_id) = vault.new_key().expect("new key");
    vault.shred(&key_id).expect("shred");
    let key = [0x33u8; 32];
    assert_eq!(vault.import_key(&key_id, &key), Err(MnemeError::Forgotten));
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

#[test]
fn ed25519_batch_verify_roundtrip() {
    use mneme_crypto::verify_signatures_batch;

    let kp1 = KeyPair::from_seed([0x11; 32]);
    let kp2 = KeyPair::from_seed([0x22; 32]);
    let kp3 = KeyPair::from_seed([0x33; 32]);

    let msg1 = b"message 1";
    let msg2 = b"message 2";
    let msg3 = b"message 3";

    let sig1 = kp1.sign(msg1);
    let sig2 = kp2.sign(msg2);
    let sig3 = kp3.sign(msg3);

    let msgs: &[&[u8]] = &[msg1, msg2, msg3];
    let sigs = &[sig1, sig2, sig3];
    let pks = &[
        kp1.verifying_key(),
        kp2.verifying_key(),
        kp3.verifying_key(),
    ];

    // Honest batch verifies successfully.
    verify_signatures_batch(msgs, sigs, pks).expect("batch verification should pass");

    // Any invalid signature in the batch fails the entire verification closed.
    let mut bad_sigs = *sigs;
    bad_sigs[1][0] ^= 0xff; // flip byte
    verify_signatures_batch(msgs, &bad_sigs, pks)
        .expect_err("tampered signature should fail batch verify");

    // Length mismatch rejects batch verify.
    let mismatch_msgs: &[&[u8]] = &[msg1, msg2];
    verify_signatures_batch(mismatch_msgs, sigs, pks)
        .expect_err("length mismatch should fail batch verify");

    // Empty batch should be a no-op success.
    verify_signatures_batch(&[], &[], &[]).expect("empty batch verify should pass");
}

/// CRYPTO-BATCH-EQ: verify_signatures_batch and serial verify_signature must produce
/// **identical** accept/reject decisions for every input (i.e., batch verification is
/// not a weaker predicate than serial). This guards against the class of attacks
/// where a specially-crafted multi-signature batch passes batch verification but
/// any individual signature would fail.
#[test]
fn ed25519_batch_verify_is_equivalent_to_serial() {
    use mneme_crypto::{verify_signature, verify_signatures_batch};

    let keypairs: Vec<KeyPair> = (0u8..8)
        .map(|i| KeyPair::from_seed([i.wrapping_mul(0x11); 32]))
        .collect();
    let messages: Vec<Vec<u8>> = (0u8..8).map(|i| vec![i; 16]).collect();
    let sigs: Vec<[u8; 64]> = keypairs
        .iter()
        .zip(messages.iter())
        .map(|(kp, msg)| kp.sign(msg))
        .collect();
    let pks: Vec<_> = keypairs.iter().map(|kp| kp.verifying_key()).collect();

    let msgs_ref: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();

    // Base case: all-valid batch ⟺ all-valid serial.
    let batch_ok = verify_signatures_batch(&msgs_ref, &sigs, &pks).is_ok();
    let serial_ok = keypairs
        .iter()
        .zip(messages.iter())
        .zip(sigs.iter())
        .all(|((kp, msg), sig)| verify_signature(&kp.verifying_key(), msg, sig).is_ok());
    assert_eq!(
        batch_ok, serial_ok,
        "batch and serial must agree on the all-valid input"
    );

    // Fault injection: flip one signature byte at each position.
    for tamper_idx in 0..8 {
        let mut bad_sigs = sigs.clone();
        bad_sigs[tamper_idx][0] ^= 0xFF;

        let batch_rejects = verify_signatures_batch(&msgs_ref, &bad_sigs, &pks).is_err();
        let serial_rejects = keypairs
            .iter()
            .zip(messages.iter())
            .zip(bad_sigs.iter())
            .any(|((kp, msg), sig)| verify_signature(&kp.verifying_key(), msg, sig).is_err());

        // Batch must reject iff serial rejects at least one.
        assert!(
            batch_rejects || !serial_rejects,
            "batch accepted a batch that serial rejected at index {tamper_idx} — soundness violation!"
        );
        assert!(
            !batch_rejects || serial_rejects,
            "batch rejected a batch that serial fully accepted at index {tamper_idx} — false positive!"
        );
    }
}
