//! Integration tests for capability sig-chain tamper cases (§17.2).

use mneme_cap::{Capability, Permissions, agent_cap};
use mneme_core::{Caveat, Hlc, MemoryKind, MnemeError, NodeId, TrustTier};
use mneme_crypto::KeyPair;

fn test_hlc(wall_ms: u64) -> Hlc {
    Hlc {
        wall_ms,
        counter: 0,
        node_id: NodeId([0x02; 16]),
    }
}

#[test]
fn cap_sig_chain_every_byte_tamper_rejected() {
    let issuer = KeyPair::from_seed([0x01; 32]);
    let subject = KeyPair::from_seed([0x02; 32]);
    let cap = agent_cap(&issuer, subject.public_key_bytes()).unwrap();
    let chain = cap.sig_chain().unwrap();
    assert_eq!(chain.len(), 1);

    for i in 0..cap.signature.len() {
        let mut tampered = cap.clone();
        tampered.signature[i] ^= 0x01;
        assert_eq!(
            tampered.verify(&issuer, &test_hlc(1)).unwrap_err(),
            MnemeError::CapDenied,
            "sig byte {i}"
        );
    }
}

#[test]
fn cap_dcbor_wire_byte_tamper_rejected() {
    let issuer = KeyPair::from_seed([0x05; 32]);
    let subject = KeyPair::from_seed([0x06; 32]);
    let cap = agent_cap(&issuer, subject.public_key_bytes()).unwrap();
    let wire = cap.to_bytes().unwrap();
    assert!(!wire.is_empty());
    for i in 0..wire.len() {
        let mut tampered = wire.clone();
        tampered[i] ^= 0x01;
        let decoded = Capability::from_bytes(&tampered);
        match decoded {
            Ok(dec) => {
                let err = dec.verify(&issuer, &test_hlc(1)).unwrap_err();
                assert!(
                    matches!(err, MnemeError::CapDenied | MnemeError::CapMalformed),
                    "wire byte {i}: {err:?}"
                );
            }
            Err(
                MnemeError::SchemaDrift
                | MnemeError::CapMalformed
                | MnemeError::SerializationNonCanonical,
            ) => {}
            Err(other) => panic!("unexpected decode error at wire byte {i}: {other:?}"),
        }
    }
}

#[test]
fn cap_preimage_tamper_changes_cap_id() {
    let issuer = KeyPair::from_seed([0x03; 32]);
    let subject = KeyPair::from_seed([0x04; 32]);
    let cap = Capability::issue(
        &issuer,
        subject.public_key_bytes(),
        vec!["ns".into()],
        vec![MemoryKind::Semantic],
        TrustTier::Working,
        TrustTier::Working,
        Permissions::READ,
        vec![Caveat::NotAfter(test_hlc(u64::MAX / 8))],
    )
    .unwrap();
    let id0 = cap.cap_id().unwrap();
    let mut bad = cap.clone();
    bad.permissions ^= 0x01;
    let id1 = bad.cap_id().unwrap();
    assert_ne!(id0, id1);
    assert_eq!(
        bad.verify(&issuer, &test_hlc(1)).unwrap_err(),
        MnemeError::CapDenied
    );
}
