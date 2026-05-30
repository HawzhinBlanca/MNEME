//! Capability sig-chain tamper cases (§17.2).

use mneme_cap::{Capability, Permissions, agent_cap};
use mneme_core::{Caveat, Hlc, MemoryKind, MnemeError, NodeId, TrustTier};
use mneme_crypto::KeyPair;

fn test_hlc(wall_ms: u64) -> Hlc {
    Hlc {
        wall_ms,
        counter: 0,
        node_id: NodeId([0x07; 16]),
    }
}

macro_rules! cap_tamper {
    ($name:ident, |$c:ident| $body:stmt, $expected:expr) => {
        #[test]
        fn $name() {
            let issuer = KeyPair::from_seed([0x01; 32]);
            let subject = KeyPair::from_seed([0x02; 32]);
            let mut cap = mneme_cap::tool_channel_cap(&issuer, subject.public_key_bytes()).unwrap();
            {
                let $c = &mut cap;
                $body
            }
            let err = cap.verify(&issuer, &test_hlc(1)).unwrap_err();
            assert_eq!(err, $expected, "case {}", stringify!($name));
        }
    };
}

cap_tamper!(
    cap_sig_byte_2,
    |c| c.signature[2] ^= 0x01,
    MnemeError::CapDenied
);
cap_tamper!(
    cap_sig_byte_3,
    |c| c.signature[3] ^= 0x02,
    MnemeError::CapDenied
);
cap_tamper!(
    cap_sig_byte_4,
    |c| c.signature[4] ^= 0x04,
    MnemeError::CapDenied
);
cap_tamper!(
    cap_sig_byte_5,
    |c| c.signature[5] ^= 0x08,
    MnemeError::CapDenied
);
cap_tamper!(
    cap_sig_byte_6,
    |c| c.signature[6] ^= 0x10,
    MnemeError::CapDenied
);
cap_tamper!(
    cap_sig_byte_7,
    |c| c.signature[7] ^= 0x20,
    MnemeError::CapDenied
);
cap_tamper!(
    cap_sig_byte_8,
    |c| c.signature[8] ^= 0x40,
    MnemeError::CapDenied
);
cap_tamper!(
    cap_sig_byte_9,
    |c| c.signature[9] ^= 0x80,
    MnemeError::CapDenied
);
cap_tamper!(
    cap_sig_byte_10,
    |c| c.signature[10] ^= 0x01,
    MnemeError::CapDenied
);
cap_tamper!(
    cap_sig_byte_11,
    |c| c.signature[11] ^= 0x02,
    MnemeError::CapDenied
);
cap_tamper!(
    cap_sig_byte_12,
    |c| c.signature[12] ^= 0x04,
    MnemeError::CapDenied
);
cap_tamper!(
    cap_sig_byte_13,
    |c| c.signature[13] ^= 0x08,
    MnemeError::CapDenied
);
cap_tamper!(
    cap_sig_byte_14,
    |c| c.signature[14] ^= 0x10,
    MnemeError::CapDenied
);
cap_tamper!(
    cap_sig_byte_15,
    |c| c.signature[15] ^= 0x20,
    MnemeError::CapDenied
);
cap_tamper!(
    cap_sig_byte_0,
    |c| c.signature[0] ^= 0x01,
    MnemeError::CapDenied
);
cap_tamper!(
    cap_sig_byte_1,
    |c| c.signature[1] ^= 0x02,
    MnemeError::CapDenied
);
cap_tamper!(
    cap_sig_byte_31,
    |c| c.signature[31] ^= 0x04,
    MnemeError::CapDenied
);
cap_tamper!(
    cap_sig_byte_63,
    |c| {
        if c.signature.len() > 63 {
            c.signature[63] ^= 0x08;
        }
    },
    MnemeError::CapDenied
);
cap_tamper!(
    cap_sig_truncated,
    |c| c.signature.truncate(32),
    MnemeError::CapMalformed
);
cap_tamper!(
    cap_sig_garbage_appended,
    |c| c.signature.push(0xff),
    MnemeError::CapMalformed
);
cap_tamper!(
    cap_permissions_widened,
    |c| c.permissions |= 0x80,
    MnemeError::CapDenied
);
cap_tamper!(
    cap_issuer_swap,
    |c| c.issuer[0] ^= 0x01,
    MnemeError::CapDenied
);
cap_tamper!(
    cap_subject_swap,
    |c| c.subject[0] ^= 0x02,
    MnemeError::CapMalformed
);
cap_tamper!(
    cap_tier_max_inflated,
    |c| c.tier_max = TrustTier::Identity.as_u8(),
    MnemeError::CapDenied
);
cap_tamper!(
    cap_namespace_tamper,
    |c| {
        if !c.namespaces.is_empty() {
            c.namespaces[0].push('x');
        }
    },
    MnemeError::CapDenied
);
cap_tamper!(
    cap_kinds_tamper,
    |c| {
        if !c.kinds.is_empty() {
            c.kinds[0] ^= 0x01;
        }
    },
    MnemeError::CapDenied
);

#[test]
fn cap_expired_not_after() {
    let issuer = KeyPair::from_seed([0x03; 32]);
    let subject = KeyPair::from_seed([0x04; 32]);
    let cap = Capability::issue(
        &issuer,
        subject.public_key_bytes(),
        vec!["*".into()],
        vec![MemoryKind::Semantic],
        TrustTier::Working,
        TrustTier::Working,
        Permissions::READ,
        vec![Caveat::NotAfter(test_hlc(10))],
    )
    .unwrap();
    assert_eq!(
        cap.verify(&issuer, &test_hlc(10)).unwrap_err(),
        MnemeError::CapExpired
    );
}

#[test]
fn cap_attenuated_sig_chain_tamper() {
    let issuer = KeyPair::from_seed([0x05; 32]);
    let subject = KeyPair::from_seed([0x06; 32]);
    let root = agent_cap(&issuer, subject.public_key_bytes()).unwrap();
    let narrowed = root
        .attenuate(&subject, vec![Caveat::NamespacePrefix("tools/".into())])
        .unwrap();
    let mut bad = narrowed.clone();
    bad.signature[64] ^= 0x01;
    assert_eq!(
        bad.verify(&issuer, &test_hlc(1)).unwrap_err(),
        MnemeError::CapDenied
    );
}
