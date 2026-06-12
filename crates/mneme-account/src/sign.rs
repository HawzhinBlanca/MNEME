//! ActionReceipt signing (P3-1 store path). Gated by `phase_iii_bind_action`.

use mneme_cap::Capability as CapToken;
use mneme_core::{ActionReceipt, MnemeError, Root};
use mneme_crypto::KeyPair;

pub fn mint_action_receipt(
    sanctioner: &KeyPair,
    action_commit: [u8; 32],
    capability: &CapToken,
    root: &Root,
    cognition_cert_commit: Option<[u8; 32]>,
) -> Result<ActionReceipt, MnemeError> {
    let capability_commit = capability.cap_id()?;
    let mut hlc = [0u8; 14];
    hlc.copy_from_slice(&root.hlc_max);
    let preimage = ActionReceipt {
        version: mneme_core::ACTION_RECEIPT_VERSION,
        action_commit,
        capability_commit,
        sanctioner: sanctioner.public_key_bytes(),
        root_bound: root.preimage_hash,
        hlc,
        cognition_cert_commit,
        signature: Vec::new(),
    };
    let sig = sanctioner.sign(&preimage.signable_preimage());
    Ok(ActionReceipt {
        signature: sig.to_vec(),
        ..preimage
    })
}

pub fn bind_action_impl(
    action_commit: [u8; 32],
    capability: &mneme_core::Capability,
    sanctioner_signer: &KeyPair,
    root: &Root,
    cognition_cert_commit: Option<[u8; 32]>,
) -> Result<ActionReceipt, MnemeError> {
    let cap = CapToken::from_core(capability.clone());
    cap.verify_signature_chain()?;
    mint_action_receipt(
        sanctioner_signer,
        action_commit,
        &cap,
        root,
        cognition_cert_commit,
    )
}

#[cfg(test)]
mod redteam_bind {
    use super::bind_action_impl;
    use mneme_cap::{Capability, Permissions};
    use mneme_core::TrustTier;
    use mneme_crypto::KeyPair;

    fn issuer() -> KeyPair {
        KeyPair::from_seed([0x01; 32])
    }
    fn sanctioner() -> KeyPair {
        KeyPair::from_seed([0x02; 32])
    }

    fn sample_capability() -> Capability {
        Capability::issue(
            &issuer(),
            issuer().public_key_bytes(),
            vec!["default".into()],
            vec![mneme_core::MemoryKind::Episodic],
            TrustTier::Identity,
            TrustTier::Working,
            Permissions::all(),
            vec![],
        )
        .unwrap()
    }

    fn sample_root() -> mneme_core::Root {
        mneme_core::Root {
            version: 1,
            preimage_hash: [0x10; 32],
            dag_head_root: [0x11; 32],
            key_index_root: [0x12; 32],
            semantic_commit: [0x13; 32],
            hlc_max: [0x14; 14],
            prev_root: [0x15; 32],
            signature: vec![0x00; 64],
            sequence: 7,
            vdf_proof: None,
            vdf_difficulty: None,
        }
    }

    #[test]
    fn bind_action_forgery_unsigned_cap_rejects() {
        let mut inner = sample_capability().into_core();
        inner.signature.clear();
        let root = sample_root();
        assert_eq!(
            bind_action_impl([0xAA; 32], &inner, &sanctioner(), &root, None).unwrap_err(),
            mneme_core::MnemeError::CapMalformed
        );
    }
}
