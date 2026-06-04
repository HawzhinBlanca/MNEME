use mneme_cap::Capability as CapToken;
use mneme_core::{ActionReceipt, FORGET_PROOF_VERSION, ForgetProof, MnemeError, Root};

pub fn verify_action_receipt(receipt: &ActionReceipt) -> Result<(), MnemeError> {
    let pk = mneme_crypto::verifying_key_from_bytes(&receipt.sanctioner)?;
    mneme_crypto::verify_signature_bytes(&pk, &receipt.signable_preimage(), &receipt.signature)
}

pub fn verify_action_receipt_bound(
    receipt: &ActionReceipt,
    action_commit: [u8; 32],
    capability: &CapToken,
    root: &Root,
) -> Result<(), MnemeError> {
    verify_action_receipt(receipt)?;
    if receipt.action_commit != action_commit {
        return Err(MnemeError::ProvenanceBroken);
    }
    if receipt.capability_commit != capability.cap_id()? {
        return Err(MnemeError::CapMalformed);
    }
    if receipt.root_bound != root.preimage_hash {
        return Err(MnemeError::ReceiptRootMismatch);
    }
    Ok(())
}

pub fn verify_forget_proof(_proof: &ForgetProof) -> Result<(), MnemeError> {
    Err(MnemeError::UnsupportedVersion {
        got: FORGET_PROOF_VERSION,
    })
}

#[cfg(test)]
mod redteam {
    use super::*;
    use crate::sign::mint_action_receipt;
    use mneme_cap::{Capability, Permissions};
    use mneme_core::TrustTier;
    use mneme_crypto::KeyPair;

    fn issuer() -> KeyPair {
        KeyPair::from_seed([0x01; 32])
    }
    fn sanctioner() -> KeyPair {
        KeyPair::from_seed([0x02; 32])
    }
    fn impostor() -> KeyPair {
        KeyPair::from_seed([0x03; 32])
    }

    fn sample_capability() -> CapToken {
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

    fn sample_root() -> Root {
        Root {
            version: 1,
            preimage_hash: [0x10; 32],
            dag_head_root: [0x11; 32],
            key_index_root: [0x12; 32],
            semantic_commit: [0x13; 32],
            hlc_max: [0x14; 14],
            prev_root: [0x15; 32],
            signature: vec![0x00; 64],
            sequence: 7,
        }
    }

    /// Forgery: signature from a different key than sanctioner claims.
    #[test]
    fn forgery_wrong_signer_rejects() {
        let cap = sample_capability();
        let root = sample_root();
        let action = [0xAA; 32];
        let mut receipt = mint_action_receipt(&impostor(), action, &cap, &root, None).unwrap();
        receipt.sanctioner = sanctioner().public_key_bytes();
        assert_eq!(
            verify_action_receipt(&receipt),
            Err(MnemeError::RootSigInvalid)
        );
    }

    /// Forgery: flip one byte of the detached signature.
    #[test]
    fn forgery_tampered_signature_rejects() {
        let cap = sample_capability();
        let root = sample_root();
        let action = [0xBB; 32];
        let mut receipt = mint_action_receipt(&sanctioner(), action, &cap, &root, None).unwrap();
        receipt.signature[0] ^= 0x01;
        assert_eq!(
            verify_action_receipt(&receipt),
            Err(MnemeError::RootSigInvalid)
        );
    }

    /// Forgery: mutate action_commit after signing (preimage tamper).
    #[test]
    fn forgery_tampered_action_commit_rejects() {
        let cap = sample_capability();
        let root = sample_root();
        let action = [0xCC; 32];
        let mut receipt = mint_action_receipt(&sanctioner(), action, &cap, &root, None).unwrap();
        receipt.action_commit[0] ^= 0x01;
        assert_eq!(
            verify_action_receipt(&receipt),
            Err(MnemeError::RootSigInvalid)
        );
        assert_eq!(
            verify_action_receipt_bound(&receipt, action, &cap, &root),
            Err(MnemeError::RootSigInvalid)
        );
    }

    /// Forgery: mutate root_bound after signing.
    #[test]
    fn forgery_tampered_root_bound_rejects() {
        let cap = sample_capability();
        let root = sample_root();
        let action = [0xDD; 32];
        let mut receipt = mint_action_receipt(&sanctioner(), action, &cap, &root, None).unwrap();
        receipt.root_bound[0] ^= 0x01;
        assert_eq!(
            verify_action_receipt(&receipt),
            Err(MnemeError::RootSigInvalid)
        );
    }

    /// Forgery: splice cert commit from a different receipt into signed preimage.
    #[test]
    fn forgery_spliced_cognition_cert_commit_rejects() {
        let cap = sample_capability();
        let root = sample_root();
        let action = [0xEE; 32];
        let mut without = mint_action_receipt(&sanctioner(), action, &cap, &root, None).unwrap();
        let with =
            mint_action_receipt(&sanctioner(), action, &cap, &root, Some([0xFF; 32])).unwrap();
        without.cognition_cert_commit = with.cognition_cert_commit;
        assert_eq!(
            verify_action_receipt(&without),
            Err(MnemeError::RootSigInvalid)
        );
    }

    /// Forgery: empty signature must not verify.
    #[test]
    fn forgery_empty_signature_rejects() {
        let cap = sample_capability();
        let root = sample_root();
        let action = [0x11; 32];
        let mut receipt = mint_action_receipt(&sanctioner(), action, &cap, &root, None).unwrap();
        receipt.signature.clear();
        assert_eq!(
            verify_action_receipt(&receipt),
            Err(MnemeError::RootSigInvalid)
        );
    }

    /// Forgery: bound verify rejects action/root/cap mismatch even if sig verifies.
    #[test]
    fn forgery_bound_mismatch_rejects_after_valid_sig() {
        let cap = sample_capability();
        let root = sample_root();
        let action = [0x22; 32];
        let receipt = mint_action_receipt(&sanctioner(), action, &cap, &root, None).unwrap();
        let wrong_action = [0x23; 32];
        assert_eq!(
            verify_action_receipt_bound(&receipt, wrong_action, &cap, &root),
            Err(MnemeError::ProvenanceBroken)
        );
        let mut wrong_root = root.clone();
        wrong_root.preimage_hash[0] ^= 1;
        assert_eq!(
            verify_action_receipt_bound(&receipt, action, &cap, &wrong_root),
            Err(MnemeError::ReceiptRootMismatch)
        );
    }
}
