use mneme_cap::Capability as CapToken;
use mneme_core::{
    ActionReceipt, FORGET_PROOF_VERSION, ForgetMode, ForgetProof, ForgetTarget, MnemeError, Root,
};
use mneme_forget::{ShredOutcome, shred_witness_commit, verify_absence};
use mneme_smt::TREE_DEPTH;

#[cfg(any(feature = "phase_iii_verify", feature = "phase_iii_prove_forget"))]
use crate::forget;

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

pub fn verify_forget_proof(proof: &ForgetProof, root: &Root) -> Result<(), MnemeError> {
    if proof.version != FORGET_PROOF_VERSION {
        return Err(MnemeError::UnsupportedVersion { got: proof.version });
    }
    if proof.mode != ForgetMode::Shred {
        return Err(MnemeError::UnsupportedVersion {
            got: FORGET_PROOF_VERSION,
        });
    }
    if proof.root_bound != root.preimage_hash {
        return Err(MnemeError::ReceiptRootMismatch);
    }
    if proof.shred_commit == [0u8; 32] {
        return Err(MnemeError::ProvenanceBroken);
    }
    if proof.absence_path.len() != TREE_DEPTH {
        return Err(MnemeError::IndexPathInvalid);
    }
    let absence = forget::absence_proof_from_wire(proof, root);
    verify_absence(&absence)?;
    Ok(())
}

pub fn verify_forget_proof_bound(
    proof: &ForgetProof,
    root: &Root,
    target: &ForgetTarget,
    shred: &ShredOutcome,
) -> Result<(), MnemeError> {
    verify_forget_proof(proof, root)?;
    if forget::target_commit(target) != proof.target_commit {
        return Err(MnemeError::ProvenanceBroken);
    }
    if shred.key_hash != proof.target_commit {
        return Err(MnemeError::ProvenanceBroken);
    }
    if shred_witness_commit(shred) != proof.shred_commit {
        return Err(MnemeError::ProvenanceBroken);
    }
    Ok(())
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

#[cfg(test)]
mod redteam_forget {
    use super::*;
    use crate::forget::{ForgetProofWitness, mint_forget_proof};
    use mneme_core::{FORGET_PROOF_VERSION, ForgetMode, ForgetTarget, LogicalKey};
    use mneme_crypto::{MemoryKeyVault, seal_payload};
    use mneme_forget::{
        ShredForgetInput, forget_shred, payload_aad, prove_absent, shred_witness_commit,
    };
    use mneme_smt::SparseMerkleTree;

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

    fn shred_fixture() -> (
        LogicalKey,
        Root,
        ShredOutcome,
        mneme_smt::NonMembershipProof,
        SparseMerkleTree,
    ) {
        let key = LogicalKey {
            namespace: "gdpr".into(),
            name: "email".into(),
        };
        let mut vault = MemoryKeyVault::new();
        let mut record = mneme_core::ObjectRecord::fixture(mneme_core::MemoryKind::Semantic);
        let aad = payload_aad(&key);
        record.payload_enc = seal_payload(&mut vault, b"user@example.com", &aad).expect("seal");
        let bytes = mneme_core::to_bytes_canonical(&record).expect("encode");
        let id = mneme_core::hash_obj(&bytes);
        let key_hash = key.hash();
        let mut smt = SparseMerkleTree::new();
        smt.upsert(key_hash, id);
        let shred = forget_shred(ShredForgetInput {
            logical_key: &key,
            key_index: &mut smt,
            vault: &mut vault,
            object_bytes: Some(&bytes),
        })
        .expect("shred");
        let absence = prove_absent(&smt, &key).expect("absent");
        let mut root = sample_root();
        root.key_index_root = smt.root();
        (key, root, shred, absence, smt)
    }

    #[test]
    fn mint_and_verify_forget_proof_roundtrip() {
        let (key, root, shred, absence, _smt) = shred_fixture();
        let target = ForgetTarget::LogicalKey(key);
        let proof = mint_forget_proof(
            &target,
            ForgetMode::Shred,
            &root,
            &ForgetProofWitness {
                shred: &shred,
                absence: &absence,
            },
            None,
        )
        .unwrap();
        verify_forget_proof_bound(&proof, &root, &target, &shred).unwrap();
    }

    #[test]
    fn forgery_tampered_shred_commit_rejects() {
        let (key, root, shred, absence, _smt) = shred_fixture();
        let target = ForgetTarget::LogicalKey(key);
        let mut proof = mint_forget_proof(
            &target,
            ForgetMode::Shred,
            &root,
            &ForgetProofWitness {
                shred: &shred,
                absence: &absence,
            },
            None,
        )
        .unwrap();
        proof.shred_commit[0] ^= 1;
        assert_eq!(
            verify_forget_proof_bound(&proof, &root, &target, &shred),
            Err(MnemeError::ProvenanceBroken)
        );
    }

    #[test]
    fn forgery_tampered_absence_path_rejects() {
        let (key, root, shred, absence, _smt) = shred_fixture();
        let target = ForgetTarget::LogicalKey(key);
        let mut proof = mint_forget_proof(
            &target,
            ForgetMode::Shred,
            &root,
            &ForgetProofWitness {
                shred: &shred,
                absence: &absence,
            },
            None,
        )
        .unwrap();
        proof.absence_path[0][0] ^= 1;
        assert_eq!(
            verify_forget_proof(&proof, &root),
            Err(MnemeError::IndexPathInvalid)
        );
    }

    #[test]
    fn forgery_wrong_root_bound_rejects() {
        let (key, root, shred, absence, _smt) = shred_fixture();
        let target = ForgetTarget::LogicalKey(key);
        let proof = mint_forget_proof(
            &target,
            ForgetMode::Shred,
            &root,
            &ForgetProofWitness {
                shred: &shred,
                absence: &absence,
            },
            None,
        )
        .unwrap();
        let mut wrong = root.clone();
        wrong.preimage_hash[0] ^= 1;
        assert_eq!(
            verify_forget_proof(&proof, &wrong),
            Err(MnemeError::ReceiptRootMismatch)
        );
    }

    /// Resurrected target: stale absence proof after the key is live again.
    #[test]
    fn forgery_resurrected_live_key_rejects() {
        let (key, root, shred, absence, mut smt) = shred_fixture();
        let target = ForgetTarget::LogicalKey(key.clone());
        let proof = mint_forget_proof(
            &target,
            ForgetMode::Shred,
            &root,
            &ForgetProofWitness {
                shred: &shred,
                absence: &absence,
            },
            None,
        )
        .unwrap();
        smt.upsert(key.hash(), shred.object_id);
        let mut resurrected = root.clone();
        resurrected.key_index_root = smt.root();
        assert_eq!(
            verify_forget_proof(&proof, &resurrected),
            Err(MnemeError::IndexPathInvalid)
        );
    }

    #[test]
    fn forgery_zero_shred_commit_rejects() {
        let (key, root, shred, absence, _smt) = shred_fixture();
        let target = ForgetTarget::LogicalKey(key);
        let mut proof = mint_forget_proof(
            &target,
            ForgetMode::Shred,
            &root,
            &ForgetProofWitness {
                shred: &shred,
                absence: &absence,
            },
            None,
        )
        .unwrap();
        proof.shred_commit = [0u8; 32];
        assert_eq!(
            verify_forget_proof(&proof, &root),
            Err(MnemeError::ProvenanceBroken)
        );
    }

    #[test]
    fn redact_mode_proof_rejects_at_verify() {
        let (key, root, shred, absence, _smt) = shred_fixture();
        let target = ForgetTarget::LogicalKey(key);
        let mut proof = mint_forget_proof(
            &target,
            ForgetMode::Shred,
            &root,
            &ForgetProofWitness {
                shred: &shred,
                absence: &absence,
            },
            None,
        )
        .unwrap();
        proof.mode = ForgetMode::Redact;
        assert_eq!(
            verify_forget_proof(&proof, &root),
            Err(MnemeError::UnsupportedVersion {
                got: FORGET_PROOF_VERSION
            })
        );
    }

    #[test]
    fn shred_witness_commit_is_stable() {
        let (_key, _root, shred, _absence, _smt) = shred_fixture();
        let a = shred_witness_commit(&shred);
        let b = shred_witness_commit(&shred);
        assert_eq!(a, b);
        assert_ne!(a, [0u8; 32]);
    }
}
