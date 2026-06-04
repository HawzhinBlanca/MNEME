use mneme_cap::Capability as CapToken;
use mneme_core::{ActionReceipt, FORGET_PROOF_VERSION, ForgetProof, MnemeError, Root};
use mneme_crypto::{KeyPair, verify_signature_bytes, verifying_key_from_bytes};

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

pub fn verify_action_receipt(receipt: &ActionReceipt) -> Result<(), MnemeError> {
    let pk = verifying_key_from_bytes(&receipt.sanctioner)?;
    verify_signature_bytes(&pk, &receipt.signable_preimage(), &receipt.signature)
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
