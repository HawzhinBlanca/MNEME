//! ForgetProof minting (P3-2). Gated by `phase_iii_prove_forget`.

use mneme_core::{FORGET_PROOF_VERSION, ForgetMode, ForgetProof, ForgetTarget, MnemeError, Root};
use mneme_forget::{ShredOutcome, shred_witness_commit, verify_absence};
use mneme_smt::{NonMembershipProof, TOMBSTONE, TREE_DEPTH};

/// Witness bundle from a completed shred forget + `prove_absent`.
#[derive(Clone, Debug)]
pub struct ForgetProofWitness<'a> {
    pub shred: &'a ShredOutcome,
    pub absence: &'a NonMembershipProof,
}

pub fn target_commit(target: &ForgetTarget) -> [u8; 32] {
    match target {
        ForgetTarget::LogicalKey(k) => k.hash(),
        ForgetTarget::ObjectId(id) => id.0,
    }
}

pub fn mint_forget_proof(
    target: &ForgetTarget,
    mode: ForgetMode,
    root: &Root,
    witness: &ForgetProofWitness<'_>,
    cognition_cert_commit: Option<[u8; 32]>,
) -> Result<ForgetProof, MnemeError> {
    if mode != ForgetMode::Shred {
        return Err(MnemeError::UnsupportedVersion {
            got: FORGET_PROOF_VERSION,
        });
    }
    let commit = target_commit(target);
    if witness.shred.key_hash != commit {
        return Err(MnemeError::ProvenanceBroken);
    }
    if witness.absence.key != commit {
        return Err(MnemeError::ProvenanceBroken);
    }
    if witness.absence.root != root.key_index_root {
        return Err(MnemeError::ReceiptRootMismatch);
    }
    verify_absence(witness.absence)?;
    if witness.absence.path.len() != TREE_DEPTH {
        return Err(MnemeError::IndexPathInvalid);
    }
    let expected_shred = shred_witness_commit(witness.shred);
    Ok(ForgetProof {
        version: FORGET_PROOF_VERSION,
        target_commit: commit,
        mode,
        shred_commit: expected_shred,
        absence_path: witness.absence.path.clone(),
        root_bound: root.preimage_hash,
        cognition_cert_commit,
    })
}

/// Reconstruct the SMT non-membership proof carried on the wire (shred path ⇒ tombstone).
pub fn absence_proof_from_wire(proof: &ForgetProof, root: &Root) -> NonMembershipProof {
    NonMembershipProof {
        key: proof.target_commit,
        path: proof.absence_path.clone(),
        root: root.key_index_root,
        conflicting_leaf: match proof.mode {
            ForgetMode::Shred => Some((proof.target_commit, TOMBSTONE)),
            ForgetMode::Redact => None,
        },
    }
}

pub fn prove_forget_impl(
    target: &ForgetTarget,
    mode: ForgetMode,
    root: &Root,
    cognition_cert_commit: Option<[u8; 32]>,
    witness: &ForgetProofWitness<'_>,
) -> Result<ForgetProof, MnemeError> {
    match target {
        ForgetTarget::LogicalKey(_) => {}
        ForgetTarget::ObjectId(_) => return Err(MnemeError::CapDenied),
    }
    mint_forget_proof(target, mode, root, witness, cognition_cert_commit)
}
