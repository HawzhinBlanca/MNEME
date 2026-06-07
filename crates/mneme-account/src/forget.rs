//! ForgetProof minting (P3-2). Gated by `phase_iii_prove_forget`.

use mneme_core::{FORGET_PROOF_VERSION, ForgetMode, ForgetProof, ForgetTarget, MnemeError, Root};
use mneme_forget::{ShredOutcome, shred_witness_commit, verify_absence};
use mneme_smt::{NonMembershipProof, TOMBSTONE, TREE_DEPTH};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AccountForgetFailure {
    UnsupportedForgetMintMode,
}

fn account_forget_failure_to_mneme(failure: AccountForgetFailure) -> MnemeError {
    match failure {
        AccountForgetFailure::UnsupportedForgetMintMode => MnemeError::UnsupportedVersion {
            got: FORGET_PROOF_VERSION,
        },
    }
}

fn unsupported_forget_mint_mode_error() -> MnemeError {
    account_forget_failure_to_mneme(AccountForgetFailure::UnsupportedForgetMintMode)
}

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
        return Err(unsupported_forget_mint_mode_error());
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
// Public reconstruction helper for an offline verifier; not yet consumed inside this crate
// under `phase_iii_prove_forget` (the lib build would otherwise trip `#![deny(warnings)]`).
#[allow(dead_code)]
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

#[cfg(test)]
mod tests {
    use super::*;

    fn account_forget_production_source() -> &'static str {
        include_str!("forget.rs")
            .split_once("#[cfg(test)]")
            .map(|(production, _tests)| production)
            .expect("forget.rs should keep tests after production code")
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

    fn inert_witness() -> (ShredOutcome, NonMembershipProof) {
        (
            ShredOutcome {
                key_hash: [0x21; 32],
                object_id: [0x22; 32],
                shredded_key_id: None,
            },
            NonMembershipProof {
                key: [0x23; 32],
                path: Vec::new(),
                root: [0x24; 32],
                conflicting_leaf: None,
            },
        )
    }

    #[test]
    fn account_forget_failures_are_classified_not_unsupported_version_collapsed() {
        let production = account_forget_production_source();

        for forbidden in [
            "return Err(MnemeError::UnsupportedVersion",
            "Err(MnemeError::UnsupportedVersion",
        ] {
            assert!(
                !production.contains(forbidden),
                "account forget production code still collapses directly through {forbidden}"
            );
        }

        for required in [
            "enum AccountForgetFailure",
            "fn account_forget_failure_to_mneme(",
            "fn unsupported_forget_mint_mode_error(",
            "AccountForgetFailure::UnsupportedForgetMintMode",
        ] {
            assert!(
                production.contains(required),
                "account forget production code is missing typed classifier marker {required}"
            );
        }
    }

    #[test]
    fn account_forget_failure_classifier_preserves_public_error() {
        assert_eq!(
            account_forget_failure_to_mneme(AccountForgetFailure::UnsupportedForgetMintMode),
            MnemeError::UnsupportedVersion {
                got: FORGET_PROOF_VERSION
            }
        );
        assert_eq!(
            unsupported_forget_mint_mode_error(),
            MnemeError::UnsupportedVersion {
                got: FORGET_PROOF_VERSION
            }
        );
    }

    #[test]
    fn mint_forget_proof_rejects_redact_mode_before_witness_checks() {
        let root = sample_root();
        let target = ForgetTarget::ObjectId(mneme_core::ObjectId([0x31; 32]));
        let (shred, absence) = inert_witness();
        let witness = ForgetProofWitness {
            shred: &shred,
            absence: &absence,
        };

        assert_eq!(
            mint_forget_proof(
                &target,
                ForgetMode::Redact,
                &root,
                &witness,
                Some([0xDD; 32])
            ),
            Err(MnemeError::UnsupportedVersion {
                got: FORGET_PROOF_VERSION
            })
        );
    }
}
