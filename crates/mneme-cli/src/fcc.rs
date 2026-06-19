//! FCC-1 — Forgetting-Closure Certificate (tiered: T1 crypto-shred, T2 + provable absence).
//!
//! A signed, offline-verifiable attestation over a real [`ForgetProof`] that records,
//! with a MANDATORY `tier_achieved` field, how completely a record was forgotten:
//!
//!   - **T1 CryptoShred** — the wrapping AEAD key was destroyed (`shred_commit`), so the
//!     stored ciphertext is unrecoverable.
//!   - **T2 TombstoneAbsence** — T1 plus a proof-of-absence (SMT non-membership) bound to
//!     the signed root, so the key is provably absent from the committed index.
//!
//! The tier is RE-DERIVED from the carried fields at verify time; a certificate that
//! claims a higher tier than its evidence supports is rejected even when correctly
//! signed (no overclaiming).
//!
//! HONESTY BOUNDARY (do not weaken): T1/T2 attest deletion of the MNEME-held record
//! (ciphertext unrecoverable; provably absent from the signed index). They do NOT prove
//! that a downstream model which once consumed the data has unlearned it — that is the
//! FCC-3 / T3 frontier (DP / certified-unlearning bound), not this certificate.
//! Authenticated ≠ erased-from-the-world; substrate deletion ≠ model unlearning.

use crate::replay::Reader;
use mneme_core::{ForgetMode, ForgetProof, MnemeError};
use mneme_crypto::{KeyPair, sign_message, verify_signature_bytes, verifying_key_from_bytes};

pub const FCC_CERT_VERSION: u16 = 1;
const PAYLOAD_DOMAIN: &[u8] = b"MNEME-fcc-cert-v1";
const ABSENCE_DOMAIN: &[u8] = b"MNEME-fcc-absence-v1";

/// Tier 1: crypto-shred only (wrapping key destroyed; ciphertext unrecoverable).
pub const TIER_CRYPTO_SHRED: u8 = 1;
/// Tier 2: crypto-shred + proof-of-absence bound to the signed root.
pub const TIER_TOMBSTONE_ABSENCE: u8 = 2;
/// Tier 3: DP influence-bound (requires epsilon, delta arguments).
pub const TIER_DP_INFLUENCE: u8 = 3;

const MODE_SHRED: u8 = 0;
const MODE_REDACT: u8 = 1;

pub const FCC_HONESTY: &str = "forgetting-closure: T1 attests the wrapping key was \
destroyed (ciphertext unrecoverable); T2 adds proof-of-absence bound to the signed root; \
T3(a) adds (epsilon, delta) DP influence-bound. \
Neither proves a downstream model that consumed the data has unlearned it (that is the FCC-3 \
certified-unlearning frontier). Substrate deletion != model unlearning; authenticated != \
erased-from-the-world";

pub const UNLEARNING_HONESTY: &str = "certified-unlearning: verified Spartan proof of \
weight-update correctness. HONESTY BOUNDARY: Spartan proof shows correct unlearning (e.g. \
Newton-step weight deletion) for a small reference model (<100M params). For large-scale \
frontier LLMs, exact unlearning via retraining or Newton-step is computationally prohibitive \
(large-model retrain cost gap). Therefore, this proof remains a scale-limited research scaffold (frontier).";

/// Offline-verifiable tiered forgetting-closure certificate (v1).
#[derive(Debug, Clone)]
pub struct ForgettingClosureCertV1 {
    pub root_seq: u64,
    /// Signed root the absence proof / deletion is bound to (`ForgetProof::root_bound`).
    pub root_preimage: [u8; 32],
    /// Commit of what was forgotten (logical-key hash or object id).
    pub target_commit: [u8; 32],
    /// Forget mode (0 = Shred, 1 = Redact).
    pub mode: u8,
    /// Crypto-shred witness commit (destruction of the wrapping key).
    pub shred_commit: [u8; 32],
    /// Commitment over the proof-of-absence path; all-zero ⇒ no absence proof carried.
    pub absence_proof_hash: [u8; 32],
    /// MANDATORY achieved tier; re-derived and checked at verify time.
    pub tier_achieved: u8,
    pub operator_pk: [u8; 32],
    pub sig: [u8; 64],
    // FCC-2 DP Fields
    pub dp_epsilon: Option<f64>,
    pub dp_delta: Option<f64>,
    // FCC-3 Certified Unlearning Fields
    pub unlearn_checkpoint_hash: Option<[u8; 32]>,
    pub unlearn_spartan_proof: Option<Vec<u8>>,
}

impl PartialEq for ForgettingClosureCertV1 {
    fn eq(&self, other: &Self) -> bool {
        self.root_seq == other.root_seq
            && self.root_preimage == other.root_preimage
            && self.target_commit == other.target_commit
            && self.mode == other.mode
            && self.shred_commit == other.shred_commit
            && self.absence_proof_hash == other.absence_proof_hash
            && self.tier_achieved == other.tier_achieved
            && self.operator_pk == other.operator_pk
            && self.sig == other.sig
            && self.dp_epsilon.map(|f| f.to_bits()) == other.dp_epsilon.map(|f| f.to_bits())
            && self.dp_delta.map(|f| f.to_bits()) == other.dp_delta.map(|f| f.to_bits())
            && self.unlearn_checkpoint_hash == other.unlearn_checkpoint_hash
            && self.unlearn_spartan_proof == other.unlearn_spartan_proof
    }
}

impl Eq for ForgettingClosureCertV1 {}

/// Commitment over a proof-of-absence path. Empty path ⇒ all-zero sentinel ("none").
pub fn absence_hash(path: &[[u8; 32]]) -> [u8; 32] {
    if path.is_empty() {
        return [0u8; 32];
    }
    let mut h = blake3::Hasher::new();
    h.update(ABSENCE_DOMAIN);
    h.update(&(path.len() as u64).to_le_bytes());
    for p in path {
        h.update(p);
    }
    *h.finalize().as_bytes()
}

/// Derive the achievable closure tier from the deletion evidence. Returns an error if
/// no crypto-shred is present (no closure to certify).
fn derive_tier(
    mode: u8,
    shred_commit: &[u8; 32],
    absence_proof_hash: &[u8; 32],
    dp_epsilon: Option<f64>,
    dp_delta: Option<f64>,
) -> Result<u8, MnemeError> {
    let has_shred = mode == MODE_SHRED && shred_commit != &[0u8; 32];
    let has_absence = absence_proof_hash != &[0u8; 32];
    if dp_epsilon.is_some() || dp_delta.is_some() {
        let eps = dp_epsilon.ok_or(MnemeError::ProvenanceBroken)?;
        let del = dp_delta.ok_or(MnemeError::ProvenanceBroken)?;
        if eps <= 0.0 || del < 0.0 || !eps.is_finite() || !del.is_finite() {
            return Err(MnemeError::ProvenanceBroken);
        }
        if !has_shred {
            return Err(MnemeError::ProvenanceBroken);
        }
        Ok(TIER_DP_INFLUENCE)
    } else if has_shred && has_absence {
        Ok(TIER_TOMBSTONE_ABSENCE)
    } else if has_shred {
        Ok(TIER_CRYPTO_SHRED)
    } else {
        Err(MnemeError::ProvenanceBroken)
    }
}

impl ForgettingClosureCertV1 {
    /// Build an (unsigned) certificate from a real `ForgetProof` and its root sequence.
    /// The tier is derived from the proof's evidence; `Redact`-mode proofs (no
    /// crypto-shred) are rejected — FCC certifies erasure, not accountable redaction.
    pub fn from_forget_proof(
        proof: &ForgetProof,
        root_seq: u64,
        dp_epsilon: Option<f64>,
        dp_delta: Option<f64>,
        unlearn_checkpoint_hash: Option<[u8; 32]>,
        unlearn_spartan_proof: Option<Vec<u8>>,
    ) -> Result<Self, MnemeError> {
        let mode = match proof.mode {
            ForgetMode::Shred => MODE_SHRED,
            ForgetMode::Redact => MODE_REDACT,
        };
        let absence_proof_hash = absence_hash(&proof.absence_path);
        let tier_achieved = derive_tier(
            mode,
            &proof.shred_commit,
            &absence_proof_hash,
            dp_epsilon,
            dp_delta,
        )?;
        Ok(Self {
            root_seq,
            root_preimage: proof.root_bound,
            target_commit: proof.target_commit,
            mode,
            shred_commit: proof.shred_commit,
            absence_proof_hash,
            tier_achieved,
            operator_pk: [0u8; 32],
            sig: [0u8; 64],
            dp_epsilon,
            dp_delta,
            unlearn_checkpoint_hash,
            unlearn_spartan_proof,
        })
    }

    fn payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(PAYLOAD_DOMAIN);
        out.extend_from_slice(&FCC_CERT_VERSION.to_le_bytes());
        out.extend_from_slice(&self.root_seq.to_le_bytes());
        out.extend_from_slice(&self.root_preimage);
        out.extend_from_slice(&self.target_commit);
        out.push(self.mode);
        out.extend_from_slice(&self.shred_commit);
        out.extend_from_slice(&self.absence_proof_hash);
        out.push(self.tier_achieved);
        out.extend_from_slice(&self.operator_pk);

        // DP Present flag + fields
        if let (Some(eps), Some(del)) = (self.dp_epsilon, self.dp_delta) {
            out.push(1);
            out.extend_from_slice(&eps.to_bits().to_le_bytes());
            out.extend_from_slice(&del.to_bits().to_le_bytes());
        } else {
            out.push(0);
        }

        // Unlearning Present flag + fields
        if let (Some(hash), Some(proof)) = (
            self.unlearn_checkpoint_hash.as_ref(),
            self.unlearn_spartan_proof.as_ref(),
        ) {
            out.push(1);
            out.extend_from_slice(hash);
            out.extend_from_slice(&(proof.len() as u32).to_le_bytes());
            out.extend_from_slice(proof);
        } else {
            out.push(0);
        }

        out
    }

    /// Sign the payload with the operator key and produce the final wire bytes.
    pub fn sign_and_encode(mut self, operator: &KeyPair) -> Result<Vec<u8>, MnemeError> {
        self.operator_pk = operator.public_key_bytes();
        let payload = self.payload();
        self.sig = sign_message(operator.signing_key(), &payload);
        let mut wire = payload;
        wire.extend_from_slice(&self.sig);
        Ok(wire)
    }

    /// Strict fail-closed decode + signature + tier re-derivation. A certificate whose
    /// `tier_achieved` does not equal the tier derived from its evidence is rejected,
    /// even with a valid signature (no overclaiming).
    pub fn verify(wire: &[u8], pinned_pk: Option<&[u8; 32]>) -> Result<Self, MnemeError> {
        let mut r = Reader::new(wire);
        r.expect(PAYLOAD_DOMAIN)?;
        let version = u16::from_le_bytes(r.take_arr::<2>()?);
        if version != FCC_CERT_VERSION {
            return Err(MnemeError::UnsupportedVersion { got: version });
        }
        let root_seq = u64::from_le_bytes(r.take_arr::<8>()?);
        let root_preimage = r.take_arr::<32>()?;
        let target_commit = r.take_arr::<32>()?;
        let mode = r.take_arr::<1>()?[0];
        if mode != MODE_SHRED && mode != MODE_REDACT {
            return Err(MnemeError::SchemaDrift);
        }
        let shred_commit = r.take_arr::<32>()?;
        let absence_proof_hash = r.take_arr::<32>()?;
        let tier_achieved = r.take_arr::<1>()?[0];
        let operator_pk = r.take_arr::<32>()?;

        // Parse optional DP fields
        let dp_present = r.take_arr::<1>()?[0];
        let (dp_epsilon, dp_delta) = if dp_present == 1 {
            let eps = f64::from_bits(u64::from_le_bytes(r.take_arr::<8>()?));
            let del = f64::from_bits(u64::from_le_bytes(r.take_arr::<8>()?));
            if eps <= 0.0 || del < 0.0 || !eps.is_finite() || !del.is_finite() {
                return Err(MnemeError::SchemaDrift);
            }
            (Some(eps), Some(del))
        } else if dp_present == 0 {
            (None, None)
        } else {
            return Err(MnemeError::SchemaDrift);
        };

        // Parse optional unlearning fields
        let unlearn_present = r.take_arr::<1>()?[0];
        let (unlearn_checkpoint_hash, unlearn_spartan_proof) = if unlearn_present == 1 {
            let hash = r.take_arr::<32>()?;
            let proof_len = u32::from_le_bytes(r.take_arr::<4>()?) as usize;
            let proof = r.take(proof_len)?.to_vec();
            (Some(hash), Some(proof))
        } else if unlearn_present == 0 {
            (None, None)
        } else {
            return Err(MnemeError::SchemaDrift);
        };

        let payload_len = r.consumed();
        let sig = r.take_arr::<64>()?;
        r.expect_end()?;

        if let Some(pk) = pinned_pk {
            if pk != &operator_pk {
                return Err(MnemeError::RootSigInvalid);
            }
        }
        let vk = verifying_key_from_bytes(&operator_pk)?;
        verify_signature_bytes(&vk, &wire[..payload_len], &sig)?;

        // Tier must equal what the carried evidence supports — reject overclaims.
        let derived = derive_tier(
            mode,
            &shred_commit,
            &absence_proof_hash,
            dp_epsilon,
            dp_delta,
        )?;
        if tier_achieved != derived {
            return Err(MnemeError::SchemaDrift);
        }

        Ok(Self {
            root_seq,
            root_preimage,
            target_commit,
            mode,
            shred_commit,
            absence_proof_hash,
            tier_achieved,
            operator_pk,
            sig,
            dp_epsilon,
            dp_delta,
            unlearn_checkpoint_hash,
            unlearn_spartan_proof,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proof(shred: bool, with_absence: bool, mode: ForgetMode) -> ForgetProof {
        ForgetProof {
            version: mneme_core::FORGET_PROOF_VERSION,
            target_commit: [0xaa; 32],
            mode,
            shred_commit: if shred { [0xbb; 32] } else { [0u8; 32] },
            absence_path: if with_absence {
                vec![[0x01; 32], [0x02; 32]]
            } else {
                vec![]
            },
            root_bound: [0xcd; 32],
            cognition_cert_commit: None,
        }
    }

    #[test]
    fn t2_roundtrip_sign_verify() {
        let op = KeyPair::from_seed([5u8; 32]);
        let cert = ForgettingClosureCertV1::from_forget_proof(
            &proof(true, true, ForgetMode::Shred),
            3,
            None,
            None,
            None,
            None,
        )
        .expect("derive");
        assert_eq!(cert.tier_achieved, TIER_TOMBSTONE_ABSENCE);
        let wire = cert.sign_and_encode(&op).expect("encode");
        let parsed =
            ForgettingClosureCertV1::verify(&wire, Some(&op.public_key_bytes())).expect("verify");
        assert_eq!(parsed.tier_achieved, TIER_TOMBSTONE_ABSENCE);
    }

    #[test]
    fn t1_when_no_absence_proof() {
        let cert = ForgettingClosureCertV1::from_forget_proof(
            &proof(true, false, ForgetMode::Shred),
            1,
            None,
            None,
            None,
            None,
        )
        .expect("derive");
        assert_eq!(cert.tier_achieved, TIER_CRYPTO_SHRED);
    }

    #[test]
    fn redact_without_shred_has_no_closure() {
        assert!(matches!(
            ForgettingClosureCertV1::from_forget_proof(
                &proof(false, true, ForgetMode::Redact),
                1,
                None,
                None,
                None,
                None
            ),
            Err(MnemeError::ProvenanceBroken)
        ));
    }

    #[test]
    fn overclaimed_tier_rejected_even_if_signed() {
        // Sign a cert that claims T2 but carries no absence proof → verify must reject.
        let op = KeyPair::from_seed([5u8; 32]);
        let mut cert = ForgettingClosureCertV1::from_forget_proof(
            &proof(true, false, ForgetMode::Shred),
            1,
            None,
            None,
            None,
            None,
        )
        .expect("derive");
        cert.tier_achieved = TIER_TOMBSTONE_ABSENCE; // overclaim
        let wire = cert.sign_and_encode(&op).expect("encode");
        assert!(matches!(
            ForgettingClosureCertV1::verify(&wire, None),
            Err(MnemeError::SchemaDrift)
        ));
    }

    #[test]
    fn t3_dp_influence_bound_roundtrip() {
        let op = KeyPair::from_seed([5u8; 32]);
        let cert = ForgettingClosureCertV1::from_forget_proof(
            &proof(true, true, ForgetMode::Shred),
            5,
            Some(1.5),
            Some(1e-5),
            None,
            None,
        )
        .expect("derive T3");
        assert_eq!(cert.tier_achieved, TIER_DP_INFLUENCE);
        assert_eq!(cert.dp_epsilon, Some(1.5));
        assert_eq!(cert.dp_delta, Some(1e-5));

        let wire = cert.sign_and_encode(&op).expect("encode");
        let parsed = ForgettingClosureCertV1::verify(&wire, Some(&op.public_key_bytes()))
            .expect("verify T3");
        assert_eq!(parsed.tier_achieved, TIER_DP_INFLUENCE);
        assert_eq!(parsed.dp_epsilon, Some(1.5));
        assert_eq!(parsed.dp_delta, Some(1e-5));
    }

    #[test]
    fn t3_unlearning_roundtrip() {
        let op = KeyPair::from_seed([5u8; 32]);
        let cp_hash = [0x55u8; 32];
        let spartan_proof = vec![0x11, 0x22, 0x33, 0x44];
        let cert = ForgettingClosureCertV1::from_forget_proof(
            &proof(true, true, ForgetMode::Shred),
            5,
            None,
            None,
            Some(cp_hash),
            Some(spartan_proof.clone()),
        )
        .expect("derive with unlearning");
        assert_eq!(cert.tier_achieved, TIER_TOMBSTONE_ABSENCE); // unlearning doesn't upgrade the basic tier itself unless DP is active
        assert_eq!(cert.unlearn_checkpoint_hash, Some(cp_hash));
        assert_eq!(cert.unlearn_spartan_proof.as_ref(), Some(&spartan_proof));

        let wire = cert.sign_and_encode(&op).expect("encode");
        let parsed =
            ForgettingClosureCertV1::verify(&wire, Some(&op.public_key_bytes())).expect("verify");
        assert_eq!(parsed.unlearn_checkpoint_hash, Some(cp_hash));
        assert_eq!(parsed.unlearn_spartan_proof.as_ref(), Some(&spartan_proof));
    }

    #[test]
    fn invalid_dp_values_rejected() {
        // negative epsilon
        assert!(
            ForgettingClosureCertV1::from_forget_proof(
                &proof(true, true, ForgetMode::Shred),
                5,
                Some(-0.1),
                Some(1e-5),
                None,
                None,
            )
            .is_err()
        );

        // negative delta
        assert!(
            ForgettingClosureCertV1::from_forget_proof(
                &proof(true, true, ForgetMode::Shred),
                5,
                Some(1.0),
                Some(-1e-5),
                None,
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn every_byte_flip_fails_closed() {
        let op = KeyPair::from_seed([5u8; 32]);
        let cp_hash = [0x55u8; 32];
        let spartan_proof = vec![0x11, 0x22, 0x33, 0x44];
        let wire = ForgettingClosureCertV1::from_forget_proof(
            &proof(true, true, ForgetMode::Shred),
            9,
            Some(1.5),
            Some(1e-5),
            Some(cp_hash),
            Some(spartan_proof),
        )
        .expect("derive")
        .sign_and_encode(&op)
        .expect("encode");
        for i in 0..wire.len() {
            let mut bad = wire.clone();
            bad[i] ^= 0x01;
            assert!(
                ForgettingClosureCertV1::verify(&bad, Some(&op.public_key_bytes())).is_err(),
                "byte flip at {i} must fail closed"
            );
        }
    }

    #[test]
    fn truncation_and_trailing_fail_closed() {
        let op = KeyPair::from_seed([5u8; 32]);
        let cp_hash = [0x55u8; 32];
        let spartan_proof = vec![0x11, 0x22, 0x33, 0x44];
        let wire = ForgettingClosureCertV1::from_forget_proof(
            &proof(true, true, ForgetMode::Shred),
            9,
            Some(1.5),
            Some(1e-5),
            Some(cp_hash),
            Some(spartan_proof),
        )
        .expect("derive")
        .sign_and_encode(&op)
        .expect("encode");
        assert!(ForgettingClosureCertV1::verify(&wire[..wire.len() - 1], None).is_err());
        let mut extra = wire.clone();
        extra.push(0);
        assert!(ForgettingClosureCertV1::verify(&extra, None).is_err());
    }

    #[test]
    fn wrong_pinned_pk_rejected() {
        let op = KeyPair::from_seed([5u8; 32]);
        let other = KeyPair::from_seed([6u8; 32]);
        let wire = ForgettingClosureCertV1::from_forget_proof(
            &proof(true, true, ForgetMode::Shred),
            9,
            None,
            None,
            None,
            None,
        )
        .expect("derive")
        .sign_and_encode(&op)
        .expect("encode");
        assert!(matches!(
            ForgettingClosureCertV1::verify(&wire, Some(&other.public_key_bytes())),
            Err(MnemeError::RootSigInvalid)
        ));
    }
}
