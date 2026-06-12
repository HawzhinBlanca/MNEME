//! Trick #2 — Homomorphic context-set lock (research scaffold).
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use mneme_core::{
    DcborDecode, DcborEncode, Decoder, Encoder, MnemeError, ObjectId, from_bytes_strict,
    to_bytes_canonical,
};
use rand::rngs::OsRng;
use std::sync::OnceLock;
pub const F_SET_COMMIT: u64 = 1;
pub const F_CONTEXT_COMMIT: u64 = 2;
pub const F_PROOF_BYTES: u64 = 3;
pub const PUBLIC_COMMIT_LEN: usize = 32;
pub const CONTEXT_SET_LOCK_PROOF_LEN: usize = 96;
const H_GENERATOR_DOMAIN: &[u8] = b"MNEME-CONTEXT-SET-LOCK-RISTRETTO-H-GENERATOR-v1";
const FS_DOMAIN: &[u8] = b"MNEME-CONTEXT-SET-LOCK-PEDERSEN-SCHNORR-v1";
const ENTRY_SCALAR_DOMAIN: &[u8] = b"MNEME-CONTEXT-SET-LOCK-ENTRY-SCALAR-v1";
const ENTRY_BLINDING_DOMAIN: &[u8] = b"MNEME-CONTEXT-SET-LOCK-ENTRY-BLINDING-v1";
pub const CONTEXT_SET_LOCK_STATUS: &str = concat!(
    "SCAFFOLD: homomorphic context-set lock uses Pedersen additivity + Schnorr equality NIZK over Ristretto with domain tags disjoint from pedersen_schnorr_zk retrieval match. Sidecar only — not wired into recall_verified, not TCB, not semantic truth, not model attention."
);
pub const CONTEXT_SET_LOCK_HONESTY: &str = concat!(
    "Context-set lock scaffold proves homomorphic binding of a committed context multiset to carried entry ids only; it is not semantic truth, not exact-NN / not exact nearest-neighbor, not a claim that authenticated entries are factually correct, and not a substitute for Phase II strict context_gate bytes-only re-derivation or TEE attestation. Pedersen/Schnorr retrieval ZK remains retrieval-match only — do not conflate with Trick #2."
);
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContextSetLockProof {
    pub set_commit: [u8; PUBLIC_COMMIT_LEN],
    pub context_commit: [u8; PUBLIC_COMMIT_LEN],
    pub proof_bytes: Vec<u8>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContextSetLockFailure {
    EmptyEntrySet,
    SetCommitMismatch,
    ContextCommitMismatch,
    ProofByteLengthInvalid,
    SetCommitEncodingRejected,
    ContextCommitEncodingRejected,
    NonceEncodingRejected,
    ResponseScalarNonCanonical,
    SetCommitDecompressionRejected,
    ContextCommitDecompressionRejected,
    NonceDecompressionRejected,
    SchnorrEquationFailed,
    SidecarFieldMissing,
    SidecarProofLengthInvalid,
    SidecarCommitLengthInvalid,
}
fn context_set_lock_failure_to_mneme(f: ContextSetLockFailure) -> MnemeError {
    match f {
        ContextSetLockFailure::EmptyEntrySet
        | ContextSetLockFailure::SetCommitMismatch
        | ContextSetLockFailure::ContextCommitMismatch
        | ContextSetLockFailure::ProofByteLengthInvalid
        | ContextSetLockFailure::SetCommitEncodingRejected
        | ContextSetLockFailure::ContextCommitEncodingRejected
        | ContextSetLockFailure::NonceEncodingRejected
        | ContextSetLockFailure::ResponseScalarNonCanonical
        | ContextSetLockFailure::SetCommitDecompressionRejected
        | ContextSetLockFailure::ContextCommitDecompressionRejected
        | ContextSetLockFailure::NonceDecompressionRejected
        | ContextSetLockFailure::SchnorrEquationFailed
        | ContextSetLockFailure::SidecarFieldMissing
        | ContextSetLockFailure::SidecarProofLengthInvalid
        | ContextSetLockFailure::SidecarCommitLengthInvalid => MnemeError::ZkProofInvalid,
    }
}
fn generator_h() -> &'static RistrettoPoint {
    static H: OnceLock<RistrettoPoint> = OnceLock::new();
    H.get_or_init(|| {
        let mut reader = blake3::Hasher::new()
            .update(H_GENERATOR_DOMAIN)
            .finalize_xof();
        let mut wide = [0u8; 64];
        reader.fill(&mut wide);
        RistrettoPoint::from_uniform_bytes(&wide)
    })
}
fn scalar_from_domain(domain: &[u8], object_id: &ObjectId) -> Scalar {
    let mut reader = blake3::Hasher::new()
        .update(domain)
        .update(object_id.as_bytes())
        .finalize_xof();
    let mut wide = [0u8; 64];
    reader.fill(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}
pub fn hash_entry_scalar(object_id: &ObjectId) -> Scalar {
    scalar_from_domain(ENTRY_SCALAR_DOMAIN, object_id)
}
fn blinding_for_entry(object_id: &ObjectId) -> Scalar {
    scalar_from_domain(ENTRY_BLINDING_DOMAIN, object_id)
}
fn commit_entry(object_id: &ObjectId) -> RistrettoPoint {
    let value = hash_entry_scalar(object_id);
    let blinding = blinding_for_entry(object_id);
    value * RISTRETTO_BASEPOINT_POINT + blinding * (*generator_h())
}
fn fiat_shamir_challenge(
    set_commit: &CompressedRistretto,
    context_commit: &CompressedRistretto,
    nonce_point: &CompressedRistretto,
) -> Scalar {
    let mut reader = blake3::Hasher::new()
        .update(FS_DOMAIN)
        .update(set_commit.as_bytes())
        .update(context_commit.as_bytes())
        .update(nonce_point.as_bytes())
        .finalize_xof();
    let mut wide = [0u8; 64];
    reader.fill(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}
pub fn sum_set_commit(entries: &[ObjectId]) -> Result<[u8; PUBLIC_COMMIT_LEN], MnemeError> {
    if entries.is_empty() {
        return Err(context_set_lock_failure_to_mneme(
            ContextSetLockFailure::EmptyEntrySet,
        ));
    }
    let mut acc = RistrettoPoint::default();
    for entry in entries {
        acc += commit_entry(entry);
    }
    Ok(*acc.compress().as_bytes())
}
pub fn prove_context_set_lock(entries: &[ObjectId]) -> Result<ContextSetLockProof, MnemeError> {
    let set_commit = sum_set_commit(entries)?;
    let context_commit = set_commit;
    let c_set = CompressedRistretto::from_slice(&set_commit).map_err(|_| {
        context_set_lock_failure_to_mneme(ContextSetLockFailure::SetCommitEncodingRejected)
    })?;
    let c_ctx = CompressedRistretto::from_slice(&context_commit).map_err(|_| {
        context_set_lock_failure_to_mneme(ContextSetLockFailure::ContextCommitEncodingRejected)
    })?;
    let mut rng = OsRng;
    let k = Scalar::random(&mut rng);
    let nonce_point = (k * (*generator_h())).compress();
    let _challenge = fiat_shamir_challenge(&c_set, &c_ctx, &nonce_point);
    let mut proof_bytes = Vec::with_capacity(CONTEXT_SET_LOCK_PROOF_LEN);
    proof_bytes.extend_from_slice(&context_commit);
    proof_bytes.extend_from_slice(nonce_point.as_bytes());
    proof_bytes.extend_from_slice(k.as_bytes());
    Ok(ContextSetLockProof {
        set_commit,
        context_commit,
        proof_bytes,
    })
}
pub fn verify_context_set_lock(
    proof: &ContextSetLockProof,
    entries: &[ObjectId],
) -> Result<(), MnemeError> {
    let expected_set = sum_set_commit(entries)?;
    if expected_set != proof.set_commit {
        return Err(context_set_lock_failure_to_mneme(
            ContextSetLockFailure::SetCommitMismatch,
        ));
    }
    if proof.proof_bytes.len() != CONTEXT_SET_LOCK_PROOF_LEN {
        return Err(context_set_lock_failure_to_mneme(
            ContextSetLockFailure::ProofByteLengthInvalid,
        ));
    }
    if proof.proof_bytes[0..PUBLIC_COMMIT_LEN] != proof.context_commit {
        return Err(context_set_lock_failure_to_mneme(
            ContextSetLockFailure::ContextCommitMismatch,
        ));
    }
    let c_set = CompressedRistretto::from_slice(&proof.set_commit).map_err(|_| {
        context_set_lock_failure_to_mneme(ContextSetLockFailure::SetCommitEncodingRejected)
    })?;
    let c_ctx = CompressedRistretto::from_slice(&proof.context_commit).map_err(|_| {
        context_set_lock_failure_to_mneme(ContextSetLockFailure::ContextCommitEncodingRejected)
    })?;
    let nonce_point =
        CompressedRistretto::from_slice(&proof.proof_bytes[32..64]).map_err(|_| {
            context_set_lock_failure_to_mneme(ContextSetLockFailure::NonceEncodingRejected)
        })?;
    let mut z_bytes = [0u8; 32];
    z_bytes.copy_from_slice(&proof.proof_bytes[64..96]);
    let z = Option::<Scalar>::from(Scalar::from_canonical_bytes(z_bytes)).ok_or_else(|| {
        context_set_lock_failure_to_mneme(ContextSetLockFailure::ResponseScalarNonCanonical)
    })?;
    let c_set_point = c_set.decompress().ok_or_else(|| {
        context_set_lock_failure_to_mneme(ContextSetLockFailure::SetCommitDecompressionRejected)
    })?;
    let c_ctx_point = c_ctx.decompress().ok_or_else(|| {
        context_set_lock_failure_to_mneme(ContextSetLockFailure::ContextCommitDecompressionRejected)
    })?;
    let nonce = nonce_point.decompress().ok_or_else(|| {
        context_set_lock_failure_to_mneme(ContextSetLockFailure::NonceDecompressionRejected)
    })?;
    let d = c_set_point - c_ctx_point;
    let challenge = fiat_shamir_challenge(&c_set, &c_ctx, &nonce_point);
    if z * (*generator_h()) == nonce + challenge * d {
        Ok(())
    } else {
        Err(context_set_lock_failure_to_mneme(
            ContextSetLockFailure::SchnorrEquationFailed,
        ))
    }
}
impl DcborEncode for ContextSetLockProof {
    fn dcbor_encode(&self, enc: &mut Encoder) -> Result<(), MnemeError> {
        enc.begin_map(3)?;
        enc.encode_unsigned(F_SET_COMMIT)?;
        enc.encode_bytes(&self.set_commit)?;
        enc.encode_unsigned(F_CONTEXT_COMMIT)?;
        enc.encode_bytes(&self.context_commit)?;
        enc.encode_unsigned(F_PROOF_BYTES)?;
        enc.encode_bytes(&self.proof_bytes)?;
        Ok(())
    }
}
impl DcborDecode for ContextSetLockProof {
    fn dcbor_decode(dec: &mut Decoder<'_>) -> Result<Self, MnemeError> {
        let map = dec.decode_map()?;
        dec.ensure_consumed()?;
        let mut set_commit = None;
        let mut context_commit = None;
        let mut proof_bytes = None;
        for (key, value) in map {
            let field = key.as_u64().ok_or(context_set_lock_failure_to_mneme(
                ContextSetLockFailure::SidecarFieldMissing,
            ))?;
            match field {
                F_SET_COMMIT => set_commit = Some(parse_fixed32(&value)?),
                F_CONTEXT_COMMIT => context_commit = Some(parse_fixed32(&value)?),
                F_PROOF_BYTES => {
                    proof_bytes = Some(
                        value
                            .as_bytes()
                            .ok_or(context_set_lock_failure_to_mneme(
                                ContextSetLockFailure::SidecarFieldMissing,
                            ))?
                            .to_vec(),
                    )
                }
                _ => {
                    return Err(context_set_lock_failure_to_mneme(
                        ContextSetLockFailure::SidecarFieldMissing,
                    ));
                }
            }
        }
        let proof_bytes = proof_bytes.ok_or_else(|| {
            context_set_lock_failure_to_mneme(ContextSetLockFailure::SidecarFieldMissing)
        })?;
        if proof_bytes.len() != CONTEXT_SET_LOCK_PROOF_LEN {
            return Err(context_set_lock_failure_to_mneme(
                ContextSetLockFailure::SidecarProofLengthInvalid,
            ));
        }
        Ok(Self {
            set_commit: set_commit.ok_or_else(|| {
                context_set_lock_failure_to_mneme(ContextSetLockFailure::SidecarFieldMissing)
            })?,
            context_commit: context_commit.ok_or_else(|| {
                context_set_lock_failure_to_mneme(ContextSetLockFailure::SidecarFieldMissing)
            })?,
            proof_bytes,
        })
    }
}
fn parse_fixed32(value: &mneme_core::CborValue) -> Result<[u8; PUBLIC_COMMIT_LEN], MnemeError> {
    let bytes = value.as_bytes().ok_or(context_set_lock_failure_to_mneme(
        ContextSetLockFailure::SidecarFieldMissing,
    ))?;
    if bytes.len() != PUBLIC_COMMIT_LEN {
        return Err(context_set_lock_failure_to_mneme(
            ContextSetLockFailure::SidecarCommitLengthInvalid,
        ));
    }
    let mut out = [0u8; PUBLIC_COMMIT_LEN];
    out.copy_from_slice(bytes);
    Ok(out)
}
pub fn encode_context_set_lock_sidecar(proof: &ContextSetLockProof) -> Result<Vec<u8>, MnemeError> {
    to_bytes_canonical(proof)
}
pub fn decode_context_set_lock_sidecar(bytes: &[u8]) -> Result<ContextSetLockProof, MnemeError> {
    from_bytes_strict(bytes)
}
