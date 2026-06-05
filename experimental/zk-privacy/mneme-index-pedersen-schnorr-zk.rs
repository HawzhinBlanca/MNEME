//! ZK retrieval backend — **12-month milestone (B3)**.
//!
//! ## Backend honesty (read this first)
//!
//! The blueprint's 12-month target names a *Plonky2/V3DB-style* (FRI-based) ZK retrieval
//! proof. The published `plonky2` crate (1.x) requires the **nightly** compiler
//! (`#![feature(specialization)]` in `plonky2_field`) and therefore cannot build on this
//! repo's pinned **stable** toolchain (`rust-toolchain.toml` = 1.86.0).
//!
//! Rather than fork to nightly or ship a non-working facade, this module links a **real, transparent,
//! zero-knowledge proof** that compiles on stable and reuses the `curve25519-dalek` already
//! present in the dependency tree: **Pedersen commitments + a Schnorr equality-of-openings
//! NIZK over the Ristretto group** (Fiat–Shamir, no trusted setup). It shares Plonky2/V3DB's
//! key honest property — *faithful execution with witness privacy and no trusted setup* —
//! while being buildable today. It is **not** Plonky2 and **not** a FRI/PLONK SNARK; do not
//! label it as such.
//!
//! ## Statement proven (zero-knowledge)
//!
//! Generators `G` (Ristretto basepoint) and `H` (nothing-up-my-sleeve, independent of `G`).
//! A Pedersen commitment is `Com(v, r) = v·G + r·H`.
//!
//! > "I know openings `(entry, r_e)` of the public commitment `public_commit = Com(entry, r_e)`
//! >  and `(query, r_q)` of a fresh commitment `query_commit = Com(query, r_q)` such that
//! >  `query == entry`."
//!
//! The proof is the equality `query_commit` plus a Schnorr proof of knowledge of
//! `s = r_e − r_q` with `public_commit − query_commit = s·H` (which exists iff the committed
//! *values* are equal). The verifier learns only the two commitments — neither `entry` nor
//! `query` is revealed (Pedersen is perfectly hiding; Schnorr is honest-verifier ZK).
//!
//! ## Honesty boundary (blueprint §3, preserved)
//!
//! This proves a *committed retrieval match* with zero-knowledge of the witness. It does
//! **not** prove semantic truth, that the entry is the true nearest neighbor, or that an
//! authenticated entry is factually correct. **Authenticated ≠ true.**
//!
//! v0/90-day still ships [`super::commitment_binding`] (feature `commitment_binding`): a
//! tagged BLAKE3 binding envelope that rejects forgeries but is **not** zero-knowledge.

use std::sync::OnceLock;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use mneme_core::MnemeError;
use rand::rngs::OsRng;

/// Public commitment length in bytes (one compressed Ristretto point).
pub const PUBLIC_COMMIT_LEN: usize = 32;
/// Proof length in bytes: `query_commit (32) || R (32) || z (32)`.
pub const PROOF_LEN: usize = 96;

/// Nothing-up-my-sleeve domain for deriving the second generator `H`.
const H_GENERATOR_DOMAIN: &[u8] = b"MNEME-ZK-RETRIEVAL-RISTRETTO-H-GENERATOR-v1";
/// Fiat–Shamir transcript domain separator.
const FS_DOMAIN: &[u8] = b"MNEME-ZK-RETRIEVAL-PEDERSEN-SCHNORR-v1";

/// Identifies the actual shipped proving backend (honesty export).
pub const ZK_BACKEND: &str = "pedersen-schnorr-ristretto-nizk (transparent, no trusted setup)";

/// Status tag for the B3 milestone (documentation / honesty exports).
pub const B3_DEFERRAL_STATUS: &str = "IMPLEMENTED (12-month milestone B3): real transparent zero-knowledge retrieval-match proof. \
     Backend is Pedersen commitments + Schnorr equality NIZK over Ristretto (no trusted setup) — NOT Plonky2/FRI, \
     because Plonky2 1.x is nightly-only (feature(specialization)) and the repo pins stable 1.86.0. Proves \
     zero-knowledge of a committed entry matching a hidden query; reveals only the public commitment. \
     Faithful-execution privacy — NOT semantic truth, NOT exact-NN. v0/90-day still uses commitment_binding \
     (BLAKE3 envelope, not ZK).";

/// Honesty boundary for the `pedersen_schnorr_zk` feature (named for the actual backend).
///
/// The `B3_DEFERRAL_STATUS` string (above) records the deferral from the blueprint's
/// Plonky2/V3DB SNARK target; the regression tests below assert this constant mentions
/// the Plonky2/FRI name only as a *non*-claim — protecting against future contributors
/// re-labelling the implementation in a way that misrepresents the backend.
pub const PEDERSEN_SCHNORR_HONESTY: &str = "ZK retrieval proof is a real zero-knowledge proof (Pedersen + Schnorr over Ristretto, transparent, \
     no trusted setup; NOT Plonky2, NOT FRI). It proves faithful execution of a retrieval-match predicate with \
     witness privacy; it is not semantic truth, not exact-NN, and not a claim that an authenticated entry is factually correct.";

/// Opaque ZK retrieval proof for a private retrieval-match statement.
///
/// `public_commit` is the binding+hiding Pedersen commitment to the stored `entry` (the value
/// the verifier checks against). `proof_bytes` = `query_commit (32) || R (32) || z (32)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PedersenSchnorrRetrievalProof {
    pub public_commit: [u8; PUBLIC_COMMIT_LEN],
    pub proof_bytes: Vec<u8>,
}

/// Private witness for a retrieval-match proof.
///
/// `entry` is the committed memory value (e.g. a folded semantic leaf); `query` is the
/// caller's lookup value. A valid proof exists iff `query == entry`, so the proof attests
/// that the hidden query matched the committed entry without revealing either.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetrievalWitness {
    pub entry: [u8; 32],
    pub query: [u8; 32],
}

impl RetrievalWitness {
    /// Build a witness where the query exactly matches the entry (the satisfiable case).
    pub fn matching(entry: [u8; 32]) -> Self {
        Self {
            entry,
            query: entry,
        }
    }
}

/// Second Pedersen generator `H`, derived deterministically from a fixed domain so nobody
/// knows its discrete log relative to `G` (nothing-up-my-sleeve).
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

fn scalar_from_bytes(bytes: &[u8; 32]) -> Scalar {
    Scalar::from_bytes_mod_order(*bytes)
}

fn commit(value: Scalar, blinding: Scalar) -> RistrettoPoint {
    value * RISTRETTO_BASEPOINT_POINT + blinding * (*generator_h())
}

/// Fiat–Shamir challenge over the public transcript `(domain, C_e, C_q, R)`.
fn fiat_shamir_challenge(
    public_commit: &CompressedRistretto,
    query_commit: &CompressedRistretto,
    nonce_point: &CompressedRistretto,
) -> Scalar {
    let mut reader = blake3::Hasher::new()
        .update(FS_DOMAIN)
        .update(public_commit.as_bytes())
        .update(query_commit.as_bytes())
        .update(nonce_point.as_bytes())
        .finalize_xof();
    let mut wide = [0u8; 64];
    reader.fill(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Generate a zero-knowledge retrieval-match proof.
///
/// Fails closed with [`MnemeError::ZkProofInvalid`] when the witness is unsatisfiable
/// (`query != entry`); a false statement cannot be proven.
pub fn prove_pedersen_schnorr(
    witness: &RetrievalWitness,
) -> Result<PedersenSchnorrRetrievalProof, MnemeError> {
    let entry = scalar_from_bytes(&witness.entry);
    let query = scalar_from_bytes(&witness.query);

    // A false statement (query != entry) is not provable; fail closed.
    if entry != query {
        return Err(MnemeError::ZkProofInvalid);
    }

    let mut rng = OsRng;
    let r_e = Scalar::random(&mut rng);
    let r_q = Scalar::random(&mut rng);

    let c_e = commit(entry, r_e).compress();
    let c_q = commit(query, r_q).compress();

    // D = C_e - C_q = (r_e - r_q)·H, since the value parts cancel. Prove knowledge of s.
    let s = r_e - r_q;

    // Schnorr proof of knowledge of s with D = s·H (base H), Fiat–Shamir non-interactive.
    let k = Scalar::random(&mut rng);
    let nonce_point = (k * (*generator_h())).compress();
    let challenge = fiat_shamir_challenge(&c_e, &c_q, &nonce_point);
    let z = k + challenge * s;

    let mut proof_bytes = Vec::with_capacity(PROOF_LEN);
    proof_bytes.extend_from_slice(c_q.as_bytes());
    proof_bytes.extend_from_slice(nonce_point.as_bytes());
    proof_bytes.extend_from_slice(z.as_bytes());

    Ok(PedersenSchnorrRetrievalProof {
        public_commit: *c_e.as_bytes(),
        proof_bytes,
    })
}

/// Verify a retrieval-match proof against a published `public_commit` (32 bytes).
///
/// Fails closed with [`MnemeError::ZkProofInvalid`] on malformed bytes, a public-commit
/// mismatch (the proof binds to a different committed entry than claimed), a non-canonical
/// scalar, or a failed Schnorr check.
pub fn verify_pedersen_schnorr(
    proof: &PedersenSchnorrRetrievalProof,
    public_commit: &[u8],
) -> Result<(), MnemeError> {
    if public_commit.len() != PUBLIC_COMMIT_LEN {
        return Err(MnemeError::ZkProofInvalid);
    }
    // The caller's published commitment must match the entry the proof binds to.
    if public_commit != proof.public_commit {
        return Err(MnemeError::ZkProofInvalid);
    }
    if proof.proof_bytes.len() != PROOF_LEN {
        return Err(MnemeError::ZkProofInvalid);
    }

    let c_e = CompressedRistretto::from_slice(&proof.public_commit)
        .map_err(|_| MnemeError::ZkProofInvalid)?;
    let c_q = CompressedRistretto::from_slice(&proof.proof_bytes[0..32])
        .map_err(|_| MnemeError::ZkProofInvalid)?;
    let nonce_point = CompressedRistretto::from_slice(&proof.proof_bytes[32..64])
        .map_err(|_| MnemeError::ZkProofInvalid)?;

    let mut z_bytes = [0u8; 32];
    z_bytes.copy_from_slice(&proof.proof_bytes[64..96]);
    let z = Option::<Scalar>::from(Scalar::from_canonical_bytes(z_bytes))
        .ok_or(MnemeError::ZkProofInvalid)?;

    let c_e_point = c_e.decompress().ok_or(MnemeError::ZkProofInvalid)?;
    let c_q_point = c_q.decompress().ok_or(MnemeError::ZkProofInvalid)?;
    let nonce = nonce_point.decompress().ok_or(MnemeError::ZkProofInvalid)?;

    // D = C_e - C_q. Verify z·H == R + c·D (Schnorr equality of committed values).
    let d = c_e_point - c_q_point;
    let challenge = fiat_shamir_challenge(&c_e, &c_q, &nonce_point);

    let lhs = z * (*generator_h());
    let rhs = nonce + challenge * d;

    if lhs == rhs {
        Ok(())
    } else {
        Err(MnemeError::ZkProofInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honesty_strings_preserve_boundary() {
        assert!(B3_DEFERRAL_STATUS.contains("12-month"));
        assert!(B3_DEFERRAL_STATUS.contains("NOT semantic truth"));
        assert!(B3_DEFERRAL_STATUS.contains("NOT exact-NN"));
        assert!(B3_DEFERRAL_STATUS.contains("NOT Plonky2/FRI"));
        assert!(PEDERSEN_SCHNORR_HONESTY.contains("zero-knowledge"));
        assert!(PEDERSEN_SCHNORR_HONESTY.contains("NOT Plonky2"));
        assert!(PEDERSEN_SCHNORR_HONESTY.contains("not semantic truth"));
        assert!(PEDERSEN_SCHNORR_HONESTY.contains("not exact-NN"));
        assert!(ZK_BACKEND.contains("pedersen-schnorr"));
        assert!(ZK_BACKEND.contains("no trusted setup"));
    }

    #[test]
    fn real_proof_round_trips() {
        let entry = [42u8; 32];
        let proof = prove_pedersen_schnorr(&RetrievalWitness::matching(entry)).expect("prove");
        assert_eq!(proof.proof_bytes.len(), PROOF_LEN);
        verify_pedersen_schnorr(&proof, &proof.public_commit).expect("verify");
    }

    #[test]
    fn proof_is_zero_knowledge_randomized() {
        // Two proofs over the same witness differ (fresh blindings) yet both verify, and
        // their public commitments differ (hiding) — the commitment leaks nothing.
        let entry = [7u8; 32];
        let p1 = prove_pedersen_schnorr(&RetrievalWitness::matching(entry)).expect("p1");
        let p2 = prove_pedersen_schnorr(&RetrievalWitness::matching(entry)).expect("p2");
        assert_ne!(
            p1.public_commit, p2.public_commit,
            "commitment must be hiding"
        );
        assert_ne!(p1.proof_bytes, p2.proof_bytes, "proof must be randomized");
        verify_pedersen_schnorr(&p1, &p1.public_commit).expect("verify p1");
        verify_pedersen_schnorr(&p2, &p2.public_commit).expect("verify p2");
    }

    #[test]
    fn unsatisfiable_witness_cannot_prove() {
        // query != entry => false statement => prove must fail closed.
        let mut entry = [3u8; 32];
        let mut query = [3u8; 32];
        entry[0] = 1;
        query[0] = 2;
        assert_eq!(
            prove_pedersen_schnorr(&RetrievalWitness { entry, query }),
            Err(MnemeError::ZkProofInvalid)
        );
    }

    #[test]
    fn wrong_public_commit_rejects() {
        let entry = [9u8; 32];
        let proof = prove_pedersen_schnorr(&RetrievalWitness::matching(entry)).expect("prove");
        let mut wrong = proof.public_commit;
        wrong[0] ^= 0x01;
        assert_eq!(
            verify_pedersen_schnorr(&proof, &wrong),
            Err(MnemeError::ZkProofInvalid)
        );
    }

    #[test]
    fn forged_response_scalar_rejects() {
        let entry = [11u8; 32];
        let mut proof = prove_pedersen_schnorr(&RetrievalWitness::matching(entry)).expect("prove");
        // Corrupt the Schnorr response z (last 32 bytes); the verification equation breaks.
        proof.proof_bytes[64] = proof.proof_bytes[64].wrapping_add(1);
        assert_eq!(
            verify_pedersen_schnorr(&proof, &proof.public_commit),
            Err(MnemeError::ZkProofInvalid)
        );
    }

    #[test]
    fn tampered_nonce_point_rejects() {
        let entry = [13u8; 32];
        let mut proof = prove_pedersen_schnorr(&RetrievalWitness::matching(entry)).expect("prove");
        proof.proof_bytes[32] ^= 0xff;
        assert_eq!(
            verify_pedersen_schnorr(&proof, &proof.public_commit),
            Err(MnemeError::ZkProofInvalid)
        );
    }

    #[test]
    fn swapped_query_commitment_rejects() {
        // Splice the query commitment from a *different* proof: the equality no longer holds,
        // and the Fiat–Shamir challenge no longer matches, so verification fails closed.
        let proof_a = prove_pedersen_schnorr(&RetrievalWitness::matching([1u8; 32])).expect("a");
        let proof_b = prove_pedersen_schnorr(&RetrievalWitness::matching([2u8; 32])).expect("b");
        let mut spliced = proof_a.clone();
        spliced.proof_bytes[0..32].copy_from_slice(&proof_b.proof_bytes[0..32]);
        assert_eq!(
            verify_pedersen_schnorr(&spliced, &spliced.public_commit),
            Err(MnemeError::ZkProofInvalid)
        );
    }

    #[test]
    fn malformed_commit_length_rejects() {
        let proof = prove_pedersen_schnorr(&RetrievalWitness::matching([11u8; 32])).expect("prove");
        assert_eq!(
            verify_pedersen_schnorr(&proof, &[0u8; 16]),
            Err(MnemeError::ZkProofInvalid)
        );
    }

    #[test]
    fn truncated_proof_bytes_reject() {
        let mut proof =
            prove_pedersen_schnorr(&RetrievalWitness::matching([11u8; 32])).expect("prove");
        proof.proof_bytes.truncate(8);
        assert_eq!(
            verify_pedersen_schnorr(&proof, &proof.public_commit),
            Err(MnemeError::ZkProofInvalid)
        );
    }
}
