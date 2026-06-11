//! ZK retrieval backend — **12-month milestone (B3)**.
//!
//! ## Backend honesty (read this first)
//!
//! The blueprint's 12-month target names a *Plonky2/V3DB-style* (FRI-based) ZK retrieval
//! proof. The published `plonky2` crate (1.x) requires the **nightly** compiler
//! (`#![feature(specialization)]` in `plonky2_field`) and therefore cannot build on this
//! repo's pinned **stable** toolchain (`rust-toolchain.toml` = 1.86.0).
//!
//! Rather than fork to nightly or ship a stub, this module links a **real, transparent,
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
//! authenticated entry is factually correct. It also does not upgrade Phase I
//! `ExactDominance`: current v1 proves membership/completeness plus top-k over
//! prover-asserted distances; true top-k ranking is not proven and this is not
//! top-k by true query-to-embedding distance until verifiers recompute candidate distances.
//! **Authenticated ≠ true.**
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
/// Fiat–Shamir transcript domain separator (retrieval-match / scalar equality).
const FS_DOMAIN: &[u8] = b"MNEME-ZK-RETRIEVAL-PEDERSEN-SCHNORR-v1";
/// Hash-to-group domain for multiset elements `h_set(x)` (Connection 1 / ECMH map).
/// Load-bearing: MUST NOT reuse `H_GENERATOR_DOMAIN` — independent generator derivation.
const H_SET_DOMAIN: &[u8] = b"MNEME-ZK-SET-EQUALITY-H-SET-v1";
/// Fiat–Shamir domain for set-equality Schnorr proofs (Connection 1).
/// Load-bearing: MUST NOT reuse `FS_DOMAIN` — cross-protocol replay would otherwise verify.
const FS_SET_EQUALITY_DOMAIN: &[u8] = b"MNEME-ZK-SET-EQUALITY-PEDERSEN-SCHNORR-v1";

/// Identifies the actual shipped proving backend (honesty export).
pub const ZK_BACKEND: &str = "pedersen-schnorr-ristretto-nizk (transparent, no trusted setup)";

/// Status tag for the B3 milestone (documentation / honesty exports).
pub const B3_DEFERRAL_STATUS: &str = concat!(
    "IMPLEMENTED (12-month milestone B3): real transparent zero-knowledge retrieval-match proof. ",
    "Backend is Pedersen commitments + Schnorr equality NIZK over Ristretto (no trusted setup) — NOT Plonky2/FRI, ",
    "because Plonky2 1.x is nightly-only (feature(specialization)) and the repo pins stable 1.86.0. ",
    "Proves zero-knowledge of a committed entry matching a hidden query; reveals only the public commitment. ",
    "Faithful-execution privacy — NOT semantic truth, NOT exact-NN / not exact nearest-neighbor. ",
    "It does not prove ranking; Phase I ExactDominance proves membership/completeness plus top-k ",
    "over prover-asserted distances; true top-k ranking is not proven and it is not top-k by true ",
    "query-to-embedding distance until verifiers recompute candidate distances. ",
    "v0/90-day still uses commitment_binding (BLAKE3 envelope, not ZK)."
);

/// Honesty boundary for the `pedersen_schnorr_zk` feature (named for the actual backend).
///
/// The `B3_DEFERRAL_STATUS` string (above) records the deferral from the blueprint's
/// Plonky2/V3DB SNARK target; the regression tests below assert this constant mentions
/// the Plonky2/FRI name only as a *non*-claim — protecting against future contributors
/// re-labelling the implementation in a way that misrepresents the backend.
pub const PEDERSEN_SCHNORR_HONESTY: &str = concat!(
    "ZK retrieval proof is a real zero-knowledge proof (Pedersen + Schnorr over Ristretto, transparent, ",
    "no trusted setup; NOT Plonky2, NOT FRI). It proves faithful execution of a retrieval-match predicate with ",
    "witness privacy; it is not semantic truth, not exact-NN / not exact nearest-neighbor, ",
    "and not a claim that an authenticated entry is factually correct. It proves no ranking; ",
    "Phase I ExactDominance proves membership/completeness plus top-k over prover-asserted ",
    "distances; true top-k ranking is not proven and it is not top-k by true query-to-embedding ",
    "distance until verifiers recompute candidate distances."
);

/// Connection 1 (Verifiable Cognition Program): honesty ceiling for multiset set-equality.
///
/// Soundness is **computational** under DLP in the Ristretto group and the random-oracle
/// model (Fiat–Shamir). Multiset collision resistance follows from ECMH (Bellare–Micciancio).
/// This is **not** information-theoretic. Authenticated ≠ true. Membership is **not** proved —
/// only multiset equality; see accumulators (Jewel C) for non-membership.
pub const SET_EQUALITY_HONESTY: &str = concat!(
    "Set-equality proof (Connection 1): the shipped Schnorr verifier checks C_A − C_B ∈ span(H); ",
    "with hiding multiset commitments C(S,r) = Σ h_set(x) + r·H this proves multiset equality ",
    "under DLP+ROM (~126-bit computational). NOT information-theoretic. NOT semantic truth. ",
    "NOT membership — additive multiset hashes prove equality/union only, not element membership. ",
    "Domain separation is load-bearing (FS_SET_EQUALITY_DOMAIN ≠ FS_DOMAIN)."
);

/// Connection 1 unification lemma (documentation export).
pub const CONN1_UNIFICATION: &str = concat!(
    "Every set-shaped MNEME invariant is a Ristretto point; every pairwise equality is one ",
    "Schnorr span(H) statement. Scalar retrieval-match and multiset set-equality share one ",
    "96-byte proof and one fail-closed verifier core; security reduces to DLP+ROM + ECMH."
);

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

/// Opaque ZK proof that two committed multisets are equal (Connection 1).
///
/// Wire format matches [`PedersenSchnorrRetrievalProof`]: `public_commit` = C(S_A, r_A),
/// `proof_bytes` = `C(S_B, r_B) (32) || R (32) || z (32)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PedersenSchnorrSetEqualityProof {
    pub public_commit: [u8; PUBLIC_COMMIT_LEN],
    pub proof_bytes: Vec<u8>,
}

/// Private witness for multiset set-equality.
///
/// A valid proof exists iff `set_a` and `set_b` are equal as multisets (order irrelevant,
/// multiplicity matters). Elements are arbitrary byte strings (e.g. object IDs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetEqualityWitness {
    pub set_a: Vec<Vec<u8>>,
    pub set_b: Vec<Vec<u8>>,
}

impl SetEqualityWitness {
    /// Build a witness where both sides carry the same multiset (the satisfiable case).
    pub fn matching(elements: Vec<Vec<u8>>) -> Self {
        Self {
            set_a: elements.clone(),
            set_b: elements,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PedersenSchnorrFailure {
    UnsatisfiableWitness,
    PublishedCommitLengthInvalid,
    PublishedCommitDoesNotMatchProof,
    ProofByteLengthInvalid,
    EntryCommitEncodingRejected,
    QueryCommitEncodingRejected,
    NonceEncodingRejected,
    ResponseScalarNonCanonical,
    EntryCommitDecompressionRejected,
    QueryCommitDecompressionRejected,
    NonceDecompressionRejected,
    SchnorrEquationFailed,
}

fn pedersen_schnorr_failure_to_mneme(failure: PedersenSchnorrFailure) -> MnemeError {
    match failure {
        PedersenSchnorrFailure::UnsatisfiableWitness
        | PedersenSchnorrFailure::PublishedCommitLengthInvalid
        | PedersenSchnorrFailure::PublishedCommitDoesNotMatchProof
        | PedersenSchnorrFailure::ProofByteLengthInvalid
        | PedersenSchnorrFailure::EntryCommitEncodingRejected
        | PedersenSchnorrFailure::QueryCommitEncodingRejected
        | PedersenSchnorrFailure::NonceEncodingRejected
        | PedersenSchnorrFailure::ResponseScalarNonCanonical
        | PedersenSchnorrFailure::EntryCommitDecompressionRejected
        | PedersenSchnorrFailure::QueryCommitDecompressionRejected
        | PedersenSchnorrFailure::NonceDecompressionRejected
        | PedersenSchnorrFailure::SchnorrEquationFailed => MnemeError::ZkProofInvalid,
    }
}

fn pedersen_schnorr_error(failure: PedersenSchnorrFailure) -> MnemeError {
    pedersen_schnorr_failure_to_mneme(failure)
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

/// ECMH element map `h_set : {0,1}* → Ristretto` (Connection 1).
///
/// Uses the same `from_uniform_bytes` hash-to-group primitive as [`generator_h`], under a
/// fresh domain tag so multiset commitments are independent of the Pedersen generator derivation.
pub fn h_set(element: &[u8]) -> RistrettoPoint {
    let mut reader = blake3::Hasher::new()
        .update(H_SET_DOMAIN)
        .update(element)
        .finalize_xof();
    let mut wide = [0u8; 64];
    reader.fill(&mut wide);
    RistrettoPoint::from_uniform_bytes(&wide)
}

/// Hiding multiset commitment `C(S, r) = Σ_{x∈S} h_set(x) + r·H`.
pub fn commit_multiset(elements: &[impl AsRef<[u8]>], blinding: Scalar) -> RistrettoPoint {
    let mut point = blinding * (*generator_h());
    for elem in elements {
        point += h_set(elem.as_ref());
    }
    point
}

fn multisets_equal(a: &[Vec<u8>], b: &[Vec<u8>]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut sa = a.to_vec();
    let mut sb = b.to_vec();
    sa.sort();
    sb.sort();
    sa == sb
}

/// Fiat–Shamir challenge over the public transcript `(domain, C_a, C_b, R)`.
fn fiat_shamir_challenge(
    fs_domain: &[u8],
    public_commit: &CompressedRistretto,
    query_commit: &CompressedRistretto,
    nonce_point: &CompressedRistretto,
) -> Scalar {
    let mut reader = blake3::Hasher::new()
        .update(fs_domain)
        .update(public_commit.as_bytes())
        .update(query_commit.as_bytes())
        .update(nonce_point.as_bytes())
        .finalize_xof();
    let mut wide = [0u8; 64];
    reader.fill(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Schnorr proof of knowledge of `s` with `C_a − C_b = s·H` (shared verifier core).
fn prove_span_h_difference(
    c_a: &CompressedRistretto,
    c_b: &CompressedRistretto,
    s: Scalar,
    fs_domain: &[u8],
) -> Vec<u8> {
    let mut rng = OsRng;
    let k = Scalar::random(&mut rng);
    let nonce_point = (k * (*generator_h())).compress();
    let challenge = fiat_shamir_challenge(fs_domain, c_a, c_b, &nonce_point);
    let z = k + challenge * s;

    let mut proof_bytes = Vec::with_capacity(PROOF_LEN);
    proof_bytes.extend_from_slice(c_b.as_bytes());
    proof_bytes.extend_from_slice(nonce_point.as_bytes());
    proof_bytes.extend_from_slice(z.as_bytes());
    proof_bytes
}

/// Verify `z·H == R + c·(C_a − C_b)` for a span(H) Schnorr proof (shared verifier core).
fn verify_span_h_difference(
    public_commit: &[u8; PUBLIC_COMMIT_LEN],
    proof_bytes: &[u8],
    fs_domain: &[u8],
) -> Result<(), MnemeError> {
    if proof_bytes.len() != PROOF_LEN {
        return Err(pedersen_schnorr_error(
            PedersenSchnorrFailure::ProofByteLengthInvalid,
        ));
    }

    let c_a = CompressedRistretto::from_slice(public_commit)
        .map_err(|_| pedersen_schnorr_error(PedersenSchnorrFailure::EntryCommitEncodingRejected))?;
    let c_b = CompressedRistretto::from_slice(&proof_bytes[0..32])
        .map_err(|_| pedersen_schnorr_error(PedersenSchnorrFailure::QueryCommitEncodingRejected))?;
    let nonce_point = CompressedRistretto::from_slice(&proof_bytes[32..64])
        .map_err(|_| pedersen_schnorr_error(PedersenSchnorrFailure::NonceEncodingRejected))?;

    let mut z_bytes = [0u8; 32];
    z_bytes.copy_from_slice(&proof_bytes[64..96]);
    let z = Option::<Scalar>::from(Scalar::from_canonical_bytes(z_bytes)).ok_or_else(|| {
        pedersen_schnorr_error(PedersenSchnorrFailure::ResponseScalarNonCanonical)
    })?;

    let c_a_point = c_a.decompress().ok_or_else(|| {
        pedersen_schnorr_error(PedersenSchnorrFailure::EntryCommitDecompressionRejected)
    })?;
    let c_b_point = c_b.decompress().ok_or_else(|| {
        pedersen_schnorr_error(PedersenSchnorrFailure::QueryCommitDecompressionRejected)
    })?;
    let nonce = nonce_point.decompress().ok_or_else(|| {
        pedersen_schnorr_error(PedersenSchnorrFailure::NonceDecompressionRejected)
    })?;

    let d = c_a_point - c_b_point;
    let challenge = fiat_shamir_challenge(fs_domain, &c_a, &c_b, &nonce_point);

    let lhs = z * (*generator_h());
    let rhs = nonce + challenge * d;

    if lhs == rhs {
        Ok(())
    } else {
        Err(pedersen_schnorr_error(
            PedersenSchnorrFailure::SchnorrEquationFailed,
        ))
    }
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
        return Err(pedersen_schnorr_error(
            PedersenSchnorrFailure::UnsatisfiableWitness,
        ));
    }

    let mut rng = OsRng;
    let r_e = Scalar::random(&mut rng);
    let r_q = Scalar::random(&mut rng);

    let c_e = commit(entry, r_e).compress();
    let c_q = commit(query, r_q).compress();

    // D = C_e - C_q = (r_e - r_q)·H, since the value parts cancel. Prove knowledge of s.
    let s = r_e - r_q;

    let proof_bytes = prove_span_h_difference(&c_e, &c_q, s, FS_DOMAIN);

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
        return Err(pedersen_schnorr_error(
            PedersenSchnorrFailure::PublishedCommitLengthInvalid,
        ));
    }
    // The caller's published commitment must match the entry the proof binds to.
    if public_commit != proof.public_commit {
        return Err(pedersen_schnorr_error(
            PedersenSchnorrFailure::PublishedCommitDoesNotMatchProof,
        ));
    }
    if proof.proof_bytes.len() != PROOF_LEN {
        return Err(pedersen_schnorr_error(
            PedersenSchnorrFailure::ProofByteLengthInvalid,
        ));
    }

    verify_span_h_difference(&proof.public_commit, &proof.proof_bytes, FS_DOMAIN)
}

/// Generate a zero-knowledge multiset set-equality proof (Connection 1).
///
/// Fails closed with [`MnemeError::ZkProofInvalid`] when the witness is unsatisfiable
/// (`set_a` and `set_b` differ as multisets); a false statement cannot be proven.
pub fn prove_set_equality(
    witness: &SetEqualityWitness,
) -> Result<PedersenSchnorrSetEqualityProof, MnemeError> {
    if !multisets_equal(&witness.set_a, &witness.set_b) {
        return Err(pedersen_schnorr_error(
            PedersenSchnorrFailure::UnsatisfiableWitness,
        ));
    }

    let mut rng = OsRng;
    let r_a = Scalar::random(&mut rng);
    let r_b = Scalar::random(&mut rng);

    let c_a = commit_multiset(&witness.set_a, r_a).compress();
    let c_b = commit_multiset(&witness.set_b, r_b).compress();

    // C(S,r) = Σ h_set(x) + r·H; equal multisets cancel the Σ term, leaving (r_a − r_b)·H.
    let s = r_a - r_b;
    let proof_bytes = prove_span_h_difference(&c_a, &c_b, s, FS_SET_EQUALITY_DOMAIN);

    Ok(PedersenSchnorrSetEqualityProof {
        public_commit: *c_a.as_bytes(),
        proof_bytes,
    })
}

/// Verify a multiset set-equality proof against a published `public_commit` (32 bytes).
///
/// Uses the same Schnorr span(H) check as [`verify_pedersen_schnorr`], with a separate
/// Fiat–Shamir domain so retrieval-match proofs cannot be replayed as set-equality proofs.
pub fn verify_set_equality(
    proof: &PedersenSchnorrSetEqualityProof,
    public_commit: &[u8],
) -> Result<(), MnemeError> {
    if public_commit.len() != PUBLIC_COMMIT_LEN {
        return Err(pedersen_schnorr_error(
            PedersenSchnorrFailure::PublishedCommitLengthInvalid,
        ));
    }
    if public_commit != proof.public_commit {
        return Err(pedersen_schnorr_error(
            PedersenSchnorrFailure::PublishedCommitDoesNotMatchProof,
        ));
    }
    if proof.proof_bytes.len() != PROOF_LEN {
        return Err(pedersen_schnorr_error(
            PedersenSchnorrFailure::ProofByteLengthInvalid,
        ));
    }

    verify_span_h_difference(
        &proof.public_commit,
        &proof.proof_bytes,
        FS_SET_EQUALITY_DOMAIN,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honesty_strings_preserve_boundary() {
        assert!(B3_DEFERRAL_STATUS.contains("12-month"));
        assert!(B3_DEFERRAL_STATUS.contains("NOT semantic truth"));
        assert!(B3_DEFERRAL_STATUS.contains("NOT exact-NN"));
        assert_distance_caveat("B3_DEFERRAL_STATUS", B3_DEFERRAL_STATUS);
        assert!(B3_DEFERRAL_STATUS.contains("NOT Plonky2/FRI"));
        assert!(PEDERSEN_SCHNORR_HONESTY.contains("zero-knowledge"));
        assert!(PEDERSEN_SCHNORR_HONESTY.contains("NOT Plonky2"));
        assert!(PEDERSEN_SCHNORR_HONESTY.contains("not semantic truth"));
        assert!(PEDERSEN_SCHNORR_HONESTY.contains("not exact-NN"));
        assert_distance_caveat("PEDERSEN_SCHNORR_HONESTY", PEDERSEN_SCHNORR_HONESTY);
        assert!(ZK_BACKEND.contains("pedersen-schnorr"));
        assert!(ZK_BACKEND.contains("no trusted setup"));
    }

    fn assert_distance_caveat(surface: &str, text: &str) {
        for phrase in [
            "not exact",
            "membership/completeness",
            "top-k over prover-asserted distances",
            "top-k ranking is not proven",
            "not top-k by true query-to-embedding distance",
        ] {
            assert!(
                text.contains(phrase),
                "{surface} missing required honesty phrase `{phrase}`: {text}"
            );
        }
    }

    #[test]
    fn proof_failures_are_classified_not_zkproof_collapsed() {
        let source = include_str!("pedersen_schnorr_zk.rs")
            .split_once("#[cfg(test)]")
            .map(|(production, _tests)| production)
            .expect("pedersen_schnorr_zk tests should follow production code");

        for forbidden in [
            "return Err(MnemeError::ZkProofInvalid",
            ".map_err(|_| MnemeError::ZkProofInvalid",
            ".ok_or(MnemeError::ZkProofInvalid",
            "Err(MnemeError::ZkProofInvalid)",
        ] {
            assert!(
                !source.contains(forbidden),
                "Pedersen-Schnorr proof path should route `{forbidden}` through named classifiers"
            );
        }

        for required in [
            "enum PedersenSchnorrFailure",
            "UnsatisfiableWitness",
            "PublishedCommitLengthInvalid",
            "PublishedCommitDoesNotMatchProof",
            "ProofByteLengthInvalid",
            "EntryCommitEncodingRejected",
            "QueryCommitEncodingRejected",
            "NonceEncodingRejected",
            "ResponseScalarNonCanonical",
            "EntryCommitDecompressionRejected",
            "QueryCommitDecompressionRejected",
            "NonceDecompressionRejected",
            "SchnorrEquationFailed",
            "fn pedersen_schnorr_failure_to_mneme(",
            "fn pedersen_schnorr_error(",
        ] {
            assert!(
                source.contains(required),
                "Pedersen-Schnorr proof path should include `{required}`"
            );
        }
    }

    #[test]
    fn proof_failure_classifier_preserves_public_zkproof_invalid() {
        for failure in [
            PedersenSchnorrFailure::UnsatisfiableWitness,
            PedersenSchnorrFailure::PublishedCommitLengthInvalid,
            PedersenSchnorrFailure::PublishedCommitDoesNotMatchProof,
            PedersenSchnorrFailure::ProofByteLengthInvalid,
            PedersenSchnorrFailure::EntryCommitEncodingRejected,
            PedersenSchnorrFailure::QueryCommitEncodingRejected,
            PedersenSchnorrFailure::NonceEncodingRejected,
            PedersenSchnorrFailure::ResponseScalarNonCanonical,
            PedersenSchnorrFailure::EntryCommitDecompressionRejected,
            PedersenSchnorrFailure::QueryCommitDecompressionRejected,
            PedersenSchnorrFailure::NonceDecompressionRejected,
            PedersenSchnorrFailure::SchnorrEquationFailed,
        ] {
            assert_eq!(
                pedersen_schnorr_failure_to_mneme(failure),
                MnemeError::ZkProofInvalid
            );
            assert_eq!(pedersen_schnorr_error(failure), MnemeError::ZkProofInvalid);
        }
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

    #[test]
    fn conn1_honesty_strings_preserve_dlp_rom_ceiling() {
        assert!(SET_EQUALITY_HONESTY.contains("DLP+ROM"));
        assert!(SET_EQUALITY_HONESTY.contains("NOT membership"));
        assert!(SET_EQUALITY_HONESTY.contains("NOT information-theoretic"));
        assert!(SET_EQUALITY_HONESTY.contains("NOT semantic truth"));
        assert!(SET_EQUALITY_HONESTY.contains("FS_SET_EQUALITY_DOMAIN"));
        assert!(CONN1_UNIFICATION.contains("Schnorr span(H)"));
        assert!(CONN1_UNIFICATION.contains("DLP+ROM"));
    }

    #[test]
    fn set_equality_proof_round_trips() {
        let elements = vec![b"obj-a".to_vec(), b"obj-b".to_vec(), b"obj-c".to_vec()];
        let proof = prove_set_equality(&SetEqualityWitness::matching(elements)).expect("prove");
        assert_eq!(proof.proof_bytes.len(), PROOF_LEN);
        verify_set_equality(&proof, &proof.public_commit).expect("verify");
    }

    #[test]
    fn set_equality_is_order_independent() {
        let a = vec![b"x".to_vec(), b"y".to_vec(), b"z".to_vec()];
        let mut b = vec![b"z".to_vec(), b"x".to_vec(), b"y".to_vec()];
        let proof_a = prove_set_equality(&SetEqualityWitness::matching(a)).expect("a");
        let proof_b = prove_set_equality(&SetEqualityWitness::matching(b.clone())).expect("b");
        verify_set_equality(&proof_a, &proof_a.public_commit).expect("verify a");
        verify_set_equality(&proof_b, &proof_b.public_commit).expect("verify b");

        // Same multiset under different orderings yields equal Σ h_set(x) (ECMH homomorphism).
        let r = Scalar::ZERO;
        let ca = commit_multiset(&[b"x", b"y", b"z"], r);
        b.sort();
        let cb = commit_multiset(&b.iter().map(|v| v.as_slice()).collect::<Vec<_>>(), r);
        assert_eq!(ca, cb, "multiset commitment must be order-independent");
    }

    #[test]
    fn set_equality_respects_multiplicity() {
        let equal = vec![b"dup".to_vec(), b"dup".to_vec()];
        prove_set_equality(&SetEqualityWitness::matching(equal)).expect("equal multisets prove");

        let a = vec![b"dup".to_vec(), b"dup".to_vec()];
        let b = vec![b"dup".to_vec()];
        assert_eq!(
            prove_set_equality(&SetEqualityWitness { set_a: a, set_b: b }),
            Err(MnemeError::ZkProofInvalid)
        );
    }

    #[test]
    fn set_equality_unsatisfiable_multisets_cannot_prove() {
        let a = vec![b"alpha".to_vec()];
        let b = vec![b"beta".to_vec()];
        assert_eq!(
            prove_set_equality(&SetEqualityWitness { set_a: a, set_b: b }),
            Err(MnemeError::ZkProofInvalid)
        );
    }

    #[test]
    fn set_equality_proof_is_randomized() {
        let elements = vec![b"k1".to_vec(), b"k2".to_vec()];
        let p1 = prove_set_equality(&SetEqualityWitness::matching(elements.clone())).expect("p1");
        let p2 = prove_set_equality(&SetEqualityWitness::matching(elements)).expect("p2");
        assert_ne!(
            p1.public_commit, p2.public_commit,
            "blinding hides the multiset"
        );
        assert_ne!(p1.proof_bytes, p2.proof_bytes);
        verify_set_equality(&p1, &p1.public_commit).expect("verify p1");
        verify_set_equality(&p2, &p2.public_commit).expect("verify p2");
    }

    #[test]
    fn set_equality_domain_separation_blocks_cross_protocol_replay() {
        let elements = vec![b"obj".to_vec()];
        let set_proof =
            prove_set_equality(&SetEqualityWitness::matching(elements)).expect("set prove");

        // A set-equality proof must not verify under the retrieval-match FS domain.
        assert_eq!(
            verify_span_h_difference(&set_proof.public_commit, &set_proof.proof_bytes, FS_DOMAIN,),
            Err(MnemeError::ZkProofInvalid)
        );

        // Retrieval-match proof must not verify under set-equality FS domain.
        let entry = [5u8; 32];
        let retrieval =
            prove_pedersen_schnorr(&RetrievalWitness::matching(entry)).expect("retrieval prove");
        assert_eq!(
            verify_span_h_difference(
                &retrieval.public_commit,
                &retrieval.proof_bytes,
                FS_SET_EQUALITY_DOMAIN,
            ),
            Err(MnemeError::ZkProofInvalid)
        );
    }

    #[test]
    fn set_equality_forgery_rejects() {
        let elements = vec![b"t1".to_vec(), b"t2".to_vec()];
        let mut proof = prove_set_equality(&SetEqualityWitness::matching(elements)).expect("prove");
        proof.proof_bytes[64] = proof.proof_bytes[64].wrapping_add(1);
        assert_eq!(
            verify_set_equality(&proof, &proof.public_commit),
            Err(MnemeError::ZkProofInvalid)
        );

        let fresh = prove_set_equality(&SetEqualityWitness::matching(vec![
            b"t1".to_vec(),
            b"t2".to_vec(),
        ]))
        .expect("fresh");
        let mut wrong = fresh.public_commit;
        wrong[0] ^= 0x01;
        assert_eq!(
            verify_set_equality(&fresh, &wrong),
            Err(MnemeError::ZkProofInvalid)
        );
    }

    #[test]
    fn h_set_domain_differs_from_generator_h() {
        let elem_point = h_set(b"test-element");
        assert_ne!(
            elem_point,
            *generator_h(),
            "h_set must not collide with H generator derivation"
        );
    }
}
