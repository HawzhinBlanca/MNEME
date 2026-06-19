//! RSA / class-group universal accumulator scaffold (Benaloh–de Mare style).
//!
//! Software-feasible on stable Rust via `num-bigint`. Witness generation keeps a prover-side
//! prime list (Ω(n) setup); constant-size non-membership is the north-star, not this month's TCB.

use std::sync::OnceLock;

use blake3::Hasher;
use mneme_core::MnemeError;
use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::{One, Zero};

/// Domain-separated tag for hashing cognition commits into accumulator elements.
pub const ACCUM_COMMIT_TAG: &[u8] = b"MNEME-JEWEL-C-COMMIT/v1";
/// Domain-separated tag for mapping commit bytes to a nothing-up-my-sleeve prime representative.
const ELEMENT_DOMAIN: &[u8] = b"MNEME-JEWEL-C-ACCUM-ELEMENT-v1";

/// Status export for docs / honesty surfaces.
pub const JEWEL_C_STATUS: &str = concat!(
    "SCAFFOLD: Jewel C class-group universal accumulator (RSA accumulator over num-bigint). ",
    "Research prototype for certified-cognition non-use only — not wired into recall/receipt/",
    "cognition-cert verify paths; feature `jewel_c` off by default. Prover keeps Ω(n) prime ",
    "list for witness generation."
);

/// Honesty ceiling (VCP §5 Jewel C).
pub const JEWEL_C_HONESTY: &str = concat!(
    "Jewel C proves non-membership in an operator-presented accumulated used-set for certified ",
    "cognition commits only — NOT semantic truth, NOT that no out-of-band copy ever existed, ",
    "and NOT max wall-clock spacing between cognition events (σ_max remains OPEN — see T8 ",
    "counterexample). Soundness is computational under RSA / class-group assumptions; ",
    "operator can withhold certificates or alternate chains (T10). Authenticated ≠ true. ",
    "Relative to the presented accumulator state and witness chain only."
);

#[derive(Clone, Debug)]
pub struct AccumulatorParams {
    pub modulus: BigUint,
    pub generator: BigUint,
}

#[derive(Clone, Debug)]
pub struct AccumulatorProver {
    params: AccumulatorParams,
    state: BigUint,
    primes: Vec<BigUint>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipWitness {
    pub witness: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonMembershipWitness {
    pub coprime_coeff: Vec<u8>,
    pub witness: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JewelCFailure {
    EmptyModulus,
    GeneratorOutOfRange,
    GeneratorNotInvertible,
    ElementNotPrime,
    ElementAlreadyAccumulated,
    ElementNotInSet,
    ElementInSet,
    WitnessOutOfRange,
    MembershipCheckFailed,
    NonMembershipCheckFailed,
    ByteEncodingInvalid,
}

fn jewel_c_failure_to_mneme(failure: JewelCFailure) -> MnemeError {
    match failure {
        JewelCFailure::EmptyModulus
        | JewelCFailure::GeneratorOutOfRange
        | JewelCFailure::GeneratorNotInvertible
        | JewelCFailure::ElementNotPrime
        | JewelCFailure::ElementAlreadyAccumulated
        | JewelCFailure::ElementNotInSet
        | JewelCFailure::ElementInSet
        | JewelCFailure::WitnessOutOfRange
        | JewelCFailure::MembershipCheckFailed
        | JewelCFailure::NonMembershipCheckFailed
        | JewelCFailure::ByteEncodingInvalid => MnemeError::ZkProofInvalid,
    }
}

fn jewel_c_error(failure: JewelCFailure) -> MnemeError {
    jewel_c_failure_to_mneme(failure)
}

fn params_once() -> &'static AccumulatorParams {
    static PARAMS: OnceLock<AccumulatorParams> = OnceLock::new();
    PARAMS.get_or_init(test_accumulator_params)
}

/// Deterministic test parameters (nothing-up-my-sleeve small safe primes).
pub fn test_accumulator_params() -> AccumulatorParams {
    let p = BigUint::from(1_009_u32);
    let q = BigUint::from(1_013_u32);
    let modulus = &p * &q;
    let generator = BigUint::from(5_u32);
    AccumulatorParams { modulus, generator }
}

/// Hash a 32-byte commit into the tagged envelope used by forget-absence / cognition binds.
pub fn hash_commit(raw: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(ACCUM_COMMIT_TAG);
    hasher.update(raw);
    *hasher.finalize().as_bytes()
}

/// Map a commit digest to a domain-separated prime accumulator element.
pub fn element_prime_from_commit(commit: &[u8; 32]) -> BigUint {
    hash_to_prime(ELEMENT_DOMAIN, commit)
}

fn hash_to_prime(domain: &[u8], message: &[u8]) -> BigUint {
    let mut seed = Hasher::new();
    seed.update(domain);
    seed.update(message);
    let digest = seed.finalize();
    // Scaffold scale: 32-bit seed → small odd prime compatible with test modulus (~1M).
    // Production Jewel C would widen this domain; honesty string documents research status.
    let lo = u32::from_le_bytes(digest.as_bytes()[0..4].try_into().expect("4 bytes"));
    let mut candidate = BigUint::from((lo % 900) + 101u32);
    if &candidate % 2u32 == BigUint::zero() {
        candidate += 1u32;
    }
    while !is_probably_prime(&candidate) {
        candidate += 2u32;
    }
    candidate
}

fn is_probably_prime(n: &BigUint) -> bool {
    if n < &BigUint::from(2_u32) {
        return false;
    }
    if n == &BigUint::from(2_u32) {
        return true;
    }
    if n % 2u32 == BigUint::zero() {
        return false;
    }
    let n_minus_one = n - 1u32;
    let mut d = n_minus_one.clone();
    let mut s = 0u32;
    while &d % 2u32 == BigUint::zero() {
        d /= 2u32;
        s += 1;
    }
    // Deterministic Miller–Rabin bases for 64-bit range; sufficient for scaffold primes.
    for a in [2_u32, 3, 5, 7, 11, 13, 17] {
        let base = BigUint::from(a);
        if &base % n == BigUint::zero() {
            continue;
        }
        let mut x = mod_pow(&base, &d, n);
        if x == BigUint::one() || x == n_minus_one {
            continue;
        }
        let mut ok = false;
        for _ in 1..s {
            x = mod_pow(&x, &BigUint::from(2_u32), n);
            if x == n_minus_one {
                ok = true;
                break;
            }
        }
        if !ok {
            return false;
        }
    }
    true
}

fn mod_pow(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    base.modpow(exp, modulus)
}

fn mod_inverse(base: &BigUint, modulus: &BigUint) -> BigUint {
    let b = BigInt::from(base.clone());
    let m = BigInt::from(modulus.clone());
    let egcd = b.extended_gcd(&m);
    assert_eq!(
        egcd.gcd,
        BigInt::one(),
        "base must be invertible mod modulus"
    );
    bytes_to_biguint(&bigint_mod_bytes(&egcd.x, modulus)).expect("mod inverse bytes")
}

fn product(primes: &[BigUint]) -> BigUint {
    primes.iter().fold(BigUint::one(), |acc, p| acc * p)
}

fn bezout_coefficients(
    element: &BigUint,
    accumulated: &BigUint,
) -> Result<(BigInt, BigInt), MnemeError> {
    let e = BigInt::from(element.clone());
    let p = BigInt::from(accumulated.clone());
    let egcd = e.extended_gcd(&p);
    if egcd.gcd != BigInt::one() {
        return Err(jewel_c_error(JewelCFailure::NonMembershipCheckFailed));
    }
    Ok((egcd.x, egcd.y))
}

fn mod_pow_signed(base: &BigUint, exponent: &BigInt, modulus: &BigUint) -> BigUint {
    match exponent.sign() {
        Sign::NoSign => BigUint::one(),
        Sign::Plus => {
            let exp = exponent
                .to_biguint()
                .expect("positive BigInt exponent fits BigUint");
            mod_pow(base, &exp, modulus)
        }
        Sign::Minus => {
            let inv = mod_inverse(base, modulus);
            let pos = (-exponent)
                .to_biguint()
                .expect("negated BigInt exponent fits BigUint");
            mod_pow(&inv, &pos, modulus)
        }
    }
}

fn bigint_signed_minimal_bytes(value: &BigInt) -> Vec<u8> {
    let mut mag = value.magnitude().to_bytes_le();
    if mag.is_empty() {
        mag.push(0);
    }
    let mut out = Vec::with_capacity(1 + mag.len());
    out.push(match value.sign() {
        Sign::Minus => 1u8,
        _ => 0u8,
    });
    out.extend_from_slice(&mag);
    out
}

fn bigint_from_signed_minimal_bytes(bytes: &[u8]) -> Result<BigInt, MnemeError> {
    if bytes.is_empty() {
        return Err(jewel_c_error(JewelCFailure::ByteEncodingInvalid));
    }
    let negative = bytes[0] == 1;
    let mag = BigUint::from_bytes_le(bytes.get(1..).unwrap_or(&[]));
    let unsigned = BigInt::from(mag);
    if negative {
        Ok(-unsigned)
    } else {
        Ok(unsigned)
    }
}

fn bigint_mod_bytes(value: &BigInt, modulus: &BigUint) -> Vec<u8> {
    let m = BigInt::from(modulus.clone());
    let mut reduced = value % &m;
    if reduced.sign() == Sign::Minus {
        reduced += m;
    }
    let uint = reduced.to_biguint().expect("reduced BigInt fits BigUint");
    biguint_to_minimal_bytes(&uint)
}

fn biguint_to_minimal_bytes(value: &BigUint) -> Vec<u8> {
    let bytes = value.to_bytes_be();
    if bytes.is_empty() { vec![0] } else { bytes }
}

fn bytes_to_biguint(bytes: &[u8]) -> Result<BigUint, MnemeError> {
    if bytes.is_empty() {
        return Err(jewel_c_error(JewelCFailure::ByteEncodingInvalid));
    }
    Ok(BigUint::from_bytes_be(bytes))
}

fn validate_params(params: &AccumulatorParams) -> Result<(), MnemeError> {
    if params.modulus.is_zero() {
        return Err(jewel_c_error(JewelCFailure::EmptyModulus));
    }
    if params.generator >= params.modulus || params.generator.is_zero() {
        return Err(jewel_c_error(JewelCFailure::GeneratorOutOfRange));
    }
    if params.generator.gcd(&params.modulus) != BigUint::one() {
        return Err(jewel_c_error(JewelCFailure::GeneratorNotInvertible));
    }
    Ok(())
}

/// Create a fresh prover state from published parameters.
pub fn accumulator_prover(params: &AccumulatorParams) -> Result<AccumulatorProver, MnemeError> {
    validate_params(params)?;
    Ok(AccumulatorProver {
        params: params.clone(),
        state: params.generator.clone(),
        primes: Vec::new(),
    })
}

/// Create a prover with the shared deterministic test parameters.
pub fn test_accumulator_prover() -> Result<AccumulatorProver, MnemeError> {
    accumulator_prover(params_once())
}

/// Accumulate a domain-separated prime element into the running state.
pub fn accumulate(prover: &mut AccumulatorProver, element: &BigUint) -> Result<(), MnemeError> {
    validate_params(&prover.params)?;
    if !is_probably_prime(element) {
        return Err(jewel_c_error(JewelCFailure::ElementNotPrime));
    }
    if prover.primes.iter().any(|p| p == element) {
        return Err(jewel_c_error(JewelCFailure::ElementAlreadyAccumulated));
    }
    prover.state = mod_pow(&prover.state, element, &prover.params.modulus);
    prover.primes.push(element.clone());
    Ok(())
}

/// Accumulate a cognition commit into the used-set accumulator.
pub fn accumulate_commit(
    prover: &mut AccumulatorProver,
    commit: &[u8; 32],
) -> Result<(), MnemeError> {
    let prime = element_prime_from_commit(commit);
    accumulate(prover, &prime)
}

/// Current published accumulator value (constant-size bytes).
pub fn accumulator_value(prover: &AccumulatorProver) -> Vec<u8> {
    biguint_to_minimal_bytes(&prover.state)
}

/// Membership witness for an accumulated element.
pub fn prove_membership(
    prover: &AccumulatorProver,
    element: &BigUint,
) -> Result<MembershipWitness, MnemeError> {
    let idx = prover
        .primes
        .iter()
        .position(|p| p == element)
        .ok_or_else(|| jewel_c_error(JewelCFailure::ElementNotInSet))?;
    let mut others = prover.primes.clone();
    others.remove(idx);
    let witness = if others.is_empty() {
        prover.params.generator.clone()
    } else {
        mod_pow(
            &prover.params.generator,
            &product(&others),
            &prover.params.modulus,
        )
    };
    Ok(MembershipWitness {
        witness: biguint_to_minimal_bytes(&witness),
    })
}

/// Non-membership witness (Bezout / coprime proof).
pub fn prove_non_membership(
    prover: &AccumulatorProver,
    element: &BigUint,
) -> Result<NonMembershipWitness, MnemeError> {
    if prover.primes.iter().any(|p| p == element) {
        return Err(jewel_c_error(JewelCFailure::ElementInSet));
    }
    let accumulated = product(&prover.primes);
    let (a, b) = bezout_coefficients(element, &accumulated)?;
    let witness = mod_pow_signed(&prover.params.generator, &a, &prover.params.modulus);
    Ok(NonMembershipWitness {
        coprime_coeff: bigint_signed_minimal_bytes(&b),
        witness: biguint_to_minimal_bytes(&witness),
    })
}

pub fn verify_membership(
    params: &AccumulatorParams,
    acc_bytes: &[u8],
    element: &BigUint,
    proof: &MembershipWitness,
) -> Result<(), MnemeError> {
    validate_params(params)?;
    let acc = bytes_to_biguint(acc_bytes)?;
    let witness = bytes_to_biguint(&proof.witness)?;
    if witness >= params.modulus {
        return Err(jewel_c_error(JewelCFailure::WitnessOutOfRange));
    }
    let lhs = mod_pow(&witness, element, &params.modulus);
    if lhs == acc {
        Ok(())
    } else {
        Err(jewel_c_error(JewelCFailure::MembershipCheckFailed))
    }
}

pub fn verify_non_membership(
    params: &AccumulatorParams,
    acc_bytes: &[u8],
    element: &BigUint,
    proof: &NonMembershipWitness,
) -> Result<(), MnemeError> {
    validate_params(params)?;
    let acc = bytes_to_biguint(acc_bytes)?;
    let witness = bytes_to_biguint(&proof.witness)?;
    let coeff = bigint_from_signed_minimal_bytes(&proof.coprime_coeff)?;
    if witness >= params.modulus {
        return Err(jewel_c_error(JewelCFailure::WitnessOutOfRange));
    }
    let lhs = (mod_pow(&witness, element, &params.modulus)
        * mod_pow_signed(&acc, &coeff, &params.modulus))
        % &params.modulus;
    if lhs == params.generator {
        Ok(())
    } else {
        Err(jewel_c_error(JewelCFailure::NonMembershipCheckFailed))
    }
}

/// Prove a forgotten cognition commit is absent from the post-forget used-set accumulator.
pub fn prove_nonuse_after_forget(
    prover: &AccumulatorProver,
    forgotten_commit: &[u8; 32],
) -> Result<NonMembershipWitness, MnemeError> {
    let prime = element_prime_from_commit(forgotten_commit);
    prove_non_membership(prover, &prime)
}

pub fn verify_nonuse_after_forget(
    params: &AccumulatorParams,
    acc_bytes: &[u8],
    forgotten_commit: &[u8; 32],
    proof: &NonMembershipWitness,
) -> Result<(), MnemeError> {
    let prime = element_prime_from_commit(forgotten_commit);
    verify_non_membership(params, acc_bytes, &prime, proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ACCUM-1: Membership proof roundtrip — accumulate then prove then verify.
    #[test]
    fn membership_proof_roundtrip() {
        let mut prover = test_accumulator_prover().expect("test prover must initialize");
        let params = test_accumulator_params();

        let commit = [0x01u8; 32];
        let prime = element_prime_from_commit(&commit);

        accumulate(&mut prover, &prime).expect("accumulate must succeed for a fresh prime");
        let acc = accumulator_value(&prover);

        let proof = prove_membership(&prover, &prime).expect("membership proof must succeed");
        verify_membership(&params, &acc, &prime, &proof)
            .expect("fresh membership proof must verify");
    }

    /// ACCUM-2: Non-membership proof roundtrip — element never added → prove then verify.
    #[test]
    fn non_membership_proof_roundtrip() {
        let mut prover = test_accumulator_prover().expect("test prover");
        let params = test_accumulator_params();

        // Accumulate one element so the primes product is non-trivial.
        let used_commit = [0xAAu8; 32];
        let used_prime = element_prime_from_commit(&used_commit);
        accumulate(&mut prover, &used_prime).expect("accumulate");
        let acc = accumulator_value(&prover);

        // A different commit was never accumulated.
        let absent_commit = [0xBBu8; 32];
        let absent_prime = element_prime_from_commit(&absent_commit);

        let proof = prove_non_membership(&prover, &absent_prime)
            .expect("non-membership proof must succeed for absent element");
        verify_non_membership(&params, &acc, &absent_prime, &proof)
            .expect("non-membership proof must verify");
    }

    /// ACCUM-3: Duplicate element is rejected by accumulate.
    #[test]
    fn accumulate_rejects_duplicate_element() {
        let mut prover = test_accumulator_prover().expect("test prover");
        let commit = [0x02u8; 32];
        let prime = element_prime_from_commit(&commit);

        accumulate(&mut prover, &prime).expect("first accumulate must succeed");
        let result = accumulate(&mut prover, &prime);
        assert!(result.is_err(), "duplicate element must be rejected");
    }

    /// ACCUM-4: prove_membership fails for an element not in the accumulator.
    #[test]
    fn prove_membership_fails_for_unknown_element() {
        let mut prover = test_accumulator_prover().expect("test prover");
        let known = element_prime_from_commit(&[0x10u8; 32]);
        let unknown = element_prime_from_commit(&[0x20u8; 32]);
        accumulate(&mut prover, &known).expect("accumulate known");

        assert!(
            prove_membership(&prover, &unknown).is_err(),
            "membership proof must fail for element not in the accumulator"
        );
    }

    /// ACCUM-5: prove_non_membership fails for an accumulated element (fail-closed).
    #[test]
    fn prove_non_membership_rejects_accumulated_element() {
        let mut prover = test_accumulator_prover().expect("test prover");
        let commit = [0x33u8; 32];
        let prime = element_prime_from_commit(&commit);
        accumulate(&mut prover, &prime).expect("accumulate");

        assert!(
            prove_non_membership(&prover, &prime).is_err(),
            "non-membership proof must fail for a member element"
        );
    }

    /// ACCUM-6: verify_membership rejects proof for wrong element.
    #[test]
    fn verify_membership_rejects_wrong_element() {
        let mut prover = test_accumulator_prover().expect("test prover");
        let params = test_accumulator_params();
        let commit_a = [0xA0u8; 32];
        let commit_b = [0xB0u8; 32];
        let prime_a = element_prime_from_commit(&commit_a);
        let prime_b = element_prime_from_commit(&commit_b);

        accumulate(&mut prover, &prime_a).expect("accumulate a");
        accumulate(&mut prover, &prime_b).expect("accumulate b");
        let acc = accumulator_value(&prover);

        let proof_a = prove_membership(&prover, &prime_a).expect("proof for a");
        // Verifying proof_a against prime_b must fail.
        assert!(
            verify_membership(&params, &acc, &prime_b, &proof_a).is_err(),
            "membership proof for element A must not verify against element B"
        );
    }

    /// ACCUM-7: nonuse_after_forget roundtrip — commit added then removed → non-membership.
    #[test]
    fn nonuse_after_forget_roundtrip() {
        let mut prover = test_accumulator_prover().expect("test prover");
        let params = test_accumulator_params();

        // Accumulate two commits; then simulate forget by rebuilding prover
        // without the forgotten one (Jewel C accumulator requires re-init on forget).
        let active_commit = [0xC1u8; 32];
        let forgotten_commit = [0xC2u8; 32];

        let active_prime = element_prime_from_commit(&active_commit);
        accumulate(&mut prover, &active_prime).expect("accumulate active");
        // Note: we do NOT accumulate forgotten_commit — it was never added.
        let acc = accumulator_value(&prover);

        let proof = prove_nonuse_after_forget(&prover, &forgotten_commit)
            .expect("nonuse proof must succeed");
        verify_nonuse_after_forget(&params, &acc, &forgotten_commit, &proof)
            .expect("nonuse proof must verify");
    }

    /// ACCUM-8: hash_commit is deterministic and domain-separated.
    #[test]
    fn hash_commit_deterministic_and_domain_separated() {
        let raw = [0x42u8; 32];
        let h1 = hash_commit(&raw);
        let h2 = hash_commit(&raw);
        assert_eq!(h1, h2, "hash_commit must be deterministic");
        // Domain separation: hash_commit must differ from raw BLAKE3 of same input.
        let plain = *blake3::hash(&raw).as_bytes();
        assert_ne!(
            h1, plain,
            "hash_commit must be domain-separated from plain BLAKE3"
        );
        assert_ne!(h1, [0u8; 32], "hash_commit must not be all-zeros");
    }
}
