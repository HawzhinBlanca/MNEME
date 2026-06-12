//! Pure-Rust implementation of Wesolowski's Verifiable Delay Function (VDF)
//! over a 2048-bit RSA group of unknown order.

use blake3::Hasher;
use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::One;

/// Public RSA-2048 modulus from a generated key with no known factorization.
pub const MODULUS_HEX: &str = "B91FF85172A968055C1B4CDCF930C724EDEDE700643E90C02F28DE4AE29AB164BD539B90EBE4BCC2327C40EE0B4575ADB7CE0642057FE9EC940C29FCBBE6DE668AAFEC63C42F65987B25AA0DEB3C6A29FC1E084065B95D597489BA552E1B567A4FF52484EFAF8C40C91D919A3051BBB6375DAC8015C1284254E366DBD411915DDE3F69C79F0EAE2AF921AE74B036D597A20062BC36A4112245DA47142BFEF34C1CF44B0F0251D76500073E0F9B7CE0D0B70B478F5CA1710671CC1EF135A274D57BDAE9D376F88E54FD0784ACEEF3F9BDC2B59701A147709EE2004F9C958B1F0451E1FD5E5901985D5B8EE95101773B53024451E452FA018D535BF82FF8BCB9E9";

use std::sync::OnceLock;

static MODULUS: OnceLock<BigUint> = OnceLock::new();

/// Parsed RSA-2048 modulus accessor.
pub fn get_modulus() -> &'static BigUint {
    MODULUS.get_or_init(|| BigUint::parse_bytes(MODULUS_HEX.as_bytes(), 16).unwrap())
}

/// Helper function to perform Miller-Rabin primality test.
pub fn is_prime(n: &BigUint, k: usize) -> bool {
    if n <= &BigUint::from(1u32) {
        return false;
    }
    if n == &BigUint::from(2u32) || n == &BigUint::from(3u32) {
        return true;
    }
    if n.is_even() {
        return false;
    }

    let n_minus_1 = n - 1u32;
    let mut d = n_minus_1.clone();
    let mut s = 0u32;
    while d.is_even() {
        d /= 2u32;
        s += 1;
    }

    let mut rng = rand::thread_rng();
    for _ in 0..k {
        let a = rng.gen_biguint_range(&BigUint::from(2u32), &n_minus_1);
        let mut x = a.modpow(&d, n);
        if x == BigUint::one() || x == n_minus_1 {
            continue;
        }
        let mut composite = true;
        for _ in 0..(s - 1) {
            x = x.modpow(&BigUint::from(2u32), n);
            if x == n_minus_1 {
                composite = false;
                break;
            }
        }
        if composite {
            return false;
        }
    }
    true
}

/// Hash parameters deterministically to a prime number l for Wesolowski proof.
pub fn hash_to_prime(x: &BigUint, y: &BigUint, difficulty: u64, modulus: &BigUint) -> BigUint {
    let mut hasher = Hasher::new();
    hasher.update(&x.to_bytes_be());
    hasher.update(&y.to_bytes_be());
    hasher.update(&difficulty.to_be_bytes());
    hasher.update(&modulus.to_bytes_be());
    let digest = hasher.finalize();

    // Start with the 256-bit hash converted to BigUint
    let mut candidate = BigUint::from_bytes_be(digest.as_bytes());

    // Ensure it is odd
    if candidate.is_even() {
        candidate += BigUint::one();
    }

    // Search for the next prime
    while !is_prime(&candidate, 15) {
        candidate += 2u32;
    }
    candidate
}

/// Map an input 32-byte hash to a valid base in Z_N^*
pub fn map_to_group(input_hash: &[u8; 32], modulus: &BigUint) -> BigUint {
    let mut base = BigUint::from_bytes_be(input_hash);
    base %= modulus;
    if base <= BigUint::one() {
        base = BigUint::from(2u32);
    }
    while base.gcd(modulus) != BigUint::one() {
        base += BigUint::one();
    }
    base
}

/// Wesolowski VDF Prover
pub struct VdfProver;

impl VdfProver {
    /// Solves the VDF: computes y = x^(2^T) mod N and a Wesolowski succinct proof.
    /// Returns (y, proof).
    pub fn solve(x_hash: &[u8; 32], difficulty: u64) -> (Vec<u8>, Vec<u8>) {
        let modulus = get_modulus();
        let x = map_to_group(x_hash, modulus);

        // 1. Sequential squaring: compute y = x^(2^T) mod N
        let mut y = x.clone();
        for _ in 0..difficulty {
            y = y.modpow(&BigUint::from(2u32), modulus);
        }

        // 2. Hash to prime l
        let l = hash_to_prime(&x, &y, difficulty, modulus);

        // 3. Compute q = 2^T / l
        let power_of_two = BigUint::one() << difficulty;
        let q = &power_of_two / &l;

        // 4. Compute proof = x^q mod N
        let proof = x.modpow(&q, modulus);

        let pad_256 = |mut bytes: Vec<u8>| {
            if bytes.len() < 256 {
                let mut padded = vec![0u8; 256 - bytes.len()];
                padded.append(&mut bytes);
                padded
            } else {
                bytes
            }
        };

        (pad_256(y.to_bytes_be()), pad_256(proof.to_bytes_be()))
    }
}

/// Wesolowski VDF Verifier
pub struct VdfVerifier;

impl VdfVerifier {
    /// Verifies the VDF solution: checks that y is indeed x^(2^T) mod N using the succinct proof.
    pub fn verify(x_hash: &[u8; 32], y_bytes: &[u8], proof_bytes: &[u8], difficulty: u64) -> bool {
        let modulus = get_modulus();
        let x = map_to_group(x_hash, modulus);
        let y = BigUint::from_bytes_be(y_bytes);
        let proof = BigUint::from_bytes_be(proof_bytes);

        if y >= *modulus || proof >= *modulus {
            return false;
        }

        // 1. Hash to prime l
        let l = hash_to_prime(&x, &y, difficulty, modulus);

        // 2. Compute remainder r = 2^T mod l
        let power_of_two = BigUint::one() << difficulty;
        let r = &power_of_two % &l;

        // 3. Verify: y == proof^l * x^r mod N
        let term1 = proof.modpow(&l, modulus);
        let term2 = x.modpow(&r, modulus);
        let computed_y = (term1 * term2) % modulus;

        computed_y == y
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vdf_solve_and_verify_success() {
        let input_hash = [0x42; 32];
        let difficulty = 500; // Small difficulty for fast test execution

        let (y, proof) = VdfProver::solve(&input_hash, difficulty);
        assert!(VdfVerifier::verify(&input_hash, &y, &proof, difficulty));
    }

    #[test]
    fn test_vdf_verify_failure_on_corrupt_proof() {
        let input_hash = [0x42; 32];
        let difficulty = 500;

        let (y, mut proof) = VdfProver::solve(&input_hash, difficulty);
        if !proof.is_empty() {
            proof[0] ^= 1; // Corrupt the proof
        }
        assert!(!VdfVerifier::verify(&input_hash, &y, &proof, difficulty));
    }

    #[test]
    fn test_vdf_verify_failure_on_corrupt_y() {
        let input_hash = [0x42; 32];
        let difficulty = 500;

        let (mut y, proof) = VdfProver::solve(&input_hash, difficulty);
        if !y.is_empty() {
            y[0] ^= 1; // Corrupt the output
        }
        assert!(!VdfVerifier::verify(&input_hash, &y, &proof, difficulty));
    }
}
