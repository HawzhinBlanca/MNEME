pub const PACE_ALG_BLAKE3_SEQUENTIAL: u8 = 2;
pub const PACE_DOMAIN_GENESIS: &[u8] = b"MNEME-PACE/v1/genesis";

#[inline]
pub fn blake3_step(input: &[u8; 32]) -> [u8; 32] {
    *blake3::hash(input).as_bytes()
}

pub fn blake3_sequential(seed: &[u8; 32], iterations: u64) -> [u8; 32] {
    let mut state = *seed;
    for _ in 0..iterations {
        state = blake3_step(&state);
    }
    state
}

pub fn pace_genesis_anchor(genesis: &[u8; 32]) -> [u8; 32] {
    *blake3::Hasher::new()
        .update(PACE_DOMAIN_GENESIS)
        .update(genesis)
        .finalize()
        .as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequential_is_repeatable() {
        let seed = [7u8; 32];
        assert_eq!(blake3_sequential(&seed, 16), blake3_sequential(&seed, 16));
    }
}
