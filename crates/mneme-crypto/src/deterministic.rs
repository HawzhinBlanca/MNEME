//! Gate-only deterministic randomness (blueprint §17.7 foundation-gate).
//!
//! When enabled via [`enable_fixture_crypto`], vault keys and AEAD nonces derive from a
//! fixed seed + monotonic counter. Production CLI paths leave this disabled and use OsRng.

use std::cell::RefCell;

thread_local! {
    static FIXTURE: RefCell<Option<([u8; 32], u64)>> = const { RefCell::new(None) };
}

/// Enable deterministic crypto material for foundation-gate fixture runs only.
pub fn enable_fixture_crypto(seed: [u8; 32]) {
    FIXTURE.with(|f| *f.borrow_mut() = Some((seed, 0)));
}

/// Disable fixture mode (restores OsRng for subsequent operations).
pub fn disable_fixture_crypto() {
    FIXTURE.with(|f| *f.borrow_mut() = None);
}

/// Fill `out` with OsRng bytes, or deterministic bytes when fixture mode is active.
pub fn fill_random<const N: usize>(domain: &str, out: &mut [u8; N]) {
    if let Some(bytes) = fixture_derive::<N>(domain) {
        *out = bytes;
        return;
    }
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, out);
}

fn fixture_derive<const N: usize>(domain: &str) -> Option<[u8; N]> {
    FIXTURE.with(|f| {
        let mut guard = f.borrow_mut();
        let (seed, counter) = guard.as_mut()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain.as_bytes());
        hasher.update(seed);
        hasher.update(&counter.to_le_bytes());
        *counter += 1;
        let hash = hasher.finalize();
        let mut out = [0u8; N];
        out.copy_from_slice(&hash.as_bytes()[..N]);
        Some(out)
    })
}
