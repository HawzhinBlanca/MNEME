//! RPT — Radioactive Provenance Tracer (EXPERIMENTAL, statistical, off by default).
//!
//! A per-record watermark keyed to the record's DAG-node id: a deterministic "green
//! list" partition of the token vocabulary (after Kirchenbauer et al.). If a partner
//! trains on a watermarked export, its outputs are biased toward that record's green
//! list; the detector measures the green-token fraction of a suspect token stream and
//! reports a z-score and an (approximate) one-sided p-value.
//!
//! HONESTY BOUNDARY (do not weaken): this is STATISTICAL, not cryptographic. It detects
//! a VIOLATION with a p-value; it can NEVER prove a clean negative ("absence of use").
//! It only carries signal for partners who *train* on the data — in-context / RAG use
//! leaves NO training signature — and it requires query access to the suspect model.
//! Off by default, experimental. Authenticated != true; detection != proof.

use mneme_core::MnemeError;

const GREENLIST_DOMAIN: &[u8] = b"MNEME-rpt-greenlist-v1";

pub const RPT_HONESTY: &str = "EXPERIMENTAL statistical tracer: a low p-value flags likely \
training on a watermarked record; it NEVER proves non-use (no clean negative), carries signal \
only for partners that TRAIN on the data (not in-context/RAG), and needs query access to the \
suspect model. Statistical, not cryptographic — detection != proof, authenticated != true";

/// Deterministic per-record green-list keyed to the DAG-node id. A token id `t` is green
/// iff `H(domain ‖ dag_node_id ‖ t) mod 10000 < gamma_permil_10k`. `gamma` is the target
/// green fraction in (0,1); the keying is stable and host-independent.
pub fn is_green(dag_node_id: &[u8; 32], token: u32, gamma: f64) -> bool {
    let mut h = blake3::Hasher::new();
    h.update(GREENLIST_DOMAIN);
    h.update(dag_node_id);
    h.update(&token.to_le_bytes());
    let d = h.finalize();
    let v = u32::from_le_bytes([
        d.as_bytes()[0],
        d.as_bytes()[1],
        d.as_bytes()[2],
        d.as_bytes()[3],
    ]);
    let threshold = (gamma.clamp(0.0, 1.0) * f64::from(u32::MAX)) as u32;
    v < threshold
}

/// Result of probing a suspect token stream for a record's watermark.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DetectionResult {
    pub total: usize,
    pub green: usize,
    pub gamma: f64,
    pub z_score: f64,
    pub p_value: f64,
}

/// Approximate complementary error function (Abramowitz & Stegun 7.1.26, ~1e-7).
fn erfc(x: f64) -> f64 {
    let z = x.abs();
    let t = 1.0 / (1.0 + 0.5 * z);
    let tau = t
        * (-z * z - 1.26551223
            + t * (1.00002368
                + t * (0.37409196
                    + t * (0.09678418
                        + t * (-0.18628806
                            + t * (0.27886807
                                + t * (-1.13520398
                                    + t * (1.48851587 + t * (-0.82215223 + t * 0.17087277)))))))))
            .exp();
    if x >= 0.0 { tau } else { 2.0 - tau }
}

/// Probe `tokens` for the green-list of `dag_node_id`. Under the null (no watermark) the
/// green fraction is ~`gamma`; a watermarked/trained stream shows an excess, raising the
/// z-score and lowering the one-sided p-value.
pub fn detect(
    dag_node_id: &[u8; 32],
    tokens: &[u32],
    gamma: f64,
) -> Result<DetectionResult, MnemeError> {
    if tokens.is_empty() || !(0.0..1.0).contains(&gamma) || gamma <= 0.0 {
        return Err(MnemeError::SchemaDrift);
    }
    let total = tokens.len();
    let green = tokens
        .iter()
        .filter(|&&t| is_green(dag_node_id, t, gamma))
        .count();
    let t = total as f64;
    let expected = gamma * t;
    let std = (t * gamma * (1.0 - gamma)).sqrt();
    let z_score = if std > 0.0 {
        (green as f64 - expected) / std
    } else {
        0.0
    };
    // One-sided upper-tail p-value: P(Z >= z) = 0.5 * erfc(z / sqrt 2).
    let p_value = 0.5 * erfc(z_score / std::f64::consts::SQRT_2);
    Ok(DetectionResult {
        total,
        green,
        gamma,
        z_score,
        p_value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn xorshift(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    #[test]
    fn green_list_is_deterministic_and_roughly_gamma() {
        let n = node(0x11);
        // Deterministic.
        assert_eq!(is_green(&n, 42, 0.5), is_green(&n, 42, 0.5));
        // Roughly gamma fraction over a vocab sweep.
        let vocab = 20_000u32;
        let gamma = 0.25;
        let greens = (0..vocab).filter(|&t| is_green(&n, t, gamma)).count();
        let frac = greens as f64 / f64::from(vocab);
        assert!(
            (frac - gamma).abs() < 0.02,
            "green fraction {frac} should be ~{gamma}"
        );
    }

    #[test]
    fn watermarked_stream_is_detected_with_tiny_p() {
        // A stream drawn ENTIRELY from the green list (as a trained model would be
        // biased) must yield a huge z and a vanishing p-value.
        let n = node(0x22);
        let gamma = 0.25;
        let green_tokens: Vec<u32> = (0..50_000u32).filter(|&t| is_green(&n, t, gamma)).collect();
        let stream: Vec<u32> = (0..400)
            .map(|i| green_tokens[i % green_tokens.len()])
            .collect();
        let r = detect(&n, &stream, gamma).unwrap();
        assert!(r.z_score > 8.0, "z={} should be large", r.z_score);
        assert!(r.p_value < 1e-12, "p={} should be vanishing", r.p_value);
    }

    #[test]
    fn unmarked_stream_is_not_detected() {
        // A random stream (no training on this record) sits near the null: modest z,
        // p-value far from significant.
        let n = node(0x33);
        let gamma = 0.25;
        let mut st = 0xDEAD_BEEF;
        let stream: Vec<u32> = (0..400)
            .map(|_| (xorshift(&mut st) % 50_000) as u32)
            .collect();
        let r = detect(&n, &stream, gamma).unwrap();
        assert!(r.z_score.abs() < 4.0, "z={} should be near null", r.z_score);
        assert!(
            r.p_value > 1e-4,
            "p={} should not be significant",
            r.p_value
        );
    }

    #[test]
    fn watermark_for_one_record_is_not_detected_under_another_key() {
        // A stream marked for node A must NOT trip the detector keyed to node B —
        // the watermark is per-record (per DAG node).
        let a = node(0x44);
        let b = node(0x55);
        let gamma = 0.25;
        let a_green: Vec<u32> = (0..50_000u32).filter(|&t| is_green(&a, t, gamma)).collect();
        let stream: Vec<u32> = (0..400).map(|i| a_green[i % a_green.len()]).collect();
        let under_b = detect(&b, &stream, gamma).unwrap();
        assert!(
            under_b.z_score.abs() < 4.0,
            "A-marked stream must look null under B's key (z={})",
            under_b.z_score
        );
    }

    #[test]
    fn empty_or_bad_gamma_fails_closed() {
        assert!(detect(&node(1), &[], 0.5).is_err());
        assert!(detect(&node(1), &[1, 2, 3], 0.0).is_err());
        assert!(detect(&node(1), &[1, 2, 3], 1.0).is_err());
    }
}
