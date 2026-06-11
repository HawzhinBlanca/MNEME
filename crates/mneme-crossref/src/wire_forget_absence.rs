//! Forget-absence — independent reference sketch (Trick #3 prototype).

pub const COGNITION_CERT_COMMIT_TAG: &[u8] = b"MNEME-COGNITION-CERT-COMMIT/v1";

pub const FORGET_ABSENCE_HONESTY: &str = "Forget-absence proves non-membership of the forgotten \
target commit in operator-supplied post-forget cognition certificates only (Ω(N) scan). \
Certified cognition only; operator can withhold certs. Does not prove out-of-band deletion \
or semantic truth.";

pub fn cognition_certificate_commit(cert_bytes: &[u8]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(COGNITION_CERT_COMMIT_TAG.len() + cert_bytes.len());
    payload.extend_from_slice(COGNITION_CERT_COMMIT_TAG);
    payload.extend_from_slice(cert_bytes);
    *blake3::hash(&payload).as_bytes()
}

pub fn post_forget_non_use_scan(
    forget_sequence: u64,
    cert_sequences: &[(u64, &[[u8; 32]])],
    target_commit: &[u8; 32],
) -> bool {
    for (seq, used) in cert_sequences {
        if *seq <= forget_sequence { return false; }
        if used.iter().any(|c| c == target_commit) { return false; }
    }
    !cert_sequences.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn non_use_scan_rejects_used_target() {
        let used = [[0xAA; 32], [0xBB; 32]];
        assert!(!post_forget_non_use_scan(3, &[(5, &used)], &[0xAA; 32]));
    }
    #[test]
    fn non_use_scan_accepts_clean_chain() {
        let used = [[0xAA; 32], [0xBB; 32]];
        assert!(post_forget_non_use_scan(3, &[(5, &used)], &[0xCC; 32]));
    }
}
