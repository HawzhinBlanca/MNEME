//! Beacon spot-check retrieval — independent reference sketch (Trick #1 prototype).
//!
//! **Honesty:** statistical audit deterrence on lottery-selected recalls only —
//! not per-call ZK, not semantic truth, not global exact-NN on every call.
//! See `docs/research/BEACON_SPOT_CHECK_RETRIEVAL.md`.
//!
//! Zero `mneme-*` dependencies preserved. Full BLS / drand chain verification is
//! intentionally deferred; this module documents wire layout + selector math mirroring
//! the primary implementation.

use crate::dcbor::{CborValue, Decoder};
use crate::error::CrossrefError;

/// Cert outer field key for optional `audit_beacon` (cognition certificate v1 / v2 draft).
pub const F_AUDIT_BEACON_CERT: u64 = 7;

/// Inner map field: drand round number.
pub const F_DRAND_ROUND: u64 = 1;
/// Inner map field: drand `randomness` (32 bytes).
pub const F_BEACON_RANDOMNESS: u64 = 2;
/// Inner map field: `audit_beacon_binding_digest(round, randomness, receipt.digest())`.
pub const F_BINDING_DIGEST: u64 = 3;

/// Domain tag binding drand beacon randomness into the receipt/cert hash domain.
pub const AUDIT_BEACON_BIND_TAG: &[u8] = b"MNEME-AUDIT-BEACON-BIND-v1";
/// Domain tag for lottery ticket derivation (beacon ‖ cert binding).
pub const AUDIT_LOTTERY_DOMAIN: &[u8] = b"MNEME-AUDIT-LOTTERY-v1";

/// Default audit lottery rate: 100_000 ppm = 10% of beacon-bound certificates.
pub const DEFAULT_AUDIT_RATE_PPM: u32 = 100_000;

pub const BEACON_SPOT_CHECK_HONESTY: &str = "Beacon spot-check upgrades audited calls only to \
lottery-enforced exact-NN over the committed embedding set; non-audited calls remain \
procedure-faithful only. Statistical deterrence, not per-call zero-knowledge; does not prove \
semantic truth.";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditBeacon {
    pub drand_round: u64,
    pub beacon_randomness: [u8; 32],
    pub binding_digest: [u8; 32],
}

/// Bind drand beacon into the receipt/cert hash domain (mirrors `mneme-index`).
pub fn audit_beacon_binding_digest(
    drand_round: u64,
    beacon_randomness: &[u8],
    receipt_digest: &[u8; 32],
) -> [u8; 32] {
    let mut payload = Vec::with_capacity(
        AUDIT_BEACON_BIND_TAG.len() + 8 + beacon_randomness.len() + 32,
    );
    payload.extend_from_slice(AUDIT_BEACON_BIND_TAG);
    payload.extend_from_slice(&drand_round.to_le_bytes());
    payload.extend_from_slice(beacon_randomness);
    payload.extend_from_slice(receipt_digest);
    *blake3::hash(&payload).as_bytes()
}

/// Deterministic lottery: returns true when this certificate is selected for spot-check audit.
pub fn audit_lottery_selected(
    beacon_randomness: &[u8],
    binding_digest: &[u8; 32],
    audit_rate_ppm: u32,
) -> bool {
    let mut payload =
        Vec::with_capacity(AUDIT_LOTTERY_DOMAIN.len() + beacon_randomness.len() + 32);
    payload.extend_from_slice(AUDIT_LOTTERY_DOMAIN);
    payload.extend_from_slice(beacon_randomness);
    payload.extend_from_slice(binding_digest);
    let hash = blake3::hash(&payload);
    let ticket = u64::from_le_bytes(hash.as_bytes()[0..8].try_into().unwrap());
    ticket % 1_000_000 < u64::from(audit_rate_ppm)
}

/// Decode optional `audit_beacon` extension map (fields 1..3).
pub fn decode_audit_beacon(bytes: &[u8]) -> Result<AuditBeacon, CrossrefError> {
    let mut dec = Decoder::new(bytes);
    let map = dec.decode_map()?;
    dec.ensure_consumed()?;

    let mut drand_round = None;
    let mut beacon_randomness = None;
    let mut binding_digest = None;

    for (key, value) in map {
        let field = key.as_u64().ok_or(CrossrefError::SchemaDrift)?;
        match field {
            F_DRAND_ROUND => drand_round = Some(value.as_u64().ok_or(CrossrefError::SchemaDrift)?),
            F_BEACON_RANDOMNESS => {
                beacon_randomness = Some(parse_fixed32(&value)?);
            }
            F_BINDING_DIGEST => binding_digest = Some(parse_fixed32(&value)?),
            _ => return Err(CrossrefError::SchemaDrift),
        }
    }

    Ok(AuditBeacon {
        drand_round: drand_round.ok_or(CrossrefError::SchemaDrift)?,
        beacon_randomness: beacon_randomness.ok_or(CrossrefError::SchemaDrift)?,
        binding_digest: binding_digest.ok_or(CrossrefError::SchemaDrift)?,
    })
}

/// Prototype verifier hook for Appendix B extension.
///
/// When `audit_beacon` is present and the call is selected, full exact-NN replay
/// requires embedding sidecars not carried in the v1 VO — return `UnsupportedVersion` until
/// the v-next distance-recompute path or store-backed audit CLI lands.
pub fn verify_beacon_spot_check_stub(
    beacon: Option<&AuditBeacon>,
    audit_rate_ppm: u32,
) -> Result<(), CrossrefError> {
    let Some(beacon) = beacon else {
        return Ok(());
    };
    if audit_lottery_selected(
        &beacon.beacon_randomness,
        &beacon.binding_digest,
        audit_rate_ppm,
    ) {
        return Err(CrossrefError::UnsupportedVersion);
    }
    Ok(())
}

fn parse_fixed32(value: &CborValue) -> Result<[u8; 32], CrossrefError> {
    let bytes = value.as_bytes().ok_or(CrossrefError::SchemaDrift)?;
    if bytes.len() != 32 {
        return Err(CrossrefError::SchemaDrift);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_lottery_is_deterministic() {
        let r = [0xAB; 32];
        let b = [0xCD; 32];
        assert_eq!(
            audit_lottery_selected(&r, &b, DEFAULT_AUDIT_RATE_PPM),
            audit_lottery_selected(&r, &b, DEFAULT_AUDIT_RATE_PPM)
        );
    }

    #[test]
    fn decode_audit_beacon_roundtrip_map() {
        use crate::dcbor::Encoder;
        let mut enc = Encoder::new();
        enc.begin_map(3).unwrap();
        enc.encode_unsigned(F_DRAND_ROUND).unwrap();
        enc.encode_unsigned(4_646_464).unwrap();
        enc.encode_unsigned(F_BEACON_RANDOMNESS).unwrap();
        enc.encode_bytes(&[0x11; 32]).unwrap();
        enc.encode_unsigned(F_BINDING_DIGEST).unwrap();
        enc.encode_bytes(&[0x22; 32]).unwrap();
        let bytes = enc.finish();

        let decoded = decode_audit_beacon(&bytes).unwrap();
        assert_eq!(decoded.drand_round, 4_646_464);
        assert_eq!(decoded.beacon_randomness, [0x11; 32]);
        assert_eq!(decoded.binding_digest, [0x22; 32]);
    }
}
