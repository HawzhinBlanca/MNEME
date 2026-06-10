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

/// Cert outer field key for `audit_beacon` on Cognition Certificate v1.
pub const F_AUDIT_BEACON_CERT_V1: u64 = 6;
/// Cert outer field key for `audit_beacon` on Cognition Certificate v2 draft.
pub const F_AUDIT_BEACON_CERT_V2: u64 = 7;

/// Default audit rate: ~1/256 recalls selected for full exact-NN recompute.
pub const AUDIT_RATE_DENOM: u64 = 256;

/// Domain tag for beacon output hashing (matches primary crate).
pub const AUDIT_BEACON_RANDOMNESS_DOMAIN: &[u8] = b"MNEME-AUDIT-BEACON/v1";
/// Domain tag for audit selector (matches primary crate).
pub const AUDIT_SELECT_DOMAIN: &[u8] = b"MNEME-AUDIT-SELECT/v1";

pub const BEACON_SPOT_CHECK_HONESTY: &str = "Beacon spot-check upgrades audited calls only to \
lottery-enforced exact-NN over the committed embedding set; non-audited calls remain \
procedure-faithful only. Statistical deterrence, not per-call zero-knowledge; does not prove \
semantic truth.";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditBeacon {
    pub source: BeaconSource,
    pub round: u64,
    pub randomness: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BeaconSource {
    Drand,
    Nist,
}

impl BeaconSource {
    fn parse(text: &str) -> Result<Self, CrossrefError> {
        match text {
            "drand" => Ok(Self::Drand),
            "nist" => Ok(Self::Nist),
            _ => Err(CrossrefError::SchemaDrift),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Drand => "drand",
            Self::Nist => "nist",
        }
    }
}

/// Decode optional `audit_beacon` extension map (fields 0..2).
pub fn decode_audit_beacon(bytes: &[u8]) -> Result<AuditBeacon, CrossrefError> {
    let mut dec = Decoder::new(bytes);
    let map = dec.decode_map()?;
    dec.ensure_consumed()?;

    let mut source = None;
    let mut round = None;
    let mut randomness = None;

    for (key, value) in map {
        let field = key.as_u64().ok_or(CrossrefError::SchemaDrift)?;
        match field {
            0 => {
                let text = value.as_text().ok_or(CrossrefError::SchemaDrift)?;
                source = Some(BeaconSource::parse(text)?);
            }
            1 => round = Some(value.as_u64().ok_or(CrossrefError::SchemaDrift)?),
            2 => randomness = Some(parse_fixed32(&value)?),
            _ => return Err(CrossrefError::SchemaDrift),
        }
    }

    Ok(AuditBeacon {
        source: source.ok_or(CrossrefError::SchemaDrift)?,
        round: round.ok_or(CrossrefError::SchemaDrift)?,
        randomness: randomness.ok_or(CrossrefError::SchemaDrift)?,
    })
}

/// Deterministic audit selector (reference implementation).
pub fn audit_selected(
    randomness: &[u8; 32],
    query_commit: &[u8; 32],
    semantic_commit: &[u8; 32],
) -> bool {
    let mut hasher = blake3::Hasher::new();
    hasher.update(AUDIT_SELECT_DOMAIN);
    hasher.update(randomness);
    hasher.update(query_commit);
    hasher.update(semantic_commit);
    let digest = hasher.finalize();
    let limb = u64::from_le_bytes(digest.as_bytes()[0..8].try_into().unwrap());
    limb % AUDIT_RATE_DENOM == 0
}

/// Prototype verifier hook for Appendix B extension.
///
/// When `audit_beacon` is present and the call is selected, full exact-NN replay
/// requires embedding sidecars not carried in the v1 VO — return `AuditRequired` until
/// the v-next distance-recompute path or store-backed audit CLI lands.
pub fn verify_beacon_spot_check_stub(
    beacon: Option<&AuditBeacon>,
    query_commit: &[u8; 32],
    semantic_commit: &[u8; 32],
) -> Result<(), CrossrefError> {
    let Some(beacon) = beacon else {
        return Ok(());
    };
    if audit_selected(&beacon.randomness, query_commit, semantic_commit) {
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
    fn audit_selector_is_deterministic() {
        let r = [0xAB; 32];
        let q = [0x01; 32];
        let s = [0x02; 32];
        assert_eq!(audit_selected(&r, &q, &s), audit_selected(&r, &q, &s));
    }

    #[test]
    fn decode_audit_beacon_roundtrip_map() {
        use crate::dcbor::Encoder;
        let mut enc = Encoder::new();
        enc.begin_map(3).unwrap();
        enc.encode_unsigned(0).unwrap();
        enc.encode_text("drand").unwrap();
        enc.encode_unsigned(1).unwrap();
        enc.encode_unsigned(4_646_464).unwrap();
        enc.encode_unsigned(2).unwrap();
        enc.encode_bytes(&[0x11; 32]).unwrap();
        let bytes = enc.finish();

        let decoded = decode_audit_beacon(&bytes).unwrap();
        assert_eq!(decoded.source, BeaconSource::Drand);
        assert_eq!(decoded.round, 4_646_464);
        assert_eq!(decoded.randomness, [0x11; 32]);
    }
}
