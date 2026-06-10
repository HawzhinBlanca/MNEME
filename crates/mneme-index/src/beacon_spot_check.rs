//! Trick #1 — Probabilistically-Checkable Retrieval (beacon spot-check prototype).
//!
//! Binds a public drand v2 beacon into the cognition-certificate hash domain and uses
//! lottery selection over that beacon to upgrade *audited calls only* to lottery-enforced
//! exact-NN when the verifier has query + candidate embeddings (offline test path) or
//! to require `ExactDominance` with full candidate-set binding (online default).
//!
//! **Honesty:** statistical deterrence via public randomness — not a per-call ZK proof.

use crate::distance::integer_distance;
use crate::procedure::replay_from_candidates;
use crate::receipt::SemanticRecallReceipt;
use mneme_core::{
    CborValue, DcborDecode, DcborEncode, Decoder, Encoder, FixedPointEmbedding, MnemeError,
    ObjectId, Procedure, RetrievalProofLevel, VerificationObject, from_bytes_strict,
    to_bytes_canonical,
};
use std::collections::BTreeMap;

/// Domain tag binding drand beacon randomness into the receipt/cert hash domain.
pub const AUDIT_BEACON_BIND_TAG: &[u8] = b"MNEME-AUDIT-BEACON-BIND-v1";

/// Domain tag for lottery ticket derivation (beacon ‖ cert binding).
pub const AUDIT_LOTTERY_DOMAIN: &[u8] = b"MNEME-AUDIT-LOTTERY-v1";

/// drand quicknet chain hash (v2 public API).
pub const DRAND_QUICKNET_CHAIN_HASH: &str =
    "52db9ba70e0cc95f407f896a1a2089b94999e381114878045d418bd5422e8305";

/// drand v2 round URL template (`{chain_hash}`, `{round}` placeholders).
pub const DRAND_V2_ROUND_URL_TEMPLATE: &str =
    "https://api.drand.sh/v2/beacons/{chain_hash}/rounds/{round}";

/// Default audit lottery rate: 100_000 ppm = 10% of beacon-bound certificates.
pub const DEFAULT_AUDIT_RATE_PPM: u32 = 100_000;

/// Prototype status (research / Trick #1).
pub const BEACON_SPOT_CHECK_STATUS: &str = concat!(
    "PROTOTYPE: beacon spot-check binds drand v2 public randomness into cognition certificates. ",
    "Statistical deterrence only — not a per-call ZK proof, not semantic truth."
);

/// Honesty boundary for beacon spot-check (§3 extension).
pub const BEACON_SPOT_CHECK_HONESTY: &str = concat!(
    "Beacon spot-check is probabilistic deterrence via public drand randomness, not a SNARK and ",
    "not zero-knowledge. Non-audited calls remain procedure-faithful only (not exact-NN). ",
    "Lottery-selected audited calls upgrade to lottery-enforced exact-NN on audited calls only: ",
    "verifiers require ExactDominance with full candidate-set binding and, when query+candidate ",
    "embeddings are available, recompute true query-to-embedding top-k. ",
    "This does not prove semantic truth. Unaudited calls keep the Phase I distance caveat: ",
    "top-k over prover-asserted distances; true top-k ranking is not proven until verifiers ",
    "recompute candidate distances from carried embeddings."
);

const F_DRAND_ROUND: u64 = 1;
const F_BEACON_RANDOMNESS: u64 = 2;
const F_BINDING_DIGEST: u64 = 3;

/// Expected drand beacon randomness length (SHA-256 of BLS signature).
pub const BEACON_RANDOMNESS_LEN: usize = 32;

/// Optional drand beacon carried on cognition certificate v1/v2 wire (field 7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditBeacon {
    pub drand_round: u64,
    /// Hex-decoded `randomness` from drand v2 API (offline path: trust carried bytes + binding).
    pub beacon_randomness: Vec<u8>,
    /// `audit_beacon_binding_digest(round, randomness, receipt.digest())`.
    pub binding_digest: [u8; 32],
}

/// Outcome of beacon lottery after binding verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BeaconAuditOutcome {
    /// Lottery did not select this certificate for spot-check upgrade.
    NotSelected,
    /// Lottery selected; stricter exact-NN obligations applied and passed.
    AuditedPassed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BeaconSpotCheckFailure {
    WireDecode,
    DrandRoundZero,
    BeaconRandomnessEmpty,
    BeaconRandomnessLengthInvalid,
    BindingDigestMismatch,
    #[cfg(feature = "beacon_online")]
    OnlineFetchFailed,
    #[cfg(feature = "beacon_online")]
    OnlineRandomnessMismatch,
    AuditedRequiresExactDominance,
    AuditedExactNnFailed,
    WireRoundMissing,
    WireRandomnessMissing,
    WireBindingMissing,
    WireUnknownField {
        field: u16,
    },
}

fn beacon_spot_check_failure_to_mneme(failure: BeaconSpotCheckFailure) -> MnemeError {
    match failure {
        BeaconSpotCheckFailure::WireUnknownField { field } => MnemeError::UnknownField { field },
        BeaconSpotCheckFailure::WireDecode
        | BeaconSpotCheckFailure::DrandRoundZero
        | BeaconSpotCheckFailure::BeaconRandomnessEmpty
        | BeaconSpotCheckFailure::BeaconRandomnessLengthInvalid
        | BeaconSpotCheckFailure::BindingDigestMismatch
        | BeaconSpotCheckFailure::AuditedRequiresExactDominance
        | BeaconSpotCheckFailure::AuditedExactNnFailed
        | BeaconSpotCheckFailure::WireRoundMissing
        | BeaconSpotCheckFailure::WireRandomnessMissing
        | BeaconSpotCheckFailure::WireBindingMissing => MnemeError::CertificateInvalid,
        #[cfg(feature = "beacon_online")]
        BeaconSpotCheckFailure::OnlineFetchFailed
        | BeaconSpotCheckFailure::OnlineRandomnessMismatch => MnemeError::CertificateInvalid,
    }
}

fn beacon_spot_check_error(failure: BeaconSpotCheckFailure) -> MnemeError {
    beacon_spot_check_failure_to_mneme(failure)
}

/// Bind drand beacon into the receipt/cert hash domain.
pub fn audit_beacon_binding_digest(
    drand_round: u64,
    beacon_randomness: &[u8],
    receipt_digest: &[u8; 32],
) -> [u8; 32] {
    let mut payload =
        Vec::with_capacity(AUDIT_BEACON_BIND_TAG.len() + 8 + beacon_randomness.len() + 32);
    payload.extend_from_slice(AUDIT_BEACON_BIND_TAG);
    payload.extend_from_slice(&drand_round.to_le_bytes());
    payload.extend_from_slice(beacon_randomness);
    payload.extend_from_slice(receipt_digest);
    *blake3::hash(&payload).as_bytes()
}

/// Build an `AuditBeacon` with a freshly computed binding over `receipt.digest()`.
pub fn prove_audit_beacon(
    drand_round: u64,
    beacon_randomness: Vec<u8>,
    receipt: &SemanticRecallReceipt,
) -> Result<AuditBeacon, MnemeError> {
    validate_beacon_randomness(&beacon_randomness)?;
    if drand_round == 0 {
        return Err(beacon_spot_check_error(
            BeaconSpotCheckFailure::DrandRoundZero,
        ));
    }
    let receipt_digest = receipt.digest();
    let binding_digest =
        audit_beacon_binding_digest(drand_round, &beacon_randomness, &receipt_digest);
    Ok(AuditBeacon {
        drand_round,
        beacon_randomness,
        binding_digest,
    })
}

fn validate_beacon_randomness(bytes: &[u8]) -> Result<(), MnemeError> {
    if bytes.is_empty() {
        return Err(beacon_spot_check_error(
            BeaconSpotCheckFailure::BeaconRandomnessEmpty,
        ));
    }
    if bytes.len() != BEACON_RANDOMNESS_LEN {
        return Err(beacon_spot_check_error(
            BeaconSpotCheckFailure::BeaconRandomnessLengthInvalid,
        ));
    }
    Ok(())
}

/// Offline path: verify carried beacon bytes and binding digest (no network).
pub fn verify_audit_beacon_offline(
    beacon: &AuditBeacon,
    receipt: &SemanticRecallReceipt,
) -> Result<(), MnemeError> {
    if beacon.drand_round == 0 {
        return Err(beacon_spot_check_error(
            BeaconSpotCheckFailure::DrandRoundZero,
        ));
    }
    validate_beacon_randomness(&beacon.beacon_randomness)?;
    let expected = audit_beacon_binding_digest(
        beacon.drand_round,
        &beacon.beacon_randomness,
        &receipt.digest(),
    );
    if expected != beacon.binding_digest {
        return Err(beacon_spot_check_error(
            BeaconSpotCheckFailure::BindingDigestMismatch,
        ));
    }
    Ok(())
}

/// Online path: fetch drand v2 `randomness` for `beacon.drand_round` and compare to carried bytes.
///
/// Requires the `beacon_online` feature (`ureq`). Offline verifiers should use
/// [`verify_audit_beacon_offline`] with pre-fetched beacon bytes embedded in the certificate.
#[cfg(feature = "beacon_online")]
pub fn fetch_drand_beacon_randomness(drand_round: u64) -> Result<Vec<u8>, MnemeError> {
    let url = DRAND_V2_ROUND_URL_TEMPLATE
        .replace("{chain_hash}", DRAND_QUICKNET_CHAIN_HASH)
        .replace("{round}", &drand_round.to_string());
    let response = ureq::get(&url)
        .call()
        .map_err(|_| beacon_spot_check_error(BeaconSpotCheckFailure::OnlineFetchFailed))?;
    let body: serde_json::Value = response
        .into_json()
        .map_err(|_| beacon_spot_check_error(BeaconSpotCheckFailure::OnlineFetchFailed))?;
    let randomness_hex = body["randomness"]
        .as_str()
        .ok_or_else(|| beacon_spot_check_error(BeaconSpotCheckFailure::OnlineFetchFailed))?;
    hex::decode(randomness_hex)
        .map_err(|_| beacon_spot_check_error(BeaconSpotCheckFailure::OnlineFetchFailed))
}

/// Online path: binding check + drand API cross-check of carried randomness.
#[cfg(feature = "beacon_online")]
pub fn verify_audit_beacon_online(
    beacon: &AuditBeacon,
    receipt: &SemanticRecallReceipt,
) -> Result<(), MnemeError> {
    verify_audit_beacon_offline(beacon, receipt)?;
    let fetched = fetch_drand_beacon_randomness(beacon.drand_round)?;
    if fetched != beacon.beacon_randomness {
        return Err(beacon_spot_check_error(
            BeaconSpotCheckFailure::OnlineRandomnessMismatch,
        ));
    }
    Ok(())
}

/// Deterministic lottery: returns true when this certificate is selected for spot-check audit.
pub fn audit_lottery_selected(
    beacon_randomness: &[u8],
    binding_digest: &[u8; 32],
    audit_rate_ppm: u32,
) -> bool {
    let mut payload = Vec::with_capacity(AUDIT_LOTTERY_DOMAIN.len() + beacon_randomness.len() + 32);
    payload.extend_from_slice(AUDIT_LOTTERY_DOMAIN);
    payload.extend_from_slice(beacon_randomness);
    payload.extend_from_slice(binding_digest);
    let hash = blake3::hash(&payload);
    let ticket = u64::from_le_bytes(hash.as_bytes()[0..8].try_into().expect("8 bytes"));
    ticket % 1_000_000 < u64::from(audit_rate_ppm)
}

/// Embeddings available to the verifier for lottery-enforced exact-NN on audited calls.
pub struct SpotCheckContext<'a> {
    pub query: &'a FixedPointEmbedding,
    pub entries: &'a [(ObjectId, FixedPointEmbedding)],
}

/// Recompute true query-to-embedding top-k over authenticated candidates (audited path only).
pub fn verify_spot_check_exact_nn(
    vo: &VerificationObject,
    proc: &Procedure,
    ctx: &SpotCheckContext<'_>,
) -> Result<(), MnemeError> {
    let mut emb_by_id: BTreeMap<ObjectId, &FixedPointEmbedding> = BTreeMap::new();
    for (id, emb) in ctx.entries {
        emb_by_id.insert(*id, emb);
    }
    let mut recomputed: Vec<(ObjectId, [u8; 32], i64)> = Vec::with_capacity(vo.candidates.len());
    for (id, emb_commit, asserted_dist) in &vo.candidates {
        let stored = emb_by_id
            .get(id)
            .ok_or_else(|| beacon_spot_check_error(BeaconSpotCheckFailure::AuditedExactNnFailed))?;
        if stored.commit() != *emb_commit {
            return Err(beacon_spot_check_error(
                BeaconSpotCheckFailure::AuditedExactNnFailed,
            ));
        }
        let true_dist = integer_distance(proc.distance, ctx.query, stored)?;
        if true_dist != *asserted_dist {
            return Err(beacon_spot_check_error(
                BeaconSpotCheckFailure::AuditedExactNnFailed,
            ));
        }
        recomputed.push((*id, *emb_commit, true_dist));
    }
    let replayed = replay_from_candidates(proc, &recomputed)?;
    if replayed != vo.result_ids {
        return Err(beacon_spot_check_error(
            BeaconSpotCheckFailure::AuditedExactNnFailed,
        ));
    }
    Ok(())
}

/// Verify optional beacon: offline binding + lottery; audited calls require `ExactDominance`
/// and optional embedding-backed exact-NN when `spot_check` is supplied.
pub fn verify_beacon_spot_check(
    beacon: &AuditBeacon,
    receipt: &SemanticRecallReceipt,
    level: RetrievalProofLevel,
    proc: &Procedure,
    audit_rate_ppm: u32,
    spot_check: Option<&SpotCheckContext<'_>>,
) -> Result<BeaconAuditOutcome, MnemeError> {
    verify_audit_beacon_offline(beacon, receipt)?;
    if !audit_lottery_selected(
        &beacon.beacon_randomness,
        &beacon.binding_digest,
        audit_rate_ppm,
    ) {
        return Ok(BeaconAuditOutcome::NotSelected);
    }
    if level != RetrievalProofLevel::ExactDominance {
        return Err(beacon_spot_check_error(
            BeaconSpotCheckFailure::AuditedRequiresExactDominance,
        ));
    }
    if let Some(ctx) = spot_check {
        verify_spot_check_exact_nn(&receipt.verification_object, proc, ctx)?;
    }
    Ok(BeaconAuditOutcome::AuditedPassed)
}

impl DcborEncode for AuditBeacon {
    fn dcbor_encode(&self, enc: &mut Encoder) -> Result<(), MnemeError> {
        enc.begin_map(3)?;
        enc.encode_unsigned(F_DRAND_ROUND)?;
        enc.encode_unsigned(self.drand_round)?;
        enc.encode_unsigned(F_BEACON_RANDOMNESS)?;
        enc.encode_bytes(&self.beacon_randomness)?;
        enc.encode_unsigned(F_BINDING_DIGEST)?;
        enc.encode_bytes(&self.binding_digest)?;
        Ok(())
    }
}

impl DcborDecode for AuditBeacon {
    fn dcbor_decode(dec: &mut Decoder<'_>) -> Result<Self, MnemeError> {
        let map = dec.decode_map()?;
        let mut drand_round = None;
        let mut beacon_randomness = None;
        let mut binding_digest = None;
        for (key, value) in map {
            let field = parse_u64_field_key(&key)?;
            match field {
                F_DRAND_ROUND => drand_round = Some(parse_u64(&value)?),
                F_BEACON_RANDOMNESS => beacon_randomness = Some(parse_bytes(&value)?),
                F_BINDING_DIGEST => binding_digest = Some(parse_fixed32(&value)?),
                _ => {
                    let field_id = u16::try_from(field).unwrap_or(u16::MAX);
                    return Err(beacon_spot_check_error(
                        BeaconSpotCheckFailure::WireUnknownField { field: field_id },
                    ));
                }
            }
        }
        Ok(Self {
            drand_round: drand_round
                .ok_or_else(|| beacon_spot_check_error(BeaconSpotCheckFailure::WireRoundMissing))?,
            beacon_randomness: beacon_randomness.ok_or_else(|| {
                beacon_spot_check_error(BeaconSpotCheckFailure::WireRandomnessMissing)
            })?,
            binding_digest: binding_digest.ok_or_else(|| {
                beacon_spot_check_error(BeaconSpotCheckFailure::WireBindingMissing)
            })?,
        })
    }
}

/// Decode beacon extension bytes from cognition certificate field 7.
pub fn decode_audit_beacon(bytes: &[u8]) -> Result<AuditBeacon, MnemeError> {
    from_bytes_strict(bytes)
        .map_err(|_| beacon_spot_check_error(BeaconSpotCheckFailure::WireDecode))
}

/// Encode beacon for cognition certificate field 7.
pub fn encode_audit_beacon(beacon: &AuditBeacon) -> Result<Vec<u8>, MnemeError> {
    to_bytes_canonical(beacon)
}

fn parse_u64_field_key(key: &CborValue) -> Result<u64, MnemeError> {
    key.as_u64()
        .ok_or_else(|| beacon_spot_check_error(BeaconSpotCheckFailure::WireDecode))
}

fn parse_u64(value: &CborValue) -> Result<u64, MnemeError> {
    value
        .as_u64()
        .ok_or_else(|| beacon_spot_check_error(BeaconSpotCheckFailure::WireDecode))
}

fn parse_bytes(value: &CborValue) -> Result<Vec<u8>, MnemeError> {
    value
        .as_bytes()
        .map(|b| b.to_vec())
        .ok_or_else(|| beacon_spot_check_error(BeaconSpotCheckFailure::WireDecode))
}

fn parse_fixed32(value: &CborValue) -> Result<[u8; 32], MnemeError> {
    let b = parse_bytes(value)?;
    b.try_into()
        .map_err(|_| beacon_spot_check_error(BeaconSpotCheckFailure::WireDecode))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mneme_core::{DistanceMetric, ProcedureAlgo};

    fn sample_receipt() -> SemanticRecallReceipt {
        SemanticRecallReceipt::new(
            [0xaa; 32],
            [0xbb; 32],
            mneme_core::VerificationObject {
                nodes: Vec::new(),
                candidates: vec![(ObjectId([0x01; 32]), [0x11; 32], 1)],
                leaf_indices: vec![0],
                procedure_id: [0x22; 32],
                query_commit: [0x33; 32],
                result_ids: vec![ObjectId([0x01; 32])],
            },
        )
    }

    #[test]
    fn beacon_honesty_strings_are_non_empty() {
        assert!(BEACON_SPOT_CHECK_HONESTY.contains("not a SNARK"));
        assert!(BEACON_SPOT_CHECK_HONESTY.contains("lottery-enforced exact-NN"));
        assert!(BEACON_SPOT_CHECK_HONESTY.contains("audited calls only"));
        assert!(BEACON_SPOT_CHECK_HONESTY.contains("procedure-faithful"));
        assert!(BEACON_SPOT_CHECK_STATUS.contains("Statistical deterrence"));
    }

    #[test]
    fn audit_beacon_wire_roundtrip() {
        let receipt = sample_receipt();
        let beacon = prove_audit_beacon(42, vec![0x55; 32], &receipt).unwrap();
        let bytes = encode_audit_beacon(&beacon).unwrap();
        let decoded = decode_audit_beacon(&bytes).unwrap();
        assert_eq!(decoded, beacon);
    }

    #[test]
    fn binding_rejects_forged_digest() {
        let receipt = sample_receipt();
        let mut beacon = prove_audit_beacon(7, vec![0x66; 32], &receipt).unwrap();
        beacon.binding_digest[0] ^= 0xff;
        assert_eq!(
            verify_audit_beacon_offline(&beacon, &receipt),
            Err(MnemeError::CertificateInvalid)
        );
    }

    #[test]
    fn lottery_is_deterministic() {
        let binding = [0x77; 32];
        let randomness = vec![0x88; 32];
        let a = audit_lottery_selected(&randomness, &binding, DEFAULT_AUDIT_RATE_PPM);
        let b = audit_lottery_selected(&randomness, &binding, DEFAULT_AUDIT_RATE_PPM);
        assert_eq!(a, b);
    }

    #[test]
    fn spot_check_exact_nn_rejects_wrong_distance() {
        let proc = mneme_core::Procedure {
            algo: ProcedureAlgo::Hnsw,
            ef_search: 64,
            k: 1,
            distance: DistanceMetric::SquaredL2I64,
            seed: 0,
        };
        let query = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
        let emb = FixedPointEmbedding::new(2, 0, vec![5, 0]).unwrap();
        let id = ObjectId([0x01; 32]);
        let vo = mneme_core::VerificationObject {
            nodes: Vec::new(),
            candidates: vec![(id, emb.commit(), 999)],
            leaf_indices: vec![0],
            procedure_id: [0x22; 32],
            query_commit: query.commit(),
            result_ids: vec![id],
        };
        let ctx = SpotCheckContext {
            query: &query,
            entries: &[(id, emb)],
        };
        assert_eq!(
            verify_spot_check_exact_nn(&vo, &proc, &ctx),
            Err(MnemeError::CertificateInvalid)
        );
    }
}
