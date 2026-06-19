//! Cognition Certificate attachment for `RetrievalProofLevel::CompleteTopK` (CR-6).

use crate::complete_knn::{
    AuthNodeProof, AuthPathStep, BeaconSeed, CompleteKnnProof, ExcludedLeaf, FrontierNode,
    ReturnedPoint, verify_complete_knn,
};
use mneme_core::{CborValue, Decoder, Encoder, MnemeError};

const F_COMMITMENT: u64 = 1;
const F_QUERY: u64 = 2;
const F_K: u64 = 3;
const F_PROOF: u64 = 4;
const F_BEACON_ROUND: u64 = 5;
const F_BEACON_SEED: u64 = 6;
const F_CONSTANT_PROOF_HASH: u64 = 7;
const F_MERKLE_HNSW_ROOT: u64 = 8;
const F_CONSTANT_SIZE: u64 = 9;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompleteKnnCertFailure {
    Invalid,
    ProcedureMismatch,
    ObjectTampered,
}

fn complete_knn_cert_failure_to_mneme(failure: CompleteKnnCertFailure) -> MnemeError {
    match failure {
        CompleteKnnCertFailure::Invalid => MnemeError::CertificateInvalid,
        CompleteKnnCertFailure::ProcedureMismatch => MnemeError::ProcedureMismatch,
        CompleteKnnCertFailure::ObjectTampered => MnemeError::ObjectTampered,
    }
}

fn complete_knn_cert_invalid_error() -> MnemeError {
    complete_knn_cert_failure_to_mneme(CompleteKnnCertFailure::Invalid)
}

fn complete_knn_cert_error(failure: CompleteKnnCertFailure) -> MnemeError {
    complete_knn_cert_failure_to_mneme(failure)
}

/// Offline-verifiable complete top-k payload (receipt field 8 inner body).
#[derive(Clone, Debug, PartialEq)]
pub struct CompleteKnnCertAttachment {
    pub commitment: [u8; 32],
    pub query: Vec<f64>,
    pub k: u32,
    pub proof: CompleteKnnProof,
    pub beacon: Option<BeaconSeed>,
    // TTRP-1 constant-size proof fields
    pub constant_proof_hash: Option<[u8; 32]>,
    pub merkle_hnsw_root: Option<[u8; 32]>,
    pub constant_size: bool,
}

pub fn hash_proof(proof: &CompleteKnnProof) -> Result<[u8; 32], MnemeError> {
    let mut enc = Encoder::new();
    encode_proof(&mut enc, proof)?;
    let bytes = enc.finish();
    let mut h = blake3::Hasher::new();
    h.update(&bytes);
    Ok(*h.finalize().as_bytes())
}

impl CompleteKnnCertAttachment {
    pub fn verify_offline(&self) -> Result<(), MnemeError> {
        if self.constant_size {
            return Err(complete_knn_cert_error(
                CompleteKnnCertFailure::ProcedureMismatch,
            )); // Must verify with out-of-band proof
        }
        verify_complete_knn(
            &self.commitment,
            &self.query,
            usize::try_from(self.k).map_err(|_| complete_knn_cert_invalid_error())?,
            &self.proof,
        )
    }

    pub fn verify_offline_with_proof(&self, proof: &CompleteKnnProof) -> Result<(), MnemeError> {
        let expected_hash = self
            .constant_proof_hash
            .ok_or_else(|| complete_knn_cert_error(CompleteKnnCertFailure::Invalid))?;
        let actual_hash = hash_proof(proof)?;
        if actual_hash != expected_hash {
            return Err(complete_knn_cert_error(
                CompleteKnnCertFailure::ObjectTampered,
            ));
        }
        let _hnsw_root = self
            .merkle_hnsw_root
            .ok_or_else(|| complete_knn_cert_error(CompleteKnnCertFailure::Invalid))?;
        if _hnsw_root == [0u8; 32] {
            return Err(complete_knn_cert_error(CompleteKnnCertFailure::Invalid));
        }
        verify_complete_knn(
            &self.commitment,
            &self.query,
            usize::try_from(self.k).map_err(|_| complete_knn_cert_invalid_error())?,
            proof,
        )
    }
}

pub fn encode_complete_knn_attachment(
    att: &CompleteKnnCertAttachment,
) -> Result<Vec<u8>, MnemeError> {
    let mut enc = Encoder::new();
    let mut n = 5u64; // commitment, query, k, proof, constant_size
    if att.beacon.is_some() {
        n += 2;
    }
    if att.constant_proof_hash.is_some() {
        n += 1;
    }
    if att.merkle_hnsw_root.is_some() {
        n += 1;
    }
    enc.begin_map(n)?;
    enc.encode_unsigned(F_COMMITMENT)?;
    enc.encode_bytes(&att.commitment)?;
    enc.encode_unsigned(F_QUERY)?;
    encode_f64_vec(&mut enc, &att.query)?;
    enc.encode_unsigned(F_K)?;
    enc.encode_unsigned(u64::from(att.k))?;
    enc.encode_unsigned(F_PROOF)?;
    encode_proof(&mut enc, &att.proof)?;
    // dCBOR requires canonical (ascending) map-key order. Emit optional fields in
    // key order 5,6 (beacon) → 7 → 8 → 9 so strict decode never rejects a
    // constant-size attachment (which carries fields 7 and 8 alongside 9).
    if let Some(beacon) = &att.beacon {
        enc.encode_unsigned(F_BEACON_ROUND)?;
        enc.encode_unsigned(beacon.round)?;
        enc.encode_unsigned(F_BEACON_SEED)?;
        enc.encode_bytes(&beacon.seed)?;
    }
    if let Some(hash) = &att.constant_proof_hash {
        enc.encode_unsigned(F_CONSTANT_PROOF_HASH)?;
        enc.encode_bytes(hash)?;
    }
    if let Some(root) = &att.merkle_hnsw_root {
        enc.encode_unsigned(F_MERKLE_HNSW_ROOT)?;
        enc.encode_bytes(root)?;
    }
    enc.encode_unsigned(F_CONSTANT_SIZE)?;
    enc.encode_bool(att.constant_size)?;
    Ok(enc.finish())
}

pub fn decode_complete_knn_attachment(
    bytes: &[u8],
) -> Result<CompleteKnnCertAttachment, MnemeError> {
    let mut dec = Decoder::new(bytes);
    let map = dec.decode_map()?;
    let mut commitment = None;
    let mut query = None;
    let mut k = None;
    let mut proof = None;
    let mut beacon_round = None;
    let mut beacon_seed = None;
    let mut constant_proof_hash = None;
    let mut merkle_hnsw_root = None;
    let mut constant_size = false;
    for (key, value) in map {
        let field = key.as_u64().ok_or(complete_knn_cert_invalid_error())?;
        match field {
            F_COMMITMENT => commitment = Some(parse_fixed32(&value)?),
            F_QUERY => query = Some(decode_f64_vec(&value)?),
            F_K => {
                k = Some(
                    u32::try_from(parse_u64(&value)?)
                        .map_err(|_| complete_knn_cert_invalid_error())?,
                );
            }
            F_PROOF => proof = Some(decode_proof(&value)?),
            F_BEACON_ROUND => beacon_round = Some(parse_u64(&value)?),
            F_BEACON_SEED => beacon_seed = Some(parse_fixed32(&value)?),
            F_CONSTANT_PROOF_HASH => constant_proof_hash = Some(parse_fixed32(&value)?),
            F_MERKLE_HNSW_ROOT => merkle_hnsw_root = Some(parse_fixed32(&value)?),
            F_CONSTANT_SIZE => {
                constant_size = match &value {
                    CborValue::Bool(b) => *b,
                    _ => return Err(complete_knn_cert_invalid_error()),
                };
            }
            _ => return Err(complete_knn_cert_invalid_error()),
        }
    }
    let beacon = match (beacon_round, beacon_seed) {
        (Some(round), Some(seed)) => Some(BeaconSeed { round, seed }),
        (None, None) => None,
        _ => return Err(complete_knn_cert_invalid_error()),
    };
    let proof = proof.unwrap_or(CompleteKnnProof {
        total_points: 0,
        returned: Vec::new(),
        frontier: Vec::new(),
        excluded: Vec::new(),
    });
    Ok(CompleteKnnCertAttachment {
        commitment: commitment.ok_or(complete_knn_cert_invalid_error())?,
        query: query.ok_or(complete_knn_cert_invalid_error())?,
        k: k.ok_or(complete_knn_cert_invalid_error())?,
        proof,
        beacon,
        constant_proof_hash,
        merkle_hnsw_root,
        constant_size,
    })
}

/// Decode the out-of-band proof file emitted by `certify --constant-size --proof-out`.
/// That file is a full complete-kNN attachment (the cert's `complete_knn.proof_bytes`,
/// issued with `constant_size=false` so the proof body is present); the out-of-band
/// proof we need for `verify_offline_with_proof` is its `proof` field.
pub fn decode_proof_bytes_direct(bytes: &[u8]) -> Result<CompleteKnnProof, MnemeError> {
    Ok(decode_complete_knn_attachment(bytes)?.proof)
}

fn encode_proof(enc: &mut Encoder, proof: &CompleteKnnProof) -> Result<(), MnemeError> {
    let mut inner = Encoder::new();
    inner.begin_map(4)?;
    inner.encode_unsigned(1)?;
    inner.encode_unsigned(
        u64::try_from(proof.total_points).map_err(|_| complete_knn_cert_invalid_error())?,
    )?;
    inner.encode_unsigned(2)?;
    encode_returned(&mut inner, &proof.returned)?;
    inner.encode_unsigned(3)?;
    encode_frontier(&mut inner, &proof.frontier)?;
    inner.encode_unsigned(4)?;
    encode_excluded(&mut inner, &proof.excluded)?;
    enc.encode_bytes(&inner.finish())
}

fn decode_proof(value: &CborValue) -> Result<CompleteKnnProof, MnemeError> {
    let bytes = value.as_bytes().ok_or(complete_knn_cert_invalid_error())?;
    let mut dec = Decoder::new(bytes);
    let map = dec.decode_map()?;
    let mut total_points = None;
    let mut returned = None;
    let mut frontier = None;
    let mut excluded = None;
    for (key, value) in map {
        match key.as_u64().ok_or(complete_knn_cert_invalid_error())? {
            1 => {
                total_points = Some(
                    usize::try_from(parse_u64(&value)?)
                        .map_err(|_| complete_knn_cert_invalid_error())?,
                );
            }
            2 => returned = Some(decode_returned(&value)?),
            3 => frontier = Some(decode_frontier(&value)?),
            4 => excluded = Some(decode_excluded(&value)?),
            _ => return Err(complete_knn_cert_invalid_error()),
        }
    }
    Ok(CompleteKnnProof {
        total_points: total_points.ok_or(complete_knn_cert_invalid_error())?,
        returned: returned.ok_or(complete_knn_cert_invalid_error())?,
        frontier: frontier.ok_or(complete_knn_cert_invalid_error())?,
        excluded: excluded.ok_or(complete_knn_cert_invalid_error())?,
    })
}

fn encode_returned(enc: &mut Encoder, rows: &[ReturnedPoint]) -> Result<(), MnemeError> {
    enc.begin_array(rows.len() as u64)?;
    for row in rows {
        enc.begin_array(4)?;
        enc.encode_unsigned(
            u64::try_from(row.index).map_err(|_| complete_knn_cert_invalid_error())?,
        )?;
        encode_f64_vec(enc, &row.point)?;
        enc.encode_unsigned(f64_to_u64(row.distance_sq)?)?;
        encode_auth(enc, &row.auth)?;
    }
    Ok(())
}

fn decode_returned(value: &CborValue) -> Result<Vec<ReturnedPoint>, MnemeError> {
    let arr = value.as_array().ok_or(complete_knn_cert_invalid_error())?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let row = item.as_array().ok_or(complete_knn_cert_invalid_error())?;
        if row.len() != 4 {
            return Err(complete_knn_cert_invalid_error());
        }
        out.push(ReturnedPoint {
            index: usize::try_from(parse_u64(&row[0])?)
                .map_err(|_| complete_knn_cert_invalid_error())?,
            point: decode_f64_vec(&row[1])?,
            distance_sq: u64_to_f64(parse_u64(&row[2])?)?,
            auth: decode_auth(&row[3])?,
        });
    }
    Ok(out)
}

fn encode_frontier(enc: &mut Encoder, rows: &[FrontierNode]) -> Result<(), MnemeError> {
    enc.begin_array(rows.len() as u64)?;
    for row in rows {
        enc.begin_array(7)?;
        enc.encode_unsigned(
            u64::try_from(row.pivot_index).map_err(|_| complete_knn_cert_invalid_error())?,
        )?;
        encode_f64_vec(enc, &row.pivot)?;
        enc.encode_unsigned(f64_to_u64(row.radius_sq)?)?;
        enc.encode_bytes(&row.left_hash)?;
        enc.encode_bytes(&row.right_hash)?;
        enc.begin_array(row.subtree_leaf_indices.len() as u64)?;
        for idx in &row.subtree_leaf_indices {
            enc.encode_unsigned(
                u64::try_from(*idx).map_err(|_| complete_knn_cert_invalid_error())?,
            )?;
        }
        encode_auth(enc, &row.auth)?;
    }
    Ok(())
}

fn decode_frontier(value: &CborValue) -> Result<Vec<FrontierNode>, MnemeError> {
    let arr = value.as_array().ok_or(complete_knn_cert_invalid_error())?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let row = item.as_array().ok_or(complete_knn_cert_invalid_error())?;
        if row.len() != 7 {
            return Err(complete_knn_cert_invalid_error());
        }
        let indices_arr = row[5].as_array().ok_or(complete_knn_cert_invalid_error())?;
        let mut subtree_leaf_indices = Vec::with_capacity(indices_arr.len());
        for v in indices_arr {
            subtree_leaf_indices.push(
                usize::try_from(parse_u64(v)?).map_err(|_| complete_knn_cert_invalid_error())?,
            );
        }
        out.push(FrontierNode {
            pivot_index: usize::try_from(parse_u64(&row[0])?)
                .map_err(|_| complete_knn_cert_invalid_error())?,
            pivot: decode_f64_vec(&row[1])?,
            radius_sq: u64_to_f64(parse_u64(&row[2])?)?,
            left_hash: parse_fixed32(&row[3])?,
            right_hash: parse_fixed32(&row[4])?,
            subtree_leaf_indices,
            auth: decode_auth(&row[6])?,
        });
    }
    Ok(out)
}

fn encode_excluded(enc: &mut Encoder, rows: &[ExcludedLeaf]) -> Result<(), MnemeError> {
    enc.begin_array(rows.len() as u64)?;
    for row in rows {
        enc.begin_array(3)?;
        enc.encode_unsigned(
            u64::try_from(row.index).map_err(|_| complete_knn_cert_invalid_error())?,
        )?;
        encode_f64_vec(enc, &row.point)?;
        encode_auth(enc, &row.auth)?;
    }
    Ok(())
}

fn decode_excluded(value: &CborValue) -> Result<Vec<ExcludedLeaf>, MnemeError> {
    let arr = value.as_array().ok_or(complete_knn_cert_invalid_error())?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let row = item.as_array().ok_or(complete_knn_cert_invalid_error())?;
        if row.len() != 3 {
            return Err(complete_knn_cert_invalid_error());
        }
        out.push(ExcludedLeaf {
            index: usize::try_from(parse_u64(&row[0])?)
                .map_err(|_| complete_knn_cert_invalid_error())?,
            point: decode_f64_vec(&row[1])?,
            auth: decode_auth(&row[2])?,
        });
    }
    Ok(out)
}

fn encode_auth(enc: &mut Encoder, auth: &AuthNodeProof) -> Result<(), MnemeError> {
    enc.begin_array(6)?;
    enc.begin_array(auth.path.len() as u64)?;
    for step in &auth.path {
        enc.begin_array(4)?;
        encode_f64_vec(enc, &step.pivot)?;
        enc.encode_unsigned(f64_to_u64(step.radius_sq)?)?;
        enc.encode_bytes(&step.sibling_hash)?;
        enc.encode_bool(step.is_left_child)?;
    }
    match auth.leaf_index {
        Some(idx) => {
            enc.encode_unsigned(u64::try_from(idx).map_err(|_| complete_knn_cert_invalid_error())?)?
        }
        None => enc.encode_null()?,
    }
    encode_f64_vec(enc, &auth.pivot)?;
    match auth.radius_sq {
        Some(r) => enc.encode_unsigned(f64_to_u64(r)?)?,
        None => enc.encode_null()?,
    }
    enc.encode_bytes(&auth.left_hash)?;
    enc.encode_bytes(&auth.right_hash)?;
    Ok(())
}

fn decode_auth(value: &CborValue) -> Result<AuthNodeProof, MnemeError> {
    let row = value.as_array().ok_or(complete_knn_cert_invalid_error())?;
    if row.len() != 6 {
        return Err(complete_knn_cert_invalid_error());
    }
    let path_arr = row[0].as_array().ok_or(complete_knn_cert_invalid_error())?;
    let mut path = Vec::with_capacity(path_arr.len());
    for item in path_arr {
        let step = item.as_array().ok_or(complete_knn_cert_invalid_error())?;
        if step.len() != 4 {
            return Err(complete_knn_cert_invalid_error());
        }
        path.push(AuthPathStep {
            pivot: decode_f64_vec(&step[0])?,
            radius_sq: u64_to_f64(parse_u64(&step[1])?)?,
            sibling_hash: parse_fixed32(&step[2])?,
            is_left_child: match &step[3] {
                CborValue::Bool(v) => *v,
                _ => return Err(complete_knn_cert_invalid_error()),
            },
        });
    }
    let leaf_index = match &row[1] {
        CborValue::Null => None,
        other => Some(
            usize::try_from(parse_u64(other)?).map_err(|_| complete_knn_cert_invalid_error())?,
        ),
    };
    let radius_sq = match &row[3] {
        CborValue::Null => None,
        other => Some(u64_to_f64(parse_u64(other)?)?),
    };
    Ok(AuthNodeProof {
        path,
        leaf_index,
        pivot: decode_f64_vec(&row[2])?,
        radius_sq,
        left_hash: parse_fixed32(&row[4])?,
        right_hash: parse_fixed32(&row[5])?,
    })
}

fn encode_f64_vec(enc: &mut Encoder, values: &[f64]) -> Result<(), MnemeError> {
    enc.begin_array(values.len() as u64)?;
    for v in values {
        enc.encode_unsigned(f64_to_u64(*v)?)?;
    }
    Ok(())
}

fn decode_f64_vec(value: &CborValue) -> Result<Vec<f64>, MnemeError> {
    let arr = value.as_array().ok_or(complete_knn_cert_invalid_error())?;
    arr.iter().map(|v| u64_to_f64(parse_u64(v)?)).collect()
}

fn f64_to_u64(v: f64) -> Result<u64, MnemeError> {
    if !v.is_finite() {
        return Err(complete_knn_cert_invalid_error());
    }
    Ok(v.to_bits())
}

fn u64_to_f64(bits: u64) -> Result<f64, MnemeError> {
    let v = f64::from_bits(bits);
    if !v.is_finite() {
        return Err(complete_knn_cert_invalid_error());
    }
    Ok(v)
}

fn parse_u64(value: &CborValue) -> Result<u64, MnemeError> {
    value.as_u64().ok_or(complete_knn_cert_invalid_error())
}

fn parse_fixed32(value: &CborValue) -> Result<[u8; 32], MnemeError> {
    let b = value.as_bytes().ok_or(complete_knn_cert_invalid_error())?;
    b.try_into().map_err(|_| complete_knn_cert_invalid_error())
}

#[cfg(test)]
mod ttrp_constant_size_tests {
    //! TTRP-1: the constant-size attachment carries only a BLAKE3 hash of the proof
    //! plus the HNSW Merkle root; the full proof travels out-of-band and is bound
    //! back at verify time. Exercises the `constant_size = true` path end to end.
    use super::*;
    use crate::complete_knn::{AuthenticatedBallTree, prove_complete_knn};

    fn real_proof() -> (CompleteKnnProof, [u8; 32], Vec<f64>, u32) {
        let tree = AuthenticatedBallTree::from_points(vec![
            vec![0.0, 0.0],
            vec![1.0, 0.0],
            vec![3.0, 1.0],
            vec![7.0, 2.0],
        ]);
        let query = vec![0.0, 0.0];
        let k = 2usize;
        let proof = prove_complete_knn(&tree, &query, k).expect("prove");
        (proof, tree.commitment(), query, k as u32)
    }

    fn constant_size_att(
        proof: &CompleteKnnProof,
        commitment: [u8; 32],
        query: Vec<f64>,
        k: u32,
    ) -> CompleteKnnCertAttachment {
        CompleteKnnCertAttachment {
            commitment,
            query,
            k,
            // body emptied — only the hash binds the out-of-band proof.
            proof: CompleteKnnProof {
                total_points: proof.total_points,
                returned: Vec::new(),
                frontier: Vec::new(),
                excluded: Vec::new(),
            },
            beacon: None,
            constant_proof_hash: Some(hash_proof(proof).expect("hash")),
            merkle_hnsw_root: Some(commitment),
            constant_size: true,
        }
    }

    #[test]
    fn constant_size_wire_roundtrips_and_verifies_with_out_of_band_proof() {
        let (proof, commitment, query, k) = real_proof();
        let att = constant_size_att(&proof, commitment, query, k);
        let wire = encode_complete_knn_attachment(&att).expect("encode");
        let decoded = decode_complete_knn_attachment(&wire).expect("decode");
        assert!(decoded.constant_size);
        assert_eq!(decoded.constant_proof_hash, att.constant_proof_hash);
        assert_eq!(decoded.merkle_hnsw_root, Some(commitment));
        // A constant-size cert must fail closed without the out-of-band proof…
        assert!(decoded.verify_offline().is_err());
        // …and verify once the matching proof is supplied.
        decoded
            .verify_offline_with_proof(&proof)
            .expect("verify with carried proof");
    }

    #[test]
    fn constant_size_rejects_proof_whose_hash_does_not_match() {
        let (proof, commitment, query, k) = real_proof();
        let att = constant_size_att(&proof, commitment, query, k);
        // A different proof → hash mismatch → fail closed (ObjectTampered).
        let other_tree = AuthenticatedBallTree::from_points(vec![
            vec![9.0, 9.0],
            vec![1.0, 2.0],
            vec![4.0, 4.0],
        ]);
        let other = prove_complete_knn(&other_tree, &[9.0, 9.0], 1).expect("prove other");
        assert!(att.verify_offline_with_proof(&other).is_err());
    }

    #[test]
    fn constant_size_rejects_zero_merkle_root() {
        let (proof, commitment, query, k) = real_proof();
        let mut att = constant_size_att(&proof, commitment, query, k);
        att.merkle_hnsw_root = Some([0u8; 32]);
        assert!(att.verify_offline_with_proof(&proof).is_err());
    }
}
