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

/// Offline-verifiable complete top-k payload (receipt field 8 inner body).
#[derive(Clone, Debug, PartialEq)]
pub struct CompleteKnnCertAttachment {
    pub commitment: [u8; 32],
    pub query: Vec<f64>,
    pub k: u32,
    pub proof: CompleteKnnProof,
    pub beacon: Option<BeaconSeed>,
}

impl CompleteKnnCertAttachment {
    pub fn verify_offline(&self) -> Result<(), MnemeError> {
        verify_complete_knn(
            &self.commitment,
            &self.query,
            usize::try_from(self.k).map_err(|_| MnemeError::CertificateInvalid)?,
            &self.proof,
        )
    }
}

pub fn encode_complete_knn_attachment(
    att: &CompleteKnnCertAttachment,
) -> Result<Vec<u8>, MnemeError> {
    let mut enc = Encoder::new();
    let mut n = 4u64;
    if att.beacon.is_some() {
        n += 2;
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
    if let Some(beacon) = &att.beacon {
        enc.encode_unsigned(F_BEACON_ROUND)?;
        enc.encode_unsigned(beacon.round)?;
        enc.encode_unsigned(F_BEACON_SEED)?;
        enc.encode_bytes(&beacon.seed)?;
    }
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
    for (key, value) in map {
        let field = key.as_u64().ok_or(MnemeError::CertificateInvalid)?;
        match field {
            F_COMMITMENT => commitment = Some(parse_fixed32(&value)?),
            F_QUERY => query = Some(decode_f64_vec(&value)?),
            F_K => {
                k = Some(
                    u32::try_from(parse_u64(&value)?)
                        .map_err(|_| MnemeError::CertificateInvalid)?,
                );
            }
            F_PROOF => proof = Some(decode_proof(&value)?),
            F_BEACON_ROUND => beacon_round = Some(parse_u64(&value)?),
            F_BEACON_SEED => beacon_seed = Some(parse_fixed32(&value)?),
            _ => return Err(MnemeError::CertificateInvalid),
        }
    }
    let beacon = match (beacon_round, beacon_seed) {
        (Some(round), Some(seed)) => Some(BeaconSeed { round, seed }),
        (None, None) => None,
        _ => return Err(MnemeError::CertificateInvalid),
    };
    Ok(CompleteKnnCertAttachment {
        commitment: commitment.ok_or(MnemeError::CertificateInvalid)?,
        query: query.ok_or(MnemeError::CertificateInvalid)?,
        k: k.ok_or(MnemeError::CertificateInvalid)?,
        proof: proof.ok_or(MnemeError::CertificateInvalid)?,
        beacon,
    })
}

fn encode_proof(enc: &mut Encoder, proof: &CompleteKnnProof) -> Result<(), MnemeError> {
    let mut inner = Encoder::new();
    inner.begin_map(4)?;
    inner.encode_unsigned(1)?;
    inner.encode_unsigned(
        u64::try_from(proof.total_points).map_err(|_| MnemeError::CertificateInvalid)?,
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
    let bytes = value.as_bytes().ok_or(MnemeError::CertificateInvalid)?;
    let mut dec = Decoder::new(bytes);
    let map = dec.decode_map()?;
    let mut total_points = None;
    let mut returned = None;
    let mut frontier = None;
    let mut excluded = None;
    for (key, value) in map {
        match key.as_u64().ok_or(MnemeError::CertificateInvalid)? {
            1 => {
                total_points = Some(
                    usize::try_from(parse_u64(&value)?)
                        .map_err(|_| MnemeError::CertificateInvalid)?,
                );
            }
            2 => returned = Some(decode_returned(&value)?),
            3 => frontier = Some(decode_frontier(&value)?),
            4 => excluded = Some(decode_excluded(&value)?),
            _ => return Err(MnemeError::CertificateInvalid),
        }
    }
    Ok(CompleteKnnProof {
        total_points: total_points.ok_or(MnemeError::CertificateInvalid)?,
        returned: returned.ok_or(MnemeError::CertificateInvalid)?,
        frontier: frontier.ok_or(MnemeError::CertificateInvalid)?,
        excluded: excluded.ok_or(MnemeError::CertificateInvalid)?,
    })
}

fn encode_returned(enc: &mut Encoder, rows: &[ReturnedPoint]) -> Result<(), MnemeError> {
    enc.begin_array(rows.len() as u64)?;
    for row in rows {
        enc.begin_array(4)?;
        enc.encode_unsigned(u64::try_from(row.index).map_err(|_| MnemeError::CertificateInvalid)?)?;
        encode_f64_vec(enc, &row.point)?;
        enc.encode_unsigned(f64_to_u64(row.distance_sq)?)?;
        encode_auth(enc, &row.auth)?;
    }
    Ok(())
}

fn decode_returned(value: &CborValue) -> Result<Vec<ReturnedPoint>, MnemeError> {
    let arr = value.as_array().ok_or(MnemeError::CertificateInvalid)?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let row = item.as_array().ok_or(MnemeError::CertificateInvalid)?;
        if row.len() != 4 {
            return Err(MnemeError::CertificateInvalid);
        }
        out.push(ReturnedPoint {
            index: usize::try_from(parse_u64(&row[0])?)
                .map_err(|_| MnemeError::CertificateInvalid)?,
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
            u64::try_from(row.pivot_index).map_err(|_| MnemeError::CertificateInvalid)?,
        )?;
        encode_f64_vec(enc, &row.pivot)?;
        enc.encode_unsigned(f64_to_u64(row.radius_sq)?)?;
        enc.encode_bytes(&row.left_hash)?;
        enc.encode_bytes(&row.right_hash)?;
        enc.begin_array(row.subtree_leaf_indices.len() as u64)?;
        for idx in &row.subtree_leaf_indices {
            enc.encode_unsigned(u64::try_from(*idx).map_err(|_| MnemeError::CertificateInvalid)?)?;
        }
        encode_auth(enc, &row.auth)?;
    }
    Ok(())
}

fn decode_frontier(value: &CborValue) -> Result<Vec<FrontierNode>, MnemeError> {
    let arr = value.as_array().ok_or(MnemeError::CertificateInvalid)?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let row = item.as_array().ok_or(MnemeError::CertificateInvalid)?;
        if row.len() != 7 {
            return Err(MnemeError::CertificateInvalid);
        }
        let indices_arr = row[5].as_array().ok_or(MnemeError::CertificateInvalid)?;
        let mut subtree_leaf_indices = Vec::with_capacity(indices_arr.len());
        for v in indices_arr {
            subtree_leaf_indices
                .push(usize::try_from(parse_u64(v)?).map_err(|_| MnemeError::CertificateInvalid)?);
        }
        out.push(FrontierNode {
            pivot_index: usize::try_from(parse_u64(&row[0])?)
                .map_err(|_| MnemeError::CertificateInvalid)?,
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
        enc.encode_unsigned(u64::try_from(row.index).map_err(|_| MnemeError::CertificateInvalid)?)?;
        encode_f64_vec(enc, &row.point)?;
        encode_auth(enc, &row.auth)?;
    }
    Ok(())
}

fn decode_excluded(value: &CborValue) -> Result<Vec<ExcludedLeaf>, MnemeError> {
    let arr = value.as_array().ok_or(MnemeError::CertificateInvalid)?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let row = item.as_array().ok_or(MnemeError::CertificateInvalid)?;
        if row.len() != 3 {
            return Err(MnemeError::CertificateInvalid);
        }
        out.push(ExcludedLeaf {
            index: usize::try_from(parse_u64(&row[0])?)
                .map_err(|_| MnemeError::CertificateInvalid)?,
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
            enc.encode_unsigned(u64::try_from(idx).map_err(|_| MnemeError::CertificateInvalid)?)?
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
    let row = value.as_array().ok_or(MnemeError::CertificateInvalid)?;
    if row.len() != 6 {
        return Err(MnemeError::CertificateInvalid);
    }
    let path_arr = row[0].as_array().ok_or(MnemeError::CertificateInvalid)?;
    let mut path = Vec::with_capacity(path_arr.len());
    for item in path_arr {
        let step = item.as_array().ok_or(MnemeError::CertificateInvalid)?;
        if step.len() != 4 {
            return Err(MnemeError::CertificateInvalid);
        }
        path.push(AuthPathStep {
            pivot: decode_f64_vec(&step[0])?,
            radius_sq: u64_to_f64(parse_u64(&step[1])?)?,
            sibling_hash: parse_fixed32(&step[2])?,
            is_left_child: match &step[3] {
                CborValue::Bool(v) => *v,
                _ => return Err(MnemeError::CertificateInvalid),
            },
        });
    }
    let leaf_index = match &row[1] {
        CborValue::Null => None,
        other => {
            Some(usize::try_from(parse_u64(other)?).map_err(|_| MnemeError::CertificateInvalid)?)
        }
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
    let arr = value.as_array().ok_or(MnemeError::CertificateInvalid)?;
    arr.iter().map(|v| u64_to_f64(parse_u64(v)?)).collect()
}

fn f64_to_u64(v: f64) -> Result<u64, MnemeError> {
    if !v.is_finite() {
        return Err(MnemeError::CertificateInvalid);
    }
    Ok(v.to_bits())
}

fn u64_to_f64(bits: u64) -> Result<f64, MnemeError> {
    let v = f64::from_bits(bits);
    if !v.is_finite() {
        return Err(MnemeError::CertificateInvalid);
    }
    Ok(v)
}

fn parse_u64(value: &CborValue) -> Result<u64, MnemeError> {
    value.as_u64().ok_or(MnemeError::CertificateInvalid)
}

fn parse_fixed32(value: &CborValue) -> Result<[u8; 32], MnemeError> {
    let b = value.as_bytes().ok_or(MnemeError::CertificateInvalid)?;
    b.try_into().map_err(|_| MnemeError::CertificateInvalid)
}
