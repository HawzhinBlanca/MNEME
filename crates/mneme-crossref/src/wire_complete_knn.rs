//! Receipt field 8 + complete-kNN offline verification (reference path, CR-6).
//!
//! Independent reimplementation mirroring `mneme-index::complete_knn_cert` decode and
//! `complete_knn::verify`. No `mneme-*` deps.

use crate::dcbor::{CborValue, Decoder};
use crate::error::CrossrefError;
use blake3::Hasher;
use std::collections::BTreeSet;

const KNN_DOMAIN: &[u8] = b"MNEME-cknn-v1\x00";
const LEAF_TAG: u8 = 0x20;
const INTERNAL_TAG: u8 = 0x21;

const F_COMMITMENT: u64 = 1;
const F_QUERY: u64 = 2;
const F_K: u64 = 3;
const F_PROOF: u64 = 4;

pub const COMPLETE_KNN_HONESTY: &str = "complete-kNN proves completeness of retrieval (no closer neighbor hidden), not semantic truth; authenticated ≠ true";

#[derive(Clone, Debug, PartialEq)]
pub struct CompleteKnnReceipt {
    pub commitment: [u8; 32],
    pub query: Vec<f64>,
    pub k: u32,
    pub proof_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
struct CompleteKnnProof {
    total_points: usize,
    returned: Vec<ReturnedPoint>,
    frontier: Vec<FrontierNode>,
    excluded: Vec<ExcludedLeaf>,
}

#[derive(Clone, Debug, PartialEq)]
struct ReturnedPoint {
    index: usize,
    point: Vec<f64>,
    distance_sq: f64,
    auth: AuthNodeProof,
}

#[derive(Clone, Debug, PartialEq)]
struct ExcludedLeaf {
    index: usize,
    point: Vec<f64>,
    auth: AuthNodeProof,
}

#[derive(Clone, Debug, PartialEq)]
struct FrontierNode {
    pivot_index: usize,
    pivot: Vec<f64>,
    radius_sq: f64,
    left_hash: [u8; 32],
    right_hash: [u8; 32],
    subtree_leaf_indices: Vec<usize>,
    auth: AuthNodeProof,
}

#[derive(Clone, Debug, PartialEq)]
struct AuthPathStep {
    pivot: Vec<f64>,
    radius_sq: f64,
    sibling_hash: [u8; 32],
    is_left_child: bool,
}

#[derive(Clone, Debug, PartialEq)]
struct AuthNodeProof {
    path: Vec<AuthPathStep>,
    leaf_index: Option<usize>,
    pivot: Vec<f64>,
    radius_sq: Option<f64>,
    left_hash: [u8; 32],
    right_hash: [u8; 32],
}

pub fn decode_complete_knn_receipt_value(
    value: &CborValue,
) -> Result<CompleteKnnReceipt, CrossrefError> {
    let map = value.as_map().ok_or(CrossrefError::SchemaDrift)?;
    let mut commitment = None;
    let mut query = None;
    let mut k = None;
    let mut proof_bytes = None;
    for (key, value) in map {
        match field_key(key)? {
            1 => commitment = Some(parse_fixed32(value)?),
            2 => query = Some(decode_f64_coords(value)?),
            3 => {
                k = Some(
                    u32::try_from(parse_u64(value)?)
                        .map_err(|_| CrossrefError::CertificateInvalid)?,
                );
            }
            4 => proof_bytes = Some(parse_bytes(value)?.to_vec()),
            _ => return Err(CrossrefError::SchemaDrift),
        }
    }
    Ok(CompleteKnnReceipt {
        commitment: commitment.ok_or(CrossrefError::CertificateInvalid)?,
        query: query.ok_or(CrossrefError::CertificateInvalid)?,
        k: k.ok_or(CrossrefError::CertificateInvalid)?,
        proof_bytes: proof_bytes.ok_or(CrossrefError::CertificateInvalid)?,
    })
}

pub fn decode_complete_knn_receipt(bytes: &[u8]) -> Result<CompleteKnnReceipt, CrossrefError> {
    let mut dec = Decoder::new(bytes);
    let value = dec.decode_any()?;
    dec.ensure_consumed()?;
    decode_complete_knn_receipt_value(&value)
}

pub fn verify_complete_knn_receipt(raw: &CompleteKnnReceipt) -> Result<(), CrossrefError> {
    let att = decode_complete_knn_attachment(&raw.proof_bytes)?;
    if att.commitment != raw.commitment || att.query != raw.query || att.k != raw.k {
        return Err(CrossrefError::CertificateInvalid);
    }
    verify_complete_knn(
        &att.commitment,
        &att.query,
        usize::try_from(att.k).map_err(|_| CrossrefError::CertificateInvalid)?,
        &att.proof,
    )
}

struct DecodedAttachment {
    commitment: [u8; 32],
    query: Vec<f64>,
    k: u32,
    proof: CompleteKnnProof,
}

fn decode_complete_knn_attachment(bytes: &[u8]) -> Result<DecodedAttachment, CrossrefError> {
    let mut dec = Decoder::new(bytes);
    let map = dec.decode_map()?;
    dec.ensure_consumed()?;
    let mut commitment = None;
    let mut query = None;
    let mut k = None;
    let mut proof = None;
    for (key, value) in map {
        match field_key(&key)? {
            F_COMMITMENT => commitment = Some(parse_fixed32(&value)?),
            F_QUERY => query = Some(decode_f64_coords(&value)?),
            F_K => {
                k = Some(
                    u32::try_from(parse_u64(&value)?)
                        .map_err(|_| CrossrefError::CertificateInvalid)?,
                );
            }
            F_PROOF => proof = Some(decode_proof(parse_bytes(&value)?)?),
            5 | 6 => {}
            _ => return Err(CrossrefError::SchemaDrift),
        }
    }
    Ok(DecodedAttachment {
        commitment: commitment.ok_or(CrossrefError::CertificateInvalid)?,
        query: query.ok_or(CrossrefError::CertificateInvalid)?,
        k: k.ok_or(CrossrefError::CertificateInvalid)?,
        proof: proof.ok_or(CrossrefError::CertificateInvalid)?,
    })
}

fn verify_complete_knn(
    commitment: &[u8; 32],
    query: &[f64],
    k: usize,
    proof: &CompleteKnnProof,
) -> Result<(), CrossrefError> {
    if proof.returned.len() != k {
        return Err(CrossrefError::RetrievalDominanceFailed);
    }
    let mut tau_sq = 0.0_f64;
    for rp in &proof.returned {
        verify_leaf_proof(commitment, rp.index, &rp.point, &rp.auth)?;
        let d = squared_euclidean(query, &rp.point);
        if (d - rp.distance_sq).abs() > 1e-9 {
            return Err(CrossrefError::RetrievalDominanceFailed);
        }
        tau_sq = tau_sq.max(d);
    }
    for node in &proof.frontier {
        verify_internal_proof(
            commitment,
            &node.pivot,
            node.radius_sq,
            &node.left_hash,
            &node.right_hash,
            &node.auth,
        )?;
        let d_qp = squared_euclidean(query, &node.pivot).sqrt();
        let radius = node.radius_sq.sqrt();
        let lower = (d_qp - radius).max(0.0);
        if lower * lower <= tau_sq {
            return Err(CrossrefError::PathInvalid);
        }
    }
    for ex in &proof.excluded {
        verify_leaf_proof(commitment, ex.index, &ex.point, &ex.auth)?;
        if squared_euclidean(query, &ex.point) < tau_sq {
            return Err(CrossrefError::PathInvalid);
        }
    }
    verify_antichain_cover(proof)
}

fn verify_antichain_cover(proof: &CompleteKnnProof) -> Result<(), CrossrefError> {
    let mut covered = BTreeSet::new();
    for rp in &proof.returned {
        if !covered.insert(rp.index) {
            return Err(CrossrefError::RetrievalDominanceFailed);
        }
    }
    for f in &proof.frontier {
        for &idx in &f.subtree_leaf_indices {
            if covered.contains(&idx) {
                return Err(CrossrefError::RetrievalDominanceFailed);
            }
            covered.insert(idx);
        }
    }
    for ex in &proof.excluded {
        if covered.contains(&ex.index) {
            return Err(CrossrefError::RetrievalDominanceFailed);
        }
        covered.insert(ex.index);
    }
    if covered.len() != proof.total_points {
        return Err(CrossrefError::RetrievalDominanceFailed);
    }
    Ok(())
}

fn verify_leaf_proof(
    commitment: &[u8; 32],
    index: usize,
    point: &[f64],
    proof: &AuthNodeProof,
) -> Result<(), CrossrefError> {
    if proof.leaf_index != Some(index) {
        return Err(CrossrefError::PathInvalid);
    }
    let mut current = hash_auth_leaf(index, point);
    for step in &proof.path {
        current = parent_hash(step, &current);
    }
    if current != *commitment {
        return Err(CrossrefError::PathInvalid);
    }
    Ok(())
}

fn verify_internal_proof(
    commitment: &[u8; 32],
    pivot: &[f64],
    radius_sq: f64,
    left_hash: &[u8; 32],
    right_hash: &[u8; 32],
    proof: &AuthNodeProof,
) -> Result<(), CrossrefError> {
    if proof.radius_sq != Some(radius_sq) {
        return Err(CrossrefError::PathInvalid);
    }
    let mut current = hash_auth_internal(pivot, radius_sq, left_hash, right_hash);
    for step in &proof.path {
        current = parent_hash(step, &current);
    }
    if current != *commitment {
        return Err(CrossrefError::PathInvalid);
    }
    Ok(())
}

fn parent_hash(step: &AuthPathStep, child_hash: &[u8; 32]) -> [u8; 32] {
    if step.is_left_child {
        hash_auth_internal(&step.pivot, step.radius_sq, child_hash, &step.sibling_hash)
    } else {
        hash_auth_internal(&step.pivot, step.radius_sq, &step.sibling_hash, child_hash)
    }
}

fn hash_knn_domain(payload: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(KNN_DOMAIN);
    h.update(payload);
    *h.finalize().as_bytes()
}

fn hash_auth_leaf(index: usize, point: &[f64]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(1 + 8 + point.len() * 8);
    payload.push(LEAF_TAG);
    payload.extend_from_slice(&(index as u64).to_be_bytes());
    for &c in point {
        payload.extend_from_slice(&c.to_bits().to_be_bytes());
    }
    hash_knn_domain(&payload)
}

fn hash_auth_internal(
    pivot: &[f64],
    radius_sq: f64,
    left: &[u8; 32],
    right: &[u8; 32],
) -> [u8; 32] {
    let mut payload = Vec::with_capacity(1 + pivot.len() * 8 + 8 + 64);
    payload.push(INTERNAL_TAG);
    for &c in pivot {
        payload.extend_from_slice(&c.to_bits().to_be_bytes());
    }
    payload.extend_from_slice(&radius_sq.to_bits().to_be_bytes());
    payload.extend_from_slice(left);
    payload.extend_from_slice(right);
    hash_knn_domain(&payload)
}

fn squared_euclidean(a: &[f64], b: &[f64]) -> f64 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| {
            let d = x - y;
            d * d
        })
        .sum()
}

fn decode_proof(bytes: &[u8]) -> Result<CompleteKnnProof, CrossrefError> {
    let mut dec = Decoder::new(bytes);
    let map = dec.decode_map()?;
    dec.ensure_consumed()?;
    let mut total_points = None;
    let mut returned = None;
    let mut frontier = None;
    let mut excluded = None;
    for (key, value) in map {
        match field_key(&key)? {
            1 => {
                total_points = Some(
                    usize::try_from(parse_u64(&value)?)
                        .map_err(|_| CrossrefError::CertificateInvalid)?,
                );
            }
            2 => returned = Some(decode_returned(&value)?),
            3 => frontier = Some(decode_frontier(&value)?),
            4 => excluded = Some(decode_excluded(&value)?),
            _ => return Err(CrossrefError::SchemaDrift),
        }
    }
    Ok(CompleteKnnProof {
        total_points: total_points.ok_or(CrossrefError::CertificateInvalid)?,
        returned: returned.ok_or(CrossrefError::CertificateInvalid)?,
        frontier: frontier.ok_or(CrossrefError::CertificateInvalid)?,
        excluded: excluded.ok_or(CrossrefError::CertificateInvalid)?,
    })
}

fn decode_returned(value: &CborValue) -> Result<Vec<ReturnedPoint>, CrossrefError> {
    let arr = value.as_array().ok_or(CrossrefError::SchemaDrift)?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let row = item.as_array().ok_or(CrossrefError::SchemaDrift)?;
        if row.len() != 4 {
            return Err(CrossrefError::SchemaDrift);
        }
        out.push(ReturnedPoint {
            index: usize::try_from(parse_u64(&row[0])?)
                .map_err(|_| CrossrefError::CertificateInvalid)?,
            point: decode_f64_coords(&row[1])?,
            distance_sq: u64_to_f64(parse_u64(&row[2])?)?,
            auth: decode_auth(&row[3])?,
        });
    }
    Ok(out)
}

fn decode_frontier(value: &CborValue) -> Result<Vec<FrontierNode>, CrossrefError> {
    let arr = value.as_array().ok_or(CrossrefError::SchemaDrift)?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let row = item.as_array().ok_or(CrossrefError::SchemaDrift)?;
        if row.len() != 7 {
            return Err(CrossrefError::SchemaDrift);
        }
        let indices_arr = row[5].as_array().ok_or(CrossrefError::SchemaDrift)?;
        let mut subtree_leaf_indices = Vec::with_capacity(indices_arr.len());
        for v in indices_arr {
            subtree_leaf_indices.push(
                usize::try_from(parse_u64(v)?).map_err(|_| CrossrefError::CertificateInvalid)?,
            );
        }
        out.push(FrontierNode {
            pivot_index: usize::try_from(parse_u64(&row[0])?)
                .map_err(|_| CrossrefError::CertificateInvalid)?,
            pivot: decode_f64_coords(&row[1])?,
            radius_sq: u64_to_f64(parse_u64(&row[2])?)?,
            left_hash: parse_fixed32(&row[3])?,
            right_hash: parse_fixed32(&row[4])?,
            subtree_leaf_indices,
            auth: decode_auth(&row[6])?,
        });
    }
    Ok(out)
}

fn decode_excluded(value: &CborValue) -> Result<Vec<ExcludedLeaf>, CrossrefError> {
    let arr = value.as_array().ok_or(CrossrefError::SchemaDrift)?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let row = item.as_array().ok_or(CrossrefError::SchemaDrift)?;
        if row.len() != 3 {
            return Err(CrossrefError::SchemaDrift);
        }
        out.push(ExcludedLeaf {
            index: usize::try_from(parse_u64(&row[0])?)
                .map_err(|_| CrossrefError::CertificateInvalid)?,
            point: decode_f64_coords(&row[1])?,
            auth: decode_auth(&row[2])?,
        });
    }
    Ok(out)
}

fn decode_auth(value: &CborValue) -> Result<AuthNodeProof, CrossrefError> {
    let row = value.as_array().ok_or(CrossrefError::SchemaDrift)?;
    if row.len() != 6 {
        return Err(CrossrefError::SchemaDrift);
    }
    let path_arr = row[0].as_array().ok_or(CrossrefError::SchemaDrift)?;
    let mut path = Vec::with_capacity(path_arr.len());
    for item in path_arr {
        let step = item.as_array().ok_or(CrossrefError::SchemaDrift)?;
        if step.len() != 4 {
            return Err(CrossrefError::SchemaDrift);
        }
        path.push(AuthPathStep {
            pivot: decode_f64_coords(&step[0])?,
            radius_sq: u64_to_f64(parse_u64(&step[1])?)?,
            sibling_hash: parse_fixed32(&step[2])?,
            is_left_child: match &step[3] {
                CborValue::Bool(v) => *v,
                _ => return Err(CrossrefError::SchemaDrift),
            },
        });
    }
    let leaf_index = match &row[1] {
        CborValue::Null => None,
        other => Some(
            usize::try_from(parse_u64(other)?).map_err(|_| CrossrefError::CertificateInvalid)?,
        ),
    };
    let radius_sq = match &row[3] {
        CborValue::Null => None,
        other => Some(u64_to_f64(parse_u64(other)?)?),
    };
    Ok(AuthNodeProof {
        path,
        leaf_index,
        pivot: decode_f64_coords(&row[2])?,
        radius_sq,
        left_hash: parse_fixed32(&row[4])?,
        right_hash: parse_fixed32(&row[5])?,
    })
}

fn decode_f64_coords(value: &CborValue) -> Result<Vec<f64>, CrossrefError> {
    let arr = value.as_array().ok_or(CrossrefError::SchemaDrift)?;
    arr.iter().map(|v| u64_to_f64(parse_u64(v)?)).collect()
}

fn u64_to_f64(bits: u64) -> Result<f64, CrossrefError> {
    let v = f64::from_bits(bits);
    if v.is_finite() {
        Ok(v)
    } else {
        Err(CrossrefError::CertificateInvalid)
    }
}

fn field_key(key: &CborValue) -> Result<u64, CrossrefError> {
    key.as_u64().ok_or(CrossrefError::SchemaDrift)
}

fn parse_u64(value: &CborValue) -> Result<u64, CrossrefError> {
    value.as_u64().ok_or(CrossrefError::SchemaDrift)
}

fn parse_bytes(value: &CborValue) -> Result<&[u8], CrossrefError> {
    value.as_bytes().ok_or(CrossrefError::SchemaDrift)
}

fn parse_fixed32(value: &CborValue) -> Result<[u8; 32], CrossrefError> {
    let b = value.as_bytes().ok_or(CrossrefError::SchemaDrift)?;
    b.try_into().map_err(|_| CrossrefError::SchemaDrift)
}
