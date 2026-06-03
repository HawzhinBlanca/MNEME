//! Cognition Certificate v1 wire decode + offline verification (reference path).
//!
//! Independent reimplementation mirroring mneme-index `cognition_cert.rs`. Decodes
//! the outer cert map (fields 1-5) and inner semantic receipt (fields 1-7), then
//! runs fail-closed verification: Ed25519 root signature, receipt↔root binding, and
//! ADS replay + zkANN dominance. No `mneme-*` deps.

use crate::dcbor::{CborValue, Decoder};
use crate::error::CrossrefError;
use crate::procedure::{CandidateRow, Procedure};
use crate::semantic_commit::{
    RetrievalProofLevel, VerificationObject, ZkannAttachment, verify_semantic_vo_zkann,
};
use crate::wire_root::StoredRoot;

const CERT_VERSION_V1: u16 = 1;
const CERT_VERSION_V2_DRAFT: u16 = 2;

const F_CERT_VERSION: u64 = 1;
const F_LEVEL: u64 = 2;
const F_AS_OF_SEQ: u64 = 3;
const F_STORED_ROOT: u64 = 4;
const F_SEMANTIC_RECEIPT: u64 = 5;
const F_CONTEXT_ATTESTATION: u64 = 6;

const CONTEXT_GATE_DRAFT_STATUS: &str = "unverified_until_phase_ii_gate";

struct SemanticReceipt {
    root_bound: [u8; 32],
    semantic_commit: [u8; 32],
    vo: VerificationObject,
    zkann: Option<ZkannAttachment>,
}

struct CognitionCert {
    version: u16,
    level: RetrievalProofLevel,
    as_of_seq: Option<u64>,
    stored_root: StoredRoot,
    receipt: SemanticReceipt,
    attestation: Option<ContextAttestationDraft>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ContextAttestationDraft {
    status: String,
    context_digest: [u8; 32],
    output_digest: Option<[u8; 32]>,
}

/// Decode + fail-closed verify a Certificate v1 against `operator_pubkey` and `proc`.
pub fn verify_committed_certificate(
    bytes: &[u8],
    operator_pubkey: &[u8; 32],
    proc: &Procedure,
) -> Result<(), CrossrefError> {
    let cert = decode_cert(bytes)?;
    if cert.version != CERT_VERSION_V1 && cert.version != CERT_VERSION_V2_DRAFT {
        return Err(CrossrefError::UnsupportedVersion);
    }
    let root = &cert.stored_root;
    if root.recompute_preimage_hash() != root.preimage_hash {
        return Err(CrossrefError::SigInvalid);
    }
    root.verify_signature(operator_pubkey)?;

    let receipt = &cert.receipt;
    if receipt.root_bound != root.preimage_hash || receipt.semantic_commit != root.semantic_commit {
        return Err(CrossrefError::CertificateInvalid);
    }
    if let Some(seq) = cert.as_of_seq {
        if root.sequence != seq {
            return Err(CrossrefError::CertificateInvalid);
        }
    }
    if let Some(z) = &receipt.zkann {
        if z.level != cert.level {
            return Err(CrossrefError::CertificateInvalid);
        }
    }
    if cert.version == CERT_VERSION_V2_DRAFT {
        let att = cert
            .attestation
            .as_ref()
            .ok_or(CrossrefError::CertificateInvalid)?;
        if att.status != CONTEXT_GATE_DRAFT_STATUS {
            return Err(CrossrefError::CertificateInvalid);
        }
    }

    let committed_leaf_count = receipt.vo.candidates.len();
    verify_semantic_vo_zkann(
        &receipt.vo,
        &receipt.semantic_commit,
        proc,
        receipt.zkann.as_ref(),
        committed_leaf_count,
    )
}

fn decode_cert(bytes: &[u8]) -> Result<CognitionCert, CrossrefError> {
    let mut dec = Decoder::new(bytes);
    let map = dec.decode_map()?;
    dec.ensure_consumed()?;

    let mut version = None;
    let mut level = None;
    let mut as_of_seq = None;
    let mut stored_root = None;
    let mut receipt = None;
    let mut attestation = None;

    for (key, value) in map {
        match field_key(&key)? {
            F_CERT_VERSION => version = Some(parse_u16(&value)?),
            F_LEVEL => level = Some(parse_level(&value)?),
            F_AS_OF_SEQ => as_of_seq = Some(value.as_u64().ok_or(CrossrefError::SchemaDrift)?),
            F_STORED_ROOT => stored_root = Some(StoredRoot::decode(parse_bytes(&value)?)?),
            F_SEMANTIC_RECEIPT => receipt = Some(decode_receipt(parse_bytes(&value)?)?),
            F_CONTEXT_ATTESTATION => {
                attestation = Some(decode_attestation(parse_bytes(&value)?)?);
            }
            _ => return Err(CrossrefError::SchemaDrift),
        }
    }

    Ok(CognitionCert {
        version: version.ok_or(CrossrefError::CertificateInvalid)?,
        level: level.ok_or(CrossrefError::CertificateInvalid)?,
        as_of_seq,
        stored_root: stored_root.ok_or(CrossrefError::CertificateInvalid)?,
        receipt: receipt.ok_or(CrossrefError::CertificateInvalid)?,
        attestation,
    })
}

fn decode_receipt(bytes: &[u8]) -> Result<SemanticReceipt, CrossrefError> {
    let mut dec = Decoder::new(bytes);
    let map = dec.decode_map()?;
    dec.ensure_consumed()?;

    let mut root_bound = None;
    let mut semantic_commit = None;
    let mut procedure_id = None;
    let mut query_commit = None;
    let mut result_ids = None;
    let mut vo_body = None;
    let mut zkann = None;

    for (key, value) in map {
        match field_key(&key)? {
            1 => root_bound = Some(parse_fixed32(&value)?),
            2 => semantic_commit = Some(parse_fixed32(&value)?),
            3 => procedure_id = Some(parse_fixed32(&value)?),
            4 => query_commit = Some(parse_fixed32(&value)?),
            5 => result_ids = Some(decode_id_list(&value)?),
            6 => vo_body = Some(decode_vo_body(&value)?),
            7 => zkann = Some(decode_zkann(&value)?),
            _ => return Err(CrossrefError::SchemaDrift),
        }
    }

    let (nodes, candidates, leaf_indices) = vo_body.ok_or(CrossrefError::CertificateInvalid)?;
    Ok(SemanticReceipt {
        root_bound: root_bound.ok_or(CrossrefError::CertificateInvalid)?,
        semantic_commit: semantic_commit.ok_or(CrossrefError::CertificateInvalid)?,
        vo: VerificationObject {
            nodes,
            candidates,
            leaf_indices,
            procedure_id: procedure_id.ok_or(CrossrefError::CertificateInvalid)?,
            query_commit: query_commit.ok_or(CrossrefError::CertificateInvalid)?,
            result_ids: result_ids.ok_or(CrossrefError::CertificateInvalid)?,
        },
        zkann,
    })
}

type NodeRow = ([u8; 32], Vec<[u8; 32]>);
type VoBody = (Vec<NodeRow>, Vec<CandidateRow>, Vec<usize>);

fn decode_vo_body(value: &CborValue) -> Result<VoBody, CrossrefError> {
    let map = value.as_map().ok_or(CrossrefError::SchemaDrift)?;
    let mut nodes = None;
    let mut candidates = None;
    let mut leaf_indices = None;
    for (k, v) in map {
        match field_key(k)? {
            1 => nodes = Some(decode_nodes(v)?),
            2 => candidates = Some(decode_candidates(v)?),
            3 => leaf_indices = Some(decode_leaf_indices(v)?),
            _ => return Err(CrossrefError::SchemaDrift),
        }
    }
    let nodes = nodes.ok_or(CrossrefError::CertificateInvalid)?;
    let candidates = candidates.ok_or(CrossrefError::CertificateInvalid)?;
    let leaf_indices = leaf_indices.unwrap_or_else(|| (0..nodes.len()).collect());
    if leaf_indices.len() != nodes.len() || leaf_indices.len() != candidates.len() {
        return Err(CrossrefError::CertificateInvalid);
    }
    Ok((nodes, candidates, leaf_indices))
}

fn decode_nodes(value: &CborValue) -> Result<Vec<NodeRow>, CrossrefError> {
    let outer = value.as_array().ok_or(CrossrefError::SchemaDrift)?;
    let mut out = Vec::with_capacity(outer.len());
    for item in outer {
        let pair = item.as_array().ok_or(CrossrefError::SchemaDrift)?;
        if pair.len() != 2 {
            return Err(CrossrefError::SchemaDrift);
        }
        let commit = parse_fixed32(&pair[0])?;
        let path_arr = pair[1].as_array().ok_or(CrossrefError::SchemaDrift)?;
        let path: Result<Vec<_>, _> = path_arr.iter().map(parse_fixed32).collect();
        out.push((commit, path?));
    }
    Ok(out)
}

fn decode_candidates(value: &CborValue) -> Result<Vec<CandidateRow>, CrossrefError> {
    let outer = value.as_array().ok_or(CrossrefError::SchemaDrift)?;
    let mut out = Vec::with_capacity(outer.len());
    for item in outer {
        let row = item.as_array().ok_or(CrossrefError::SchemaDrift)?;
        if row.len() != 3 {
            return Err(CrossrefError::SchemaDrift);
        }
        let id = parse_fixed32(&row[0])?;
        let emb = parse_fixed32(&row[1])?;
        let dist = row[2].as_i64().ok_or(CrossrefError::SchemaDrift)?;
        out.push((id, emb, dist));
    }
    Ok(out)
}

fn decode_leaf_indices(value: &CborValue) -> Result<Vec<usize>, CrossrefError> {
    let arr = value.as_array().ok_or(CrossrefError::SchemaDrift)?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let n = item.as_u64().ok_or(CrossrefError::SchemaDrift)?;
        out.push(usize::try_from(n).map_err(|_| CrossrefError::CertificateInvalid)?);
    }
    Ok(out)
}

fn decode_zkann(value: &CborValue) -> Result<ZkannAttachment, CrossrefError> {
    let map = value.as_map().ok_or(CrossrefError::SchemaDrift)?;
    let mut level = None;
    let mut visited = None;
    for (k, v) in map {
        match field_key(k)? {
            1 => level = Some(parse_level(v)?),
            2 => visited = Some(decode_id_list(v)?),
            _ => return Err(CrossrefError::SchemaDrift),
        }
    }
    Ok(ZkannAttachment {
        level: level.ok_or(CrossrefError::CertificateInvalid)?,
        visited_order: visited.ok_or(CrossrefError::CertificateInvalid)?,
    })
}

fn decode_attestation(bytes: &[u8]) -> Result<ContextAttestationDraft, CrossrefError> {
    let mut dec = Decoder::new(bytes);
    let map = dec.decode_map()?;
    dec.ensure_consumed()?;

    let mut status = None;
    let mut context_digest = None;
    let mut output_digest = None;

    for (k, v) in map {
        match field_key(&k)? {
            1 => status = Some(parse_text(&v)?),
            2 => context_digest = Some(parse_fixed32(&v)?),
            3 => output_digest = Some(parse_fixed32(&v)?),
            _ => return Err(CrossrefError::SchemaDrift),
        }
    }

    Ok(ContextAttestationDraft {
        status: status.ok_or(CrossrefError::CertificateInvalid)?,
        context_digest: context_digest.ok_or(CrossrefError::CertificateInvalid)?,
        output_digest,
    })
}

fn decode_id_list(value: &CborValue) -> Result<Vec<[u8; 32]>, CrossrefError> {
    let arr = value.as_array().ok_or(CrossrefError::SchemaDrift)?;
    arr.iter().map(parse_fixed32).collect()
}

fn parse_level(value: &CborValue) -> Result<RetrievalProofLevel, CrossrefError> {
    match value.as_u64().ok_or(CrossrefError::SchemaDrift)? {
        0 => Ok(RetrievalProofLevel::ExactDominance),
        1 => Ok(RetrievalProofLevel::HnswAuditOnDemand),
        _ => Err(CrossrefError::CertificateInvalid),
    }
}

fn field_key(key: &CborValue) -> Result<u64, CrossrefError> {
    key.as_u64().ok_or(CrossrefError::SchemaDrift)
}

fn parse_u16(value: &CborValue) -> Result<u16, CrossrefError> {
    let n = value.as_u64().ok_or(CrossrefError::SchemaDrift)?;
    u16::try_from(n).map_err(|_| CrossrefError::SchemaDrift)
}

fn parse_bytes(value: &CborValue) -> Result<&[u8], CrossrefError> {
    value.as_bytes().ok_or(CrossrefError::SchemaDrift)
}

fn parse_fixed32(value: &CborValue) -> Result<[u8; 32], CrossrefError> {
    let b = value.as_bytes().ok_or(CrossrefError::SchemaDrift)?;
    b.try_into().map_err(|_| CrossrefError::SchemaDrift)
}

fn parse_text(value: &CborValue) -> Result<String, CrossrefError> {
    value
        .as_text()
        .map(|s| s.to_string())
        .ok_or(CrossrefError::SchemaDrift)
}
