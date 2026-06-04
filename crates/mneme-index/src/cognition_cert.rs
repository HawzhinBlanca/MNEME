//! Cognition Certificate v1 — offline-verifiable bundle (Phase I P1-4).

#[cfg(feature = "context_gate")]
use crate::context_gate::{CONTEXT_GATE_STRICT_STATUS, apply_context_gate_strict};
use crate::receipt::SemanticRecallReceipt;
use crate::verify::verify_semantic_receipt_vo_zkann;
use mneme_core::{
    AsOf, COGNITION_CERT_VERSION, CborValue, DcborDecode, DcborEncode, Decoder, Encoder,
    MnemeError, RetrievalProofLevel, Root, from_bytes_strict, to_bytes_canonical,
};
#[cfg(feature = "context_gate")]
use mneme_core::{
    ContextConsumptionAttestation, Entry, OutputBinding, decode_context_consumption_attestation,
    decode_output_binding,
};
use mneme_core::{ObjectId, Procedure, RootPreimage};
use mneme_crypto::{TrustConfig, public_key_from_bytes, verify_signature_bytes};
use mneme_root::StoredRoot;

type VoNodes = Vec<([u8; 32], Vec<[u8; 32]>)>;
type VoCandidates = Vec<(ObjectId, [u8; 32], i64)>;

const F_CERT_VERSION: u64 = 1;
const F_LEVEL: u64 = 2;
const F_AS_OF_SEQ: u64 = 3;
const F_STORED_ROOT: u64 = 4;
const F_SEMANTIC_RECEIPT: u64 = 5;
#[cfg(feature = "context_gate")]
const F_CONTEXT_ATTESTATION: u64 = 6;

#[cfg(feature = "context_gate")]
const F_CCA: u64 = 7;
#[cfg(feature = "context_gate")]
const F_OUTPUT_BINDING: u64 = 8;
#[cfg(feature = "context_gate")]
const COGNITION_CERT_VERSION_V2_DRAFT: u16 = 2;

#[cfg(feature = "context_gate")]
pub const CONTEXT_GATE_DRAFT_STATUS: &str = "unverified_until_phase_ii_gate";

#[cfg(feature = "context_gate")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContextAttestationDraft {
    /// Digest of the deterministically assembled context (placeholder until enclave binding).
    pub context_digest: [u8; 32],
    /// Optional output digest hook for Phase II step 4 (unverified in this draft).
    pub output_digest: Option<[u8; 32]>,
    /// Honest label carried on-wire so verifiers fail-closed if an attestor claims more.
    pub status: String,
    pub consumption_attestation: Option<ContextConsumptionAttestation>,
    pub output_binding: Option<OutputBinding>,
}

#[cfg(feature = "context_gate")]
impl ContextAttestationDraft {
    pub fn placeholder(context_digest: [u8; 32]) -> Self {
        Self {
            context_digest,
            output_digest: None,
            status: CONTEXT_GATE_DRAFT_STATUS.to_string(),
            consumption_attestation: None,
            output_binding: None,
        }
    }

    pub fn strict(
        attestation: ContextConsumptionAttestation,
        output_binding: Option<OutputBinding>,
    ) -> Self {
        Self {
            context_digest: attestation.context_hash,
            output_digest: output_binding.as_ref().map(|b| b.output_hash),
            status: CONTEXT_GATE_STRICT_STATUS.to_string(),
            consumption_attestation: Some(attestation),
            output_binding,
        }
    }
}

/// Assemble Certificate v1 bytes from a signed head and semantic recall receipt.
pub fn assemble_cognition_certificate_v1(
    stored_root: &StoredRoot,
    receipt: &SemanticRecallReceipt,
    as_of: Option<AsOf>,
) -> Result<Vec<u8>, MnemeError> {
    let wire = CognitionCertWire {
        version: COGNITION_CERT_VERSION,
        level: receipt
            .zkann
            .as_ref()
            .map(|z| z.level)
            .unwrap_or(RetrievalProofLevel::ExactDominance),
        as_of_seq: match as_of {
            Some(AsOf::RootSeq(s)) => Some(s),
            Some(AsOf::ValidTime(_)) => None,
            None => None,
        },
        stored_root: stored_root.clone(),
        receipt: receipt.clone(),
    };
    to_bytes_canonical(&wire)
}

/// Assemble Certificate v2 draft (Phase II seam) behind `context_gate`.
///
/// Carries all v1 fields plus a placeholder context-attestation field that is **not**
/// enclave-backed. The attestation is labeled `CONTEXT_GATE_DRAFT_STATUS` so verifiers can
/// fail-closed until the Phase II gate lands.
#[cfg(feature = "context_gate")]
pub fn assemble_cognition_certificate_v2_draft(
    stored_root: &StoredRoot,
    receipt: &SemanticRecallReceipt,
    as_of: Option<AsOf>,
    attestation: ContextAttestationDraft,
) -> Result<Vec<u8>, MnemeError> {
    let wire = CognitionCertWireV2Draft {
        version: COGNITION_CERT_VERSION_V2_DRAFT,
        level: receipt
            .zkann
            .as_ref()
            .map(|z| z.level)
            .unwrap_or(RetrievalProofLevel::ExactDominance),
        as_of_seq: match as_of {
            Some(AsOf::RootSeq(s)) => Some(s),
            Some(AsOf::ValidTime(_)) => None,
            None => None,
        },
        stored_root: stored_root.clone(),
        receipt: receipt.clone(),
        attestation,
    };
    to_bytes_canonical(&wire)
}

/// Offline fail-closed verification (no store access beyond embedded root + receipt).
pub fn verify_cognition_certificate_v1(
    bytes: &[u8],
    trust: &TrustConfig,
    proc: &Procedure,
) -> Result<Root, MnemeError> {
    let wire: CognitionCertWire =
        from_bytes_strict(bytes).map_err(|_| MnemeError::CertificateInvalid)?;
    if wire.version != COGNITION_CERT_VERSION {
        return Err(MnemeError::UnsupportedVersion { got: wire.version });
    }

    let root = stored_root_to_root(&wire.stored_root)?;
    verify_root_offline(&root, trust)?;
    if wire.receipt.root_bound != root.preimage_hash
        || !wire.receipt.binds_to_semantic_commit(&root.semantic_commit)
    {
        return Err(MnemeError::ReceiptRootMismatch);
    }
    if let Some(seq) = wire.as_of_seq {
        if root.sequence != seq {
            return Err(MnemeError::CertificateInvalid);
        }
    }
    if let Some(z) = &wire.receipt.zkann {
        if z.level != wire.level {
            return Err(MnemeError::CertificateInvalid);
        }
    }
    let committed_leaf_count = wire.receipt.verification_object.candidates.len();
    verify_semantic_receipt_vo_zkann(&wire.receipt, proc, committed_leaf_count)?;
    Ok(root)
}

/// Offline verification for the Phase II draft certificate.
///
/// Checks the v1 fields plus the presence of an explicitly unverified context-attestation
/// marker. Fails closed if the attestation is absent or the label is elevated.
#[cfg(feature = "context_gate")]
pub fn verify_cognition_certificate_v2_draft(
    bytes: &[u8],
    trust: &TrustConfig,
    proc: &Procedure,
) -> Result<Root, MnemeError> {
    let wire: CognitionCertWireV2Draft =
        from_bytes_strict(bytes).map_err(|_| MnemeError::CertificateInvalid)?;
    if wire.version != COGNITION_CERT_VERSION_V2_DRAFT {
        return Err(MnemeError::UnsupportedVersion { got: wire.version });
    }

    let root = stored_root_to_root(&wire.stored_root)?;
    verify_root_offline(&root, trust)?;
    if wire.receipt.root_bound != root.preimage_hash
        || !wire.receipt.binds_to_semantic_commit(&root.semantic_commit)
    {
        return Err(MnemeError::ReceiptRootMismatch);
    }
    if let Some(seq) = wire.as_of_seq {
        if root.sequence != seq {
            return Err(MnemeError::CertificateInvalid);
        }
    }
    if let Some(z) = &wire.receipt.zkann {
        if z.level != wire.level {
            return Err(MnemeError::CertificateInvalid);
        }
    }
    if wire.attestation.status != CONTEXT_GATE_DRAFT_STATUS {
        return Err(MnemeError::CertificateInvalid);
    }
    if wire.attestation.consumption_attestation.is_some()
        || wire.attestation.output_binding.is_some()
    {
        return Err(MnemeError::CertificateInvalid);
    }
    let committed_leaf_count = wire.receipt.verification_object.candidates.len();
    verify_semantic_receipt_vo_zkann(&wire.receipt, proc, committed_leaf_count)?;
    Ok(root)
}

/// Offline verification for Phase II strict context gate (gate open + `context_gate` feature).
#[cfg(feature = "context_gate")]
pub fn verify_cognition_certificate_v2_draft_strict(
    bytes: &[u8],
    trust: &TrustConfig,
    proc: &Procedure,
    entries: &[Entry],
    model_output: Option<&[u8]>,
    model_identity: Option<&[u8; 32]>,
) -> Result<Root, MnemeError> {
    let wire: CognitionCertWireV2Draft =
        from_bytes_strict(bytes).map_err(|_| MnemeError::CertificateInvalid)?;
    if wire.version != COGNITION_CERT_VERSION_V2_DRAFT {
        return Err(MnemeError::UnsupportedVersion { got: wire.version });
    }
    let root = stored_root_to_root(&wire.stored_root)?;
    verify_root_offline(&root, trust)?;
    if wire.receipt.root_bound != root.preimage_hash
        || !wire.receipt.binds_to_semantic_commit(&root.semantic_commit)
    {
        return Err(MnemeError::ReceiptRootMismatch);
    }
    if let Some(seq) = wire.as_of_seq {
        if root.sequence != seq {
            return Err(MnemeError::CertificateInvalid);
        }
    }
    if let Some(z) = &wire.receipt.zkann {
        if z.level != wire.level {
            return Err(MnemeError::CertificateInvalid);
        }
    }
    if wire.attestation.status != CONTEXT_GATE_STRICT_STATUS {
        return Err(MnemeError::CertificateInvalid);
    }
    let att = wire
        .attestation
        .consumption_attestation
        .as_ref()
        .ok_or(MnemeError::CertificateInvalid)?;
    if att.context_hash != wire.attestation.context_digest {
        return Err(MnemeError::CertificateInvalid);
    }
    let committed_leaf_count = wire.receipt.verification_object.candidates.len();
    verify_semantic_receipt_vo_zkann(&wire.receipt, proc, committed_leaf_count)?;
    apply_context_gate_strict(
        &wire.receipt.verification_object.result_ids,
        entries,
        att,
        wire.attestation.output_binding.as_ref(),
        model_output,
        model_identity,
    )?;
    Ok(root)
}

fn verify_root_offline(root: &Root, trust: &TrustConfig) -> Result<(), MnemeError> {
    let bound = RootPreimage {
        version: root.version,
        dag_head_root: root.dag_head_root,
        key_index_root: root.key_index_root,
        semantic_commit: root.semantic_commit,
        hlc_max: root.hlc_max,
        prev_root: root.prev_root,
    };
    if bound.hash() != root.preimage_hash {
        return Err(MnemeError::RootSigInvalid);
    }
    let mut verified = false;
    for pk_bytes in &trust.operator_keys {
        let pk = public_key_from_bytes(pk_bytes)?;
        if verify_signature_bytes(&pk, &root.preimage_hash, &root.signature).is_ok() {
            verified = true;
            break;
        }
    }
    if !verified {
        return Err(MnemeError::RootSigInvalid);
    }
    Ok(())
}

fn stored_root_to_root(stored: &StoredRoot) -> Result<Root, MnemeError> {
    Ok(Root {
        version: stored.version,
        preimage_hash: stored.preimage_hash,
        dag_head_root: stored.dag_head_root,
        key_index_root: stored.key_index_root,
        semantic_commit: stored.semantic_commit,
        hlc_max: stored.hlc_max,
        prev_root: stored.prev_root,
        signature: stored.signature.clone(),
        sequence: stored.sequence,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CognitionCertWire {
    version: u16,
    level: RetrievalProofLevel,
    as_of_seq: Option<u64>,
    stored_root: StoredRoot,
    receipt: SemanticRecallReceipt,
}

#[cfg(feature = "context_gate")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct CognitionCertWireV2Draft {
    version: u16,
    level: RetrievalProofLevel,
    as_of_seq: Option<u64>,
    stored_root: StoredRoot,
    receipt: SemanticRecallReceipt,
    attestation: ContextAttestationDraft,
}

impl DcborEncode for CognitionCertWire {
    fn dcbor_encode(&self, enc: &mut Encoder) -> Result<(), MnemeError> {
        let receipt_bytes = encode_semantic_receipt(&self.receipt)?;
        let root_bytes = to_bytes_canonical(&self.stored_root)?;
        let mut n = 4u64;
        if self.as_of_seq.is_some() {
            n += 1;
        }
        enc.begin_map(n)?;
        enc.encode_unsigned(F_CERT_VERSION)?;
        enc.encode_unsigned(u64::from(self.version))?;
        enc.encode_unsigned(F_LEVEL)?;
        enc.encode_unsigned(level_tag(self.level))?;
        if let Some(seq) = self.as_of_seq {
            enc.encode_unsigned(F_AS_OF_SEQ)?;
            enc.encode_unsigned(seq)?;
        }
        enc.encode_unsigned(F_STORED_ROOT)?;
        enc.encode_bytes(&root_bytes)?;
        enc.encode_unsigned(F_SEMANTIC_RECEIPT)?;
        enc.encode_bytes(&receipt_bytes)?;
        Ok(())
    }
}

impl DcborDecode for CognitionCertWire {
    fn dcbor_decode(dec: &mut Decoder<'_>) -> Result<Self, MnemeError> {
        let map = dec.decode_map()?;
        let mut version = None;
        let mut level = None;
        let mut as_of_seq = None;
        let mut stored_root = None;
        let mut receipt = None;
        for (key, value) in map {
            let field = parse_u64_field_key(&key)?;
            match field {
                F_CERT_VERSION => version = Some(parse_u16(&value)?),
                F_LEVEL => level = Some(parse_level(&value)?),
                F_AS_OF_SEQ => as_of_seq = Some(parse_u64(&value)?),
                F_STORED_ROOT => {
                    let bytes = parse_bytes(&value)?;
                    stored_root = Some(from_bytes_strict(&bytes)?);
                }
                F_SEMANTIC_RECEIPT => {
                    let bytes = parse_bytes(&value)?;
                    receipt = Some(decode_semantic_receipt(&bytes)?);
                }
                _ => {
                    let field_id = u16::try_from(field).unwrap_or(u16::MAX);
                    return Err(MnemeError::UnknownField { field: field_id });
                }
            }
        }
        Ok(Self {
            version: version.ok_or(MnemeError::CertificateInvalid)?,
            level: level.ok_or(MnemeError::CertificateInvalid)?,
            as_of_seq,
            stored_root: stored_root.ok_or(MnemeError::CertificateInvalid)?,
            receipt: receipt.ok_or(MnemeError::CertificateInvalid)?,
        })
    }
}

#[cfg(feature = "context_gate")]
impl DcborEncode for CognitionCertWireV2Draft {
    fn dcbor_encode(&self, enc: &mut Encoder) -> Result<(), MnemeError> {
        let receipt_bytes = encode_semantic_receipt(&self.receipt)?;
        let root_bytes = to_bytes_canonical(&self.stored_root)?;
        let att_bytes = to_bytes_canonical(&self.attestation)?;
        let mut n = 5u64;
        if self.as_of_seq.is_some() {
            n += 1;
        }
        enc.begin_map(n)?;
        enc.encode_unsigned(F_CERT_VERSION)?;
        enc.encode_unsigned(u64::from(self.version))?;
        enc.encode_unsigned(F_LEVEL)?;
        enc.encode_unsigned(level_tag(self.level))?;
        if let Some(seq) = self.as_of_seq {
            enc.encode_unsigned(F_AS_OF_SEQ)?;
            enc.encode_unsigned(seq)?;
        }
        enc.encode_unsigned(F_STORED_ROOT)?;
        enc.encode_bytes(&root_bytes)?;
        enc.encode_unsigned(F_SEMANTIC_RECEIPT)?;
        enc.encode_bytes(&receipt_bytes)?;
        enc.encode_unsigned(F_CONTEXT_ATTESTATION)?;
        enc.encode_bytes(&att_bytes)?;
        Ok(())
    }
}

#[cfg(feature = "context_gate")]
impl DcborDecode for CognitionCertWireV2Draft {
    fn dcbor_decode(dec: &mut Decoder<'_>) -> Result<Self, MnemeError> {
        let map = dec.decode_map()?;
        let mut version = None;
        let mut level = None;
        let mut as_of_seq = None;
        let mut stored_root = None;
        let mut receipt = None;
        let mut attestation = None;
        for (key, value) in map {
            let field = parse_u64_field_key(&key)?;
            match field {
                F_CERT_VERSION => version = Some(parse_u16(&value)?),
                F_LEVEL => level = Some(parse_level(&value)?),
                F_AS_OF_SEQ => as_of_seq = Some(parse_u64(&value)?),
                F_STORED_ROOT => {
                    let bytes = parse_bytes(&value)?;
                    stored_root = Some(from_bytes_strict(&bytes)?);
                }
                F_SEMANTIC_RECEIPT => {
                    let bytes = parse_bytes(&value)?;
                    receipt = Some(decode_semantic_receipt(&bytes)?);
                }
                F_CONTEXT_ATTESTATION => {
                    let bytes = parse_bytes(&value)?;
                    attestation = Some(from_bytes_strict(&bytes)?);
                }
                _ => {
                    let field_id = u16::try_from(field).unwrap_or(u16::MAX);
                    return Err(MnemeError::UnknownField { field: field_id });
                }
            }
        }
        Ok(Self {
            version: version.ok_or(MnemeError::CertificateInvalid)?,
            level: level.ok_or(MnemeError::CertificateInvalid)?,
            as_of_seq,
            stored_root: stored_root.ok_or(MnemeError::CertificateInvalid)?,
            receipt: receipt.ok_or(MnemeError::CertificateInvalid)?,
            attestation: attestation.ok_or(MnemeError::CertificateInvalid)?,
        })
    }
}

#[cfg(feature = "context_gate")]
impl DcborEncode for ContextAttestationDraft {
    fn dcbor_encode(&self, enc: &mut Encoder) -> Result<(), MnemeError> {
        let mut n = 2u64;
        if self.output_digest.is_some() {
            n += 1;
        }
        if self.consumption_attestation.is_some() {
            n += 1;
        }
        if self.output_binding.is_some() {
            n += 1;
        }
        enc.begin_map(n)?;
        enc.encode_unsigned(1)?;
        enc.encode_text(&self.status)?;
        enc.encode_unsigned(2)?;
        enc.encode_bytes(&self.context_digest)?;
        if let Some(digest) = self.output_digest {
            enc.encode_unsigned(3)?;
            enc.encode_bytes(&digest)?;
        }
        if let Some(att) = &self.consumption_attestation {
            enc.encode_unsigned(F_CCA)?;
            enc.encode_bytes(&mneme_core::encode_context_consumption_attestation(att)?)?;
        }
        if let Some(binding) = &self.output_binding {
            enc.encode_unsigned(F_OUTPUT_BINDING)?;
            enc.encode_bytes(&mneme_core::encode_output_binding(binding)?)?;
        }
        Ok(())
    }
}

#[cfg(feature = "context_gate")]
impl DcborDecode for ContextAttestationDraft {
    fn dcbor_decode(dec: &mut Decoder<'_>) -> Result<Self, MnemeError> {
        let map = dec.decode_map()?;
        let mut status = None;
        let mut context_digest = None;
        let mut output_digest = None;
        let mut consumption_attestation = None;
        let mut output_binding = None;
        for (key, value) in map {
            let field = parse_u64_field_key(&key)?;
            match field {
                1 => status = Some(parse_text(&value)?),
                2 => context_digest = Some(parse_fixed32(&value)?),
                3 => output_digest = Some(parse_fixed32(&value)?),
                f if f == F_CCA => {
                    consumption_attestation = Some(decode_context_consumption_attestation(
                        &parse_bytes(&value)?,
                    )?);
                }
                f if f == F_OUTPUT_BINDING => {
                    output_binding = Some(decode_output_binding(&parse_bytes(&value)?)?);
                }
                _ => return Err(MnemeError::UnknownField { field: 0 }),
            }
        }
        Ok(Self {
            status: status.ok_or(MnemeError::CertificateInvalid)?,
            context_digest: context_digest.ok_or(MnemeError::CertificateInvalid)?,
            output_digest,
            consumption_attestation,
            output_binding,
        })
    }
}

fn encode_semantic_receipt(receipt: &SemanticRecallReceipt) -> Result<Vec<u8>, MnemeError> {
    let vo = &receipt.verification_object;
    let mut enc = Encoder::new();
    let map_len = if receipt.zkann.is_some() { 7 } else { 6 };
    enc.begin_map(map_len)?;
    enc.encode_unsigned(1)?;
    enc.encode_bytes(&receipt.root_bound)?;
    enc.encode_unsigned(2)?;
    enc.encode_bytes(&receipt.semantic_commit)?;
    enc.encode_unsigned(3)?;
    enc.encode_bytes(&vo.procedure_id)?;
    enc.encode_unsigned(4)?;
    enc.encode_bytes(&vo.query_commit)?;
    enc.encode_unsigned(5)?;
    encode_result_ids(&mut enc, &vo.result_ids)?;
    enc.encode_unsigned(6)?;
    encode_vo_body(&mut enc, vo)?;
    if let Some(z) = &receipt.zkann {
        enc.encode_unsigned(7)?;
        enc.begin_map(2)?;
        enc.encode_unsigned(1)?;
        enc.encode_unsigned(level_tag(z.level))?;
        enc.encode_unsigned(2)?;
        encode_object_id_list(&mut enc, &z.visited_order)?;
    }
    Ok(enc.finish())
}

fn decode_semantic_receipt(bytes: &[u8]) -> Result<SemanticRecallReceipt, MnemeError> {
    let mut dec = Decoder::new(bytes);
    let map = dec.decode_map()?;
    let mut root_bound = None;
    let mut semantic_commit = None;
    let mut procedure_id = None;
    let mut query_commit = None;
    let mut result_ids = None;
    let mut vo_body = None;
    let mut zkann = None;
    for (key, value) in map {
        let field = parse_u64_field_key(&key)?;
        match field {
            1 => root_bound = Some(parse_fixed32(&value)?),
            2 => semantic_commit = Some(parse_fixed32(&value)?),
            3 => procedure_id = Some(parse_fixed32(&value)?),
            4 => query_commit = Some(parse_fixed32(&value)?),
            5 => result_ids = Some(decode_result_ids(&value)?),
            6 => vo_body = Some(decode_vo_body(&value)?),
            7 => zkann = Some(decode_zkann(&value)?),
            _ => {
                let field_id = u16::try_from(field).unwrap_or(u16::MAX);
                return Err(MnemeError::UnknownField { field: field_id });
            }
        }
    }
    let (nodes, candidates, leaf_indices) = vo_body.ok_or(MnemeError::CertificateInvalid)?;
    Ok(SemanticRecallReceipt {
        root_bound: root_bound.ok_or(MnemeError::CertificateInvalid)?,
        semantic_commit: semantic_commit.ok_or(MnemeError::CertificateInvalid)?,
        verification_object: mneme_core::VerificationObject {
            nodes,
            candidates,
            leaf_indices,
            procedure_id: procedure_id.ok_or(MnemeError::CertificateInvalid)?,
            query_commit: query_commit.ok_or(MnemeError::CertificateInvalid)?,
            result_ids: result_ids.ok_or(MnemeError::CertificateInvalid)?,
        },
        zk_retrieval: None,
        zkann,
        provenance: None,
    })
}

fn encode_vo_body(
    enc: &mut Encoder,
    vo: &mneme_core::VerificationObject,
) -> Result<(), MnemeError> {
    enc.begin_map(3)?;
    enc.encode_unsigned(1)?;
    encode_vo_nodes(enc, &vo.nodes)?;
    enc.encode_unsigned(2)?;
    encode_candidates(enc, &vo.candidates)?;
    enc.encode_unsigned(3)?;
    encode_leaf_indices(enc, &vo.leaf_indices)?;
    Ok(())
}

fn decode_vo_body(value: &CborValue) -> Result<(VoNodes, VoCandidates, Vec<usize>), MnemeError> {
    let map = value.as_map().ok_or(MnemeError::CertificateInvalid)?;
    let mut nodes = None;
    let mut candidates = None;
    let mut leaf_indices = None;
    for (k, v) in map {
        match parse_u64_field_key(k)? {
            1 => nodes = Some(decode_vo_nodes(v)?),
            2 => candidates = Some(decode_candidates(v)?),
            3 => leaf_indices = Some(decode_leaf_indices(v)?),
            _ => return Err(MnemeError::UnknownField { field: 0 }),
        }
    }
    let nodes = nodes.ok_or(MnemeError::CertificateInvalid)?;
    let candidates = candidates.ok_or(MnemeError::CertificateInvalid)?;
    let leaf_indices = leaf_indices.unwrap_or_else(|| (0..nodes.len()).collect());
    if leaf_indices.len() != nodes.len() || leaf_indices.len() != candidates.len() {
        return Err(MnemeError::CertificateInvalid);
    }
    Ok((nodes, candidates, leaf_indices))
}

fn level_tag(level: RetrievalProofLevel) -> u64 {
    match level {
        RetrievalProofLevel::ExactDominance => 0,
        RetrievalProofLevel::HnswAuditOnDemand => 1,
    }
}

fn parse_level(value: &CborValue) -> Result<RetrievalProofLevel, MnemeError> {
    let n = parse_u64(value)?;
    match n {
        0 => Ok(RetrievalProofLevel::ExactDominance),
        1 => Ok(RetrievalProofLevel::HnswAuditOnDemand),
        _ => Err(MnemeError::CertificateInvalid),
    }
}

fn parse_u64_field_key(key: &CborValue) -> Result<u64, MnemeError> {
    key.as_u64().ok_or(MnemeError::CertificateInvalid)
}

fn parse_u16(value: &CborValue) -> Result<u16, MnemeError> {
    let n = parse_u64(value)?;
    u16::try_from(n).map_err(|_| MnemeError::CertificateInvalid)
}

fn parse_u64(value: &CborValue) -> Result<u64, MnemeError> {
    value.as_u64().ok_or(MnemeError::CertificateInvalid)
}

fn parse_bytes(value: &CborValue) -> Result<Vec<u8>, MnemeError> {
    value
        .as_bytes()
        .map(|b| b.to_vec())
        .ok_or(MnemeError::CertificateInvalid)
}

fn parse_fixed32(value: &CborValue) -> Result<[u8; 32], MnemeError> {
    let b = parse_bytes(value)?;
    b.try_into().map_err(|_| MnemeError::CertificateInvalid)
}

#[cfg(feature = "context_gate")]
fn parse_text(value: &CborValue) -> Result<String, MnemeError> {
    value
        .as_text()
        .map(|s| s.to_string())
        .ok_or(MnemeError::CertificateInvalid)
}

fn encode_result_ids(enc: &mut Encoder, ids: &[ObjectId]) -> Result<(), MnemeError> {
    enc.begin_array(ids.len() as u64)?;
    for id in ids {
        enc.encode_bytes(id.as_bytes())?;
    }
    Ok(())
}

fn decode_result_ids(value: &CborValue) -> Result<Vec<ObjectId>, MnemeError> {
    let arr = value.as_array().ok_or(MnemeError::CertificateInvalid)?;
    arr.iter().map(|v| parse_fixed32(v).map(ObjectId)).collect()
}

fn encode_object_id_list(enc: &mut Encoder, ids: &[ObjectId]) -> Result<(), MnemeError> {
    encode_result_ids(enc, ids)
}

fn encode_vo_nodes(
    enc: &mut Encoder,
    nodes: &[([u8; 32], Vec<[u8; 32]>)],
) -> Result<(), MnemeError> {
    enc.begin_array(nodes.len() as u64)?;
    for (commit, path) in nodes {
        enc.begin_array(2)?;
        enc.encode_bytes(commit)?;
        enc.begin_array(path.len() as u64)?;
        for sib in path {
            enc.encode_bytes(sib)?;
        }
    }
    Ok(())
}

fn decode_vo_nodes(value: &CborValue) -> Result<VoNodes, MnemeError> {
    let outer = value.as_array().ok_or(MnemeError::CertificateInvalid)?;
    let mut out = Vec::with_capacity(outer.len());
    for item in outer {
        let pair = item.as_array().ok_or(MnemeError::CertificateInvalid)?;
        if pair.len() != 2 {
            return Err(MnemeError::CertificateInvalid);
        }
        let commit = parse_fixed32(&pair[0])?;
        let path_arr = pair[1].as_array().ok_or(MnemeError::CertificateInvalid)?;
        let path: Result<Vec<_>, _> = path_arr.iter().map(parse_fixed32).collect();
        out.push((commit, path?));
    }
    Ok(out)
}

fn encode_leaf_indices(enc: &mut Encoder, leaves: &[usize]) -> Result<(), MnemeError> {
    enc.begin_array(leaves.len() as u64)?;
    for idx in leaves {
        enc.encode_unsigned(u64::try_from(*idx).map_err(|_| MnemeError::CertificateInvalid)?)?;
    }
    Ok(())
}

fn decode_leaf_indices(value: &CborValue) -> Result<Vec<usize>, MnemeError> {
    let arr = value.as_array().ok_or(MnemeError::CertificateInvalid)?;
    let mut out = Vec::with_capacity(arr.len());
    for v in arr {
        let n = parse_u64(v)?;
        out.push(usize::try_from(n).map_err(|_| MnemeError::CertificateInvalid)?);
    }
    Ok(out)
}

fn encode_candidates(
    enc: &mut Encoder,
    rows: &[(ObjectId, [u8; 32], i64)],
) -> Result<(), MnemeError> {
    enc.begin_array(rows.len() as u64)?;
    for (id, emb, dist) in rows {
        enc.begin_array(3)?;
        enc.encode_bytes(id.as_bytes())?;
        enc.encode_bytes(emb)?;
        enc.encode_signed(*dist)?;
    }
    Ok(())
}

fn decode_candidates(value: &CborValue) -> Result<VoCandidates, MnemeError> {
    let outer = value.as_array().ok_or(MnemeError::CertificateInvalid)?;
    let mut out = Vec::with_capacity(outer.len());
    for item in outer {
        let row = item.as_array().ok_or(MnemeError::CertificateInvalid)?;
        if row.len() != 3 {
            return Err(MnemeError::CertificateInvalid);
        }
        let id = ObjectId(parse_fixed32(&row[0])?);
        let emb = parse_fixed32(&row[1])?;
        let dist = row[2].as_i64().ok_or(MnemeError::CertificateInvalid)?;
        out.push((id, emb, dist));
    }
    Ok(out)
}

/// Fuzz entry: decode Certificate v1 wire only; must not panic (§17.4).
pub fn fuzz_cognition_cert_wire(bytes: &[u8]) {
    let _ = from_bytes_strict::<CognitionCertWire>(bytes);
}

fn decode_zkann(value: &CborValue) -> Result<crate::receipt::ZkannAttachment, MnemeError> {
    let map = value.as_map().ok_or(MnemeError::CertificateInvalid)?;
    let mut level = None;
    let mut visited = None;
    for (k, v) in map {
        match parse_u64_field_key(k)? {
            1 => level = Some(parse_level(v)?),
            2 => visited = Some(decode_result_ids(v)?),
            _ => return Err(MnemeError::UnknownField { field: 0 }),
        }
    }
    Ok(crate::receipt::ZkannAttachment {
        level: level.ok_or(MnemeError::CertificateInvalid)?,
        visited_order: visited.ok_or(MnemeError::CertificateInvalid)?,
    })
}
