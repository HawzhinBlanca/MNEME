//! Byzantine inference consistency — independent reference sketch (Trick #4).

use crate::dcbor::{CborValue, Decoder};
use crate::error::CrossrefError;

pub const F_INFERENCE_CONSISTENCY_CERT: u64 = 8;
pub const BYZANTINE_INFERENCE_BIND_TAG: &[u8] = b"MNEME-BYZANTINE-INF-BIND-v1";
pub const BYZANTINE_INFERENCE_HONESTY: &str = "Byzantine inference consistency is unanimous \
replica output agreement at temperature 0 — consistency evidence only, not correctness or \
semantic truth. Full M-way collusion breaks the guarantee.";

const F_MODEL_IDENTITY: u64 = 1;
const F_CONTEXT_DIGEST: u64 = 2;
const F_TEMPERATURE_MILLI: u64 = 3;
const F_MIN_REPLICAS: u64 = 4;
const F_BINDING_DIGEST: u64 = 5;
const F_REPLICAS: u64 = 6;
const F_ENDPOINT_ID: u64 = 1;
const F_OUTPUT_DIGEST: u64 = 2;
const F_LOGIT_COMMITMENT: u64 = 3;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InferenceReplica {
    pub endpoint_id: Vec<u8>,
    pub output_digest: [u8; 32],
    pub logit_commitment_digest: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InferenceConsistency {
    pub model_identity_digest: [u8; 32],
    pub context_digest: [u8; 32],
    pub temperature_milli: u32,
    pub min_replicas: u32,
    pub binding_digest: [u8; 32],
    pub replicas: Vec<InferenceReplica>,
}

pub fn decode_inference_consistency(bytes: &[u8]) -> Result<InferenceConsistency, CrossrefError> {
    let mut dec = Decoder::new(bytes);
    let map = dec.decode_map()?;
    dec.ensure_consumed()?;
    let mut model_identity_digest = None;
    let mut context_digest = None;
    let mut temperature_milli = None;
    let mut min_replicas = None;
    let mut binding_digest = None;
    let mut replicas = None;
    for (key, value) in map {
        let field = key.as_u64().ok_or(CrossrefError::SchemaDrift)?;
        match field {
            F_MODEL_IDENTITY => model_identity_digest = Some(fixed32(&value)?),
            F_CONTEXT_DIGEST => context_digest = Some(fixed32(&value)?),
            F_TEMPERATURE_MILLI => temperature_milli = Some(u32_field(&value)?),
            F_MIN_REPLICAS => min_replicas = Some(u32_field(&value)?),
            F_BINDING_DIGEST => binding_digest = Some(fixed32(&value)?),
            F_REPLICAS => replicas = Some(decode_replicas(&value)?),
            _ => return Err(CrossrefError::SchemaDrift),
        }
    }
    Ok(InferenceConsistency {
        model_identity_digest: model_identity_digest.ok_or(CrossrefError::SchemaDrift)?,
        context_digest: context_digest.ok_or(CrossrefError::SchemaDrift)?,
        temperature_milli: temperature_milli.ok_or(CrossrefError::SchemaDrift)?,
        min_replicas: min_replicas.ok_or(CrossrefError::SchemaDrift)?,
        binding_digest: binding_digest.ok_or(CrossrefError::SchemaDrift)?,
        replicas: replicas.ok_or(CrossrefError::SchemaDrift)?,
    })
}

pub fn verify_unanimous_outputs(witness: &InferenceConsistency) -> Result<(), CrossrefError> {
    if witness.min_replicas < 2 || witness.replicas.len() < witness.min_replicas as usize {
        return Err(CrossrefError::CertificateInvalid);
    }
    if witness.temperature_milli != 0 {
        return Err(CrossrefError::CertificateInvalid);
    }
    let reference = witness.replicas[0].output_digest;
    for r in &witness.replicas[1..] {
        if r.output_digest != reference {
            return Err(CrossrefError::CertificateInvalid);
        }
    }
    Ok(())
}

fn decode_replicas(value: &CborValue) -> Result<Vec<InferenceReplica>, CrossrefError> {
    let arr = value.as_array().ok_or(CrossrefError::SchemaDrift)?;
    arr.iter()
        .map(|item| decode_replica(item.as_bytes().ok_or(CrossrefError::SchemaDrift)?))
        .collect()
}

fn decode_replica(bytes: &[u8]) -> Result<InferenceReplica, CrossrefError> {
    let mut dec = Decoder::new(bytes);
    let map = dec.decode_map()?;
    dec.ensure_consumed()?;
    let mut endpoint_id = None;
    let mut output_digest = None;
    let mut logit = None;
    for (key, value) in map {
        let field = key.as_u64().ok_or(CrossrefError::SchemaDrift)?;
        match field {
            F_ENDPOINT_ID => {
                endpoint_id = Some(value.as_bytes().ok_or(CrossrefError::SchemaDrift)?.to_vec())
            }
            F_OUTPUT_DIGEST => output_digest = Some(fixed32(&value)?),
            F_LOGIT_COMMITMENT => logit = Some(fixed32(&value)?),
            _ => return Err(CrossrefError::SchemaDrift),
        }
    }
    Ok(InferenceReplica {
        endpoint_id: endpoint_id.ok_or(CrossrefError::SchemaDrift)?,
        output_digest: output_digest.ok_or(CrossrefError::SchemaDrift)?,
        logit_commitment_digest: logit,
    })
}

fn u32_field(value: &CborValue) -> Result<u32, CrossrefError> {
    u32::try_from(value.as_u64().ok_or(CrossrefError::SchemaDrift)?)
        .map_err(|_| CrossrefError::SchemaDrift)
}

fn fixed32(value: &CborValue) -> Result<[u8; 32], CrossrefError> {
    let bytes = value.as_bytes().ok_or(CrossrefError::SchemaDrift)?;
    if bytes.len() != 32 {
        return Err(CrossrefError::SchemaDrift);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}
