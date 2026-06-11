//! Trick #4 — Byzantine inference consistency (research prototype).
//!
//! Binds *M ≥ 2* independent model-endpoint output digests into the cognition
//! certificate. At temperature 0, unanimous output agreement is cryptographic
//! evidence that no single operator substituted context before inference.
//!
//! **Honesty:** proves *consistency across replicas*, not correctness; full collusion
//! breaks the guarantee. Complements TEE attestation — does not replace it.

use crate::receipt::SemanticRecallReceipt;
use mneme_core::{
    CborValue, DcborDecode, DcborEncode, Decoder, Encoder, MnemeError, from_bytes_strict,
    to_bytes_canonical,
};

pub const BYZANTINE_INFERENCE_BIND_TAG: &[u8] = b"MNEME-BYZANTINE-INF-BIND-v1";
pub const MIN_BYZANTINE_REPLICAS: u32 = 2;
pub const BYZANTINE_INFERENCE_STATUS: &str = concat!(
    "PROTOTYPE: Byzantine inference consistency binds M independent endpoint output digests ",
    "at temperature 0 into cognition certificates. Consistency evidence only — not correctness, ",
    "not semantic truth, not TEE attestation."
);
pub const BYZANTINE_INFERENCE_HONESTY: &str = concat!(
    "Byzantine inference consistency is unanimous-replica output agreement at temperature 0, ",
    "not a proof of model correctness or semantic truth. Divergence beyond sampling noise ",
    "flags context tampering relative to the certified assembly; full M-way collusion breaks ",
    "the guarantee. Logit-commitment digests are operator-supplied placeholders until a ",
    "normative commitment scheme ships. This complements per-recall receipts and TEE paths — ",
    "never a substitute for fail-closed recall verification."
);

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ByzantineInferenceFailure {
    WireDecode,
    ModelIdentityMissing,
    ContextDigestMissing,
    TemperatureMissing,
    MinReplicasMissing,
    BindingDigestMissing,
    ReplicasMissing,
    MinReplicasTooLow,
    ReplicaCountBelowMin,
    TemperatureNonZero,
    BindingDigestMismatch,
    ReplicaOutputDivergence,
    ReplicaLogitDivergence,
    ReplicaEndpointEmpty,
    ReplicaOutputMissing,
    ReplicaWireDecode,
    WireUnknownField { field: u16 },
}

fn byzantine_inference_failure_to_mneme(failure: ByzantineInferenceFailure) -> MnemeError {
    match failure {
        ByzantineInferenceFailure::WireUnknownField { field } => MnemeError::UnknownField { field },
        _ => MnemeError::CertificateInvalid,
    }
}

pub fn model_identity_digest(model_id: &[u8]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(18 + model_id.len());
    payload.extend_from_slice(b"MNEME-MODEL-ID/v1");
    payload.extend_from_slice(model_id);
    *blake3::hash(&payload).as_bytes()
}

pub fn inference_consistency_binding_digest(
    model_identity_digest: &[u8; 32],
    context_digest: &[u8; 32],
    temperature_milli: u32,
    min_replicas: u32,
    receipt_digest: &[u8; 32],
) -> [u8; 32] {
    let mut payload = Vec::with_capacity(BYZANTINE_INFERENCE_BIND_TAG.len() + 32 + 32 + 4 + 4 + 32);
    payload.extend_from_slice(BYZANTINE_INFERENCE_BIND_TAG);
    payload.extend_from_slice(model_identity_digest);
    payload.extend_from_slice(context_digest);
    payload.extend_from_slice(&temperature_milli.to_le_bytes());
    payload.extend_from_slice(&min_replicas.to_le_bytes());
    payload.extend_from_slice(receipt_digest);
    *blake3::hash(&payload).as_bytes()
}

pub fn prove_inference_consistency(
    model_id: &[u8],
    context_digest: [u8; 32],
    temperature_milli: u32,
    min_replicas: u32,
    replicas: Vec<InferenceReplica>,
    receipt: &SemanticRecallReceipt,
) -> Result<InferenceConsistency, MnemeError> {
    if min_replicas < MIN_BYZANTINE_REPLICAS {
        return Err(byzantine_inference_failure_to_mneme(
            ByzantineInferenceFailure::MinReplicasTooLow,
        ));
    }
    if replicas.len() < min_replicas as usize {
        return Err(byzantine_inference_failure_to_mneme(
            ByzantineInferenceFailure::ReplicaCountBelowMin,
        ));
    }
    for replica in &replicas {
        if replica.endpoint_id.is_empty() {
            return Err(byzantine_inference_failure_to_mneme(
                ByzantineInferenceFailure::ReplicaEndpointEmpty,
            ));
        }
    }
    let mid = model_identity_digest(model_id);
    let binding_digest = inference_consistency_binding_digest(
        &mid,
        &context_digest,
        temperature_milli,
        min_replicas,
        &receipt.digest(),
    );
    Ok(InferenceConsistency {
        model_identity_digest: mid,
        context_digest,
        temperature_milli,
        min_replicas,
        binding_digest,
        replicas,
    })
}

pub fn verify_inference_consistency_binding(
    witness: &InferenceConsistency,
    receipt: &SemanticRecallReceipt,
) -> Result<(), MnemeError> {
    let expected = inference_consistency_binding_digest(
        &witness.model_identity_digest,
        &witness.context_digest,
        witness.temperature_milli,
        witness.min_replicas,
        &receipt.digest(),
    );
    if expected != witness.binding_digest {
        return Err(byzantine_inference_failure_to_mneme(
            ByzantineInferenceFailure::BindingDigestMismatch,
        ));
    }
    Ok(())
}

pub fn verify_byzantine_inference(
    witness: &InferenceConsistency,
    receipt: &SemanticRecallReceipt,
) -> Result<(), MnemeError> {
    verify_inference_consistency_binding(witness, receipt)?;
    if witness.min_replicas < MIN_BYZANTINE_REPLICAS {
        return Err(byzantine_inference_failure_to_mneme(
            ByzantineInferenceFailure::MinReplicasTooLow,
        ));
    }
    if witness.replicas.len() < witness.min_replicas as usize {
        return Err(byzantine_inference_failure_to_mneme(
            ByzantineInferenceFailure::ReplicaCountBelowMin,
        ));
    }
    if witness.temperature_milli != 0 {
        return Err(byzantine_inference_failure_to_mneme(
            ByzantineInferenceFailure::TemperatureNonZero,
        ));
    }
    let reference_output = witness.replicas[0].output_digest;
    for replica in &witness.replicas[1..] {
        if replica.output_digest != reference_output {
            return Err(byzantine_inference_failure_to_mneme(
                ByzantineInferenceFailure::ReplicaOutputDivergence,
            ));
        }
    }
    let mut logit_seen = None;
    for replica in &witness.replicas {
        match (logit_seen, replica.logit_commitment_digest) {
            (None, None) => {}
            (None, Some(d)) => logit_seen = Some(d),
            (Some(expected), Some(actual)) if expected == actual => {}
            (Some(_), Some(_)) | (Some(_), None) => {
                return Err(byzantine_inference_failure_to_mneme(
                    ByzantineInferenceFailure::ReplicaLogitDivergence,
                ));
            }
        }
    }
    Ok(())
}

pub fn encode_inference_consistency(witness: &InferenceConsistency) -> Result<Vec<u8>, MnemeError> {
    to_bytes_canonical(witness)
}

pub fn decode_inference_consistency(bytes: &[u8]) -> Result<InferenceConsistency, MnemeError> {
    from_bytes_strict(bytes)
        .map_err(|_| byzantine_inference_failure_to_mneme(ByzantineInferenceFailure::WireDecode))
}

impl DcborEncode for InferenceReplica {
    fn dcbor_encode(&self, enc: &mut Encoder) -> Result<(), MnemeError> {
        let mut n = 2u64;
        if self.logit_commitment_digest.is_some() {
            n += 1;
        }
        enc.begin_map(n)?;
        enc.encode_unsigned(F_ENDPOINT_ID)?;
        enc.encode_bytes(&self.endpoint_id)?;
        enc.encode_unsigned(F_OUTPUT_DIGEST)?;
        enc.encode_bytes(&self.output_digest)?;
        if let Some(logit) = &self.logit_commitment_digest {
            enc.encode_unsigned(F_LOGIT_COMMITMENT)?;
            enc.encode_bytes(logit)?;
        }
        Ok(())
    }
}

impl DcborDecode for InferenceReplica {
    fn dcbor_decode(dec: &mut Decoder<'_>) -> Result<Self, MnemeError> {
        let map = dec.decode_map()?;
        let mut endpoint_id = None;
        let mut output_digest = None;
        let mut logit_commitment_digest = None;
        for (key, value) in map {
            let field = key.as_u64().ok_or_else(|| {
                byzantine_inference_failure_to_mneme(ByzantineInferenceFailure::ReplicaWireDecode)
            })?;
            match field {
                F_ENDPOINT_ID => {
                    endpoint_id = Some(
                        value
                            .as_bytes()
                            .ok_or_else(|| {
                                byzantine_inference_failure_to_mneme(
                                    ByzantineInferenceFailure::ReplicaWireDecode,
                                )
                            })?
                            .to_vec(),
                    )
                }
                F_OUTPUT_DIGEST => output_digest = Some(parse_fixed32(&value)?),
                F_LOGIT_COMMITMENT => logit_commitment_digest = Some(parse_fixed32(&value)?),
                _ => {
                    return Err(byzantine_inference_failure_to_mneme(
                        ByzantineInferenceFailure::WireUnknownField {
                            field: u16::try_from(field).unwrap_or(u16::MAX),
                        },
                    ));
                }
            }
        }
        Ok(Self {
            endpoint_id: endpoint_id.ok_or_else(|| {
                byzantine_inference_failure_to_mneme(ByzantineInferenceFailure::ReplicaWireDecode)
            })?,
            output_digest: output_digest.ok_or_else(|| {
                byzantine_inference_failure_to_mneme(
                    ByzantineInferenceFailure::ReplicaOutputMissing,
                )
            })?,
            logit_commitment_digest,
        })
    }
}

impl DcborEncode for InferenceConsistency {
    fn dcbor_encode(&self, enc: &mut Encoder) -> Result<(), MnemeError> {
        enc.begin_map(6)?;
        enc.encode_unsigned(F_MODEL_IDENTITY)?;
        enc.encode_bytes(&self.model_identity_digest)?;
        enc.encode_unsigned(F_CONTEXT_DIGEST)?;
        enc.encode_bytes(&self.context_digest)?;
        enc.encode_unsigned(F_TEMPERATURE_MILLI)?;
        enc.encode_unsigned(u64::from(self.temperature_milli))?;
        enc.encode_unsigned(F_MIN_REPLICAS)?;
        enc.encode_unsigned(u64::from(self.min_replicas))?;
        enc.encode_unsigned(F_BINDING_DIGEST)?;
        enc.encode_bytes(&self.binding_digest)?;
        enc.encode_unsigned(F_REPLICAS)?;
        enc.begin_array(self.replicas.len() as u64)?;
        for replica in &self.replicas {
            enc.encode_bytes(&to_bytes_canonical(replica)?)?;
        }
        Ok(())
    }
}

impl DcborDecode for InferenceConsistency {
    fn dcbor_decode(dec: &mut Decoder<'_>) -> Result<Self, MnemeError> {
        let map = dec.decode_map()?;
        let mut model_identity_digest = None;
        let mut context_digest = None;
        let mut temperature_milli = None;
        let mut min_replicas = None;
        let mut binding_digest = None;
        let mut replicas = None;
        for (key, value) in map {
            let field = key.as_u64().ok_or_else(|| {
                byzantine_inference_failure_to_mneme(ByzantineInferenceFailure::WireDecode)
            })?;
            match field {
                F_MODEL_IDENTITY => model_identity_digest = Some(parse_fixed32(&value)?),
                F_CONTEXT_DIGEST => context_digest = Some(parse_fixed32(&value)?),
                F_TEMPERATURE_MILLI => {
                    temperature_milli = Some(
                        u32::try_from(value.as_u64().ok_or_else(|| {
                            byzantine_inference_failure_to_mneme(
                                ByzantineInferenceFailure::WireDecode,
                            )
                        })?)
                        .map_err(|_| {
                            byzantine_inference_failure_to_mneme(
                                ByzantineInferenceFailure::WireDecode,
                            )
                        })?,
                    )
                }
                F_MIN_REPLICAS => {
                    min_replicas = Some(
                        u32::try_from(value.as_u64().ok_or_else(|| {
                            byzantine_inference_failure_to_mneme(
                                ByzantineInferenceFailure::WireDecode,
                            )
                        })?)
                        .map_err(|_| {
                            byzantine_inference_failure_to_mneme(
                                ByzantineInferenceFailure::WireDecode,
                            )
                        })?,
                    )
                }
                F_BINDING_DIGEST => binding_digest = Some(parse_fixed32(&value)?),
                F_REPLICAS => {
                    let arr = value.as_array().ok_or_else(|| {
                        byzantine_inference_failure_to_mneme(ByzantineInferenceFailure::WireDecode)
                    })?;
                    replicas = Some(
                        arr.iter()
                            .map(|item| {
                                from_bytes_strict(item.as_bytes().ok_or_else(|| {
                                    byzantine_inference_failure_to_mneme(
                                        ByzantineInferenceFailure::WireDecode,
                                    )
                                })?)
                            })
                            .collect::<Result<Vec<_>, _>>()?,
                    );
                }
                _ => {
                    return Err(byzantine_inference_failure_to_mneme(
                        ByzantineInferenceFailure::WireUnknownField {
                            field: u16::try_from(field).unwrap_or(u16::MAX),
                        },
                    ));
                }
            }
        }
        Ok(Self {
            model_identity_digest: model_identity_digest.ok_or_else(|| {
                byzantine_inference_failure_to_mneme(
                    ByzantineInferenceFailure::ModelIdentityMissing,
                )
            })?,
            context_digest: context_digest.ok_or_else(|| {
                byzantine_inference_failure_to_mneme(
                    ByzantineInferenceFailure::ContextDigestMissing,
                )
            })?,
            temperature_milli: temperature_milli.ok_or_else(|| {
                byzantine_inference_failure_to_mneme(ByzantineInferenceFailure::TemperatureMissing)
            })?,
            min_replicas: min_replicas.ok_or_else(|| {
                byzantine_inference_failure_to_mneme(ByzantineInferenceFailure::MinReplicasMissing)
            })?,
            binding_digest: binding_digest.ok_or_else(|| {
                byzantine_inference_failure_to_mneme(
                    ByzantineInferenceFailure::BindingDigestMissing,
                )
            })?,
            replicas: replicas.ok_or_else(|| {
                byzantine_inference_failure_to_mneme(ByzantineInferenceFailure::ReplicasMissing)
            })?,
        })
    }
}

fn parse_fixed32(value: &CborValue) -> Result<[u8; 32], MnemeError> {
    let bytes = value.as_bytes().ok_or_else(|| {
        byzantine_inference_failure_to_mneme(ByzantineInferenceFailure::WireDecode)
    })?;
    if bytes.len() != 32 {
        return Err(byzantine_inference_failure_to_mneme(
            ByzantineInferenceFailure::WireDecode,
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mneme_core::{ObjectId, VerificationObject};

    fn minimal_receipt() -> SemanticRecallReceipt {
        let id = ObjectId::from_bytes([0x44; 32]);
        SemanticRecallReceipt::new(
            [0x11; 32],
            [0x22; 32],
            VerificationObject {
                nodes: vec![],
                candidates: vec![(id, [0x55; 32], 0)],
                leaf_indices: vec![0],
                procedure_id: [0x33; 32],
                query_commit: [0x66; 32],
                result_ids: vec![id],
            },
        )
    }

    #[test]
    fn unanimous_outputs_pass_divergence_fails() {
        let receipt = minimal_receipt();
        let output = *blake3::hash(b"same").as_bytes();
        let replicas = vec![
            InferenceReplica {
                endpoint_id: b"a".to_vec(),
                output_digest: output,
                logit_commitment_digest: None,
            },
            InferenceReplica {
                endpoint_id: b"b".to_vec(),
                output_digest: output,
                logit_commitment_digest: None,
            },
        ];
        let witness =
            prove_inference_consistency(b"m", [0xBB; 32], 0, 2, replicas, &receipt).unwrap();
        verify_byzantine_inference(&witness, &receipt).unwrap();
        let mut bad = witness.clone();
        bad.replicas[1].output_digest = [0xFF; 32];
        assert_eq!(
            verify_byzantine_inference(&bad, &receipt).err(),
            Some(MnemeError::CertificateInvalid)
        );
    }
}
