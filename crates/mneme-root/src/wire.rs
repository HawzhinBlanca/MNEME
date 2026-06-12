//! MNEME-dCBOR wire format for persisted root checkpoints.

use crate::ROOT_VERSION;
use crate::StoredRoot;
use mneme_core::{CborValue, DcborDecode, DcborEncode, Decoder, Encoder, MnemeError};
use mneme_crypto::ED25519_SIG_LEN;

const F_VERSION: u64 = 1;
const F_DAG_HEAD_ROOT: u64 = 2;
const F_KEY_INDEX_ROOT: u64 = 3;
const F_SEMANTIC_COMMIT: u64 = 4;
const F_HLC_MAX: u64 = 5;
const F_PREV_ROOT: u64 = 6;
const F_PREIMAGE_HASH: u64 = 7;
const F_SIGNATURE: u64 = 8;
const F_SEQUENCE: u64 = 9;
const F_VDF_PROOF: u64 = 10;
const F_VDF_DIFFICULTY: u64 = 11;

const HLC_MAX_LEN: usize = 14;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RootWireFailure {
    UnsupportedVersion { version: u16 },
    FieldKey,
    UnknownField { field: u16 },
    MissingVersion,
    MissingDagHeadRoot,
    MissingKeyIndexRoot,
    MissingSemanticCommit,
    MissingHlcMax,
    MissingPrevRoot,
    MissingPreimageHash,
    MissingSignature,
    MissingSequence,
    U64,
    U16Width,
    Fixed32Bytes,
    Fixed32Length,
    FixedSliceBytes,
    FixedSliceLength,
    SignatureBytes,
    SignatureLength,
}

fn root_wire_failure_to_mneme(failure: RootWireFailure) -> MnemeError {
    match failure {
        RootWireFailure::UnsupportedVersion { version } => {
            MnemeError::UnsupportedVersion { got: version }
        }
        RootWireFailure::UnknownField { field } => MnemeError::UnknownField { field },
        RootWireFailure::SignatureLength => MnemeError::RootSigInvalid,
        RootWireFailure::FieldKey
        | RootWireFailure::MissingVersion
        | RootWireFailure::MissingDagHeadRoot
        | RootWireFailure::MissingKeyIndexRoot
        | RootWireFailure::MissingSemanticCommit
        | RootWireFailure::MissingHlcMax
        | RootWireFailure::MissingPrevRoot
        | RootWireFailure::MissingPreimageHash
        | RootWireFailure::MissingSignature
        | RootWireFailure::MissingSequence
        | RootWireFailure::U64
        | RootWireFailure::U16Width
        | RootWireFailure::Fixed32Bytes
        | RootWireFailure::Fixed32Length
        | RootWireFailure::FixedSliceBytes
        | RootWireFailure::FixedSliceLength
        | RootWireFailure::SignatureBytes => MnemeError::SchemaDrift,
    }
}

fn unsupported_root_version_error(version: u16) -> MnemeError {
    root_wire_failure_to_mneme(RootWireFailure::UnsupportedVersion { version })
}

fn root_field_key_error() -> MnemeError {
    root_wire_failure_to_mneme(RootWireFailure::FieldKey)
}

fn root_unknown_field_error(field: u64) -> MnemeError {
    let field = match u16::try_from(field) {
        Ok(field) => field,
        Err(_) => u16::MAX,
    };
    root_wire_failure_to_mneme(RootWireFailure::UnknownField { field })
}

fn missing_root_version_error() -> MnemeError {
    root_wire_failure_to_mneme(RootWireFailure::MissingVersion)
}

fn missing_root_dag_head_root_error() -> MnemeError {
    root_wire_failure_to_mneme(RootWireFailure::MissingDagHeadRoot)
}

fn missing_root_key_index_root_error() -> MnemeError {
    root_wire_failure_to_mneme(RootWireFailure::MissingKeyIndexRoot)
}

fn missing_root_semantic_commit_error() -> MnemeError {
    root_wire_failure_to_mneme(RootWireFailure::MissingSemanticCommit)
}

fn missing_root_hlc_max_error() -> MnemeError {
    root_wire_failure_to_mneme(RootWireFailure::MissingHlcMax)
}

fn missing_root_prev_root_error() -> MnemeError {
    root_wire_failure_to_mneme(RootWireFailure::MissingPrevRoot)
}

fn missing_root_preimage_hash_error() -> MnemeError {
    root_wire_failure_to_mneme(RootWireFailure::MissingPreimageHash)
}

fn missing_root_signature_error() -> MnemeError {
    root_wire_failure_to_mneme(RootWireFailure::MissingSignature)
}

fn missing_root_sequence_error() -> MnemeError {
    root_wire_failure_to_mneme(RootWireFailure::MissingSequence)
}

fn root_u64_error() -> MnemeError {
    root_wire_failure_to_mneme(RootWireFailure::U64)
}

fn root_u16_width_error() -> MnemeError {
    root_wire_failure_to_mneme(RootWireFailure::U16Width)
}

fn root_fixed32_bytes_error() -> MnemeError {
    root_wire_failure_to_mneme(RootWireFailure::Fixed32Bytes)
}

fn root_fixed32_length_error() -> MnemeError {
    root_wire_failure_to_mneme(RootWireFailure::Fixed32Length)
}

fn root_fixed_slice_bytes_error() -> MnemeError {
    root_wire_failure_to_mneme(RootWireFailure::FixedSliceBytes)
}

fn root_fixed_slice_length_error() -> MnemeError {
    root_wire_failure_to_mneme(RootWireFailure::FixedSliceLength)
}

fn root_signature_bytes_error() -> MnemeError {
    root_wire_failure_to_mneme(RootWireFailure::SignatureBytes)
}

fn root_signature_length_error() -> MnemeError {
    root_wire_failure_to_mneme(RootWireFailure::SignatureLength)
}

impl DcborEncode for StoredRoot {
    fn dcbor_encode(&self, enc: &mut Encoder) -> Result<(), MnemeError> {
        self.validate_invariants()?;
        let mut map_len = 9u64;
        if self.vdf_proof.is_some() {
            map_len += 1;
        }
        if self.vdf_difficulty.is_some() {
            map_len += 1;
        }
        enc.begin_map(map_len)?;
        enc.encode_unsigned(F_VERSION)?;
        enc.encode_unsigned(u64::from(self.version))?;
        enc.encode_unsigned(F_DAG_HEAD_ROOT)?;
        enc.encode_bytes(&self.dag_head_root)?;
        enc.encode_unsigned(F_KEY_INDEX_ROOT)?;
        enc.encode_bytes(&self.key_index_root)?;
        enc.encode_unsigned(F_SEMANTIC_COMMIT)?;
        enc.encode_bytes(&self.semantic_commit)?;
        enc.encode_unsigned(F_HLC_MAX)?;
        enc.encode_bytes(&self.hlc_max)?;
        enc.encode_unsigned(F_PREV_ROOT)?;
        enc.encode_bytes(&self.prev_root)?;
        enc.encode_unsigned(F_PREIMAGE_HASH)?;
        enc.encode_bytes(&self.preimage_hash)?;
        enc.encode_unsigned(F_SIGNATURE)?;
        enc.encode_bytes(&self.signature)?;
        enc.encode_unsigned(F_SEQUENCE)?;
        enc.encode_unsigned(self.sequence)?;
        if let Some(proof) = &self.vdf_proof {
            enc.encode_unsigned(F_VDF_PROOF)?;
            enc.encode_bytes(proof)?;
        }
        if let Some(diff) = self.vdf_difficulty {
            enc.encode_unsigned(F_VDF_DIFFICULTY)?;
            enc.encode_unsigned(diff)?;
        }
        Ok(())
    }
}

impl DcborDecode for StoredRoot {
    fn dcbor_decode(dec: &mut Decoder<'_>) -> Result<Self, MnemeError> {
        let map = dec.decode_map()?;
        let mut version = None;
        let mut dag_head_root = None;
        let mut key_index_root = None;
        let mut semantic_commit = None;
        let mut hlc_max = None;
        let mut prev_root = None;
        let mut preimage_hash = None;
        let mut signature = None;
        let mut sequence = None;
        let mut vdf_proof = None;
        let mut vdf_difficulty = None;

        for (key, value) in map {
            let field = parse_u64_field_key(&key)?;
            match field {
                F_VERSION => version = Some(parse_u16(&value)?),
                F_DAG_HEAD_ROOT => dag_head_root = Some(parse_fixed32(&value)?),
                F_KEY_INDEX_ROOT => key_index_root = Some(parse_fixed32(&value)?),
                F_SEMANTIC_COMMIT => semantic_commit = Some(parse_fixed32(&value)?),
                F_HLC_MAX => hlc_max = Some(parse_fixed_slice::<HLC_MAX_LEN>(&value)?),
                F_PREV_ROOT => prev_root = Some(parse_fixed32(&value)?),
                F_PREIMAGE_HASH => preimage_hash = Some(parse_fixed32(&value)?),
                F_SIGNATURE => signature = Some(parse_signature(&value)?),
                F_SEQUENCE => sequence = Some(parse_u64(&value)?),
                F_VDF_PROOF => vdf_proof = Some(parse_bytes(&value)?),
                F_VDF_DIFFICULTY => vdf_difficulty = Some(parse_u64(&value)?),
                _ => return Err(root_unknown_field_error(field)),
            }
        }

        let stored = Self {
            version: version.ok_or_else(missing_root_version_error)?,
            dag_head_root: dag_head_root.ok_or_else(missing_root_dag_head_root_error)?,
            key_index_root: key_index_root.ok_or_else(missing_root_key_index_root_error)?,
            semantic_commit: semantic_commit.ok_or_else(missing_root_semantic_commit_error)?,
            hlc_max: hlc_max.ok_or_else(missing_root_hlc_max_error)?,
            prev_root: prev_root.ok_or_else(missing_root_prev_root_error)?,
            preimage_hash: preimage_hash.ok_or_else(missing_root_preimage_hash_error)?,
            signature: signature.ok_or_else(missing_root_signature_error)?,
            sequence: sequence.ok_or_else(missing_root_sequence_error)?,
            vdf_proof,
            vdf_difficulty,
        };
        stored.validate_invariants()?;
        Ok(stored)
    }
}

impl StoredRoot {
    pub(crate) fn validate_invariants(&self) -> Result<(), MnemeError> {
        if self.version != ROOT_VERSION {
            return Err(unsupported_root_version_error(self.version));
        }
        if self.signature.len() != ED25519_SIG_LEN {
            return Err(MnemeError::RootSigInvalid);
        }
        if self.hlc_max.len() != HLC_MAX_LEN {
            return Err(MnemeError::HlcMalformed);
        }
        Ok(())
    }
}

fn parse_u64_field_key(key: &CborValue) -> Result<u64, MnemeError> {
    key.as_u64().ok_or_else(root_field_key_error)
}

fn parse_u16(value: &CborValue) -> Result<u16, MnemeError> {
    let raw = value.as_u64().ok_or_else(root_u64_error)?;
    u16::try_from(raw).map_err(|_| root_u16_width_error())
}

fn parse_u64(value: &CborValue) -> Result<u64, MnemeError> {
    value.as_u64().ok_or_else(root_u64_error)
}

fn parse_fixed32(value: &CborValue) -> Result<[u8; 32], MnemeError> {
    let bytes = value.as_bytes().ok_or_else(root_fixed32_bytes_error)?;
    if bytes.len() != 32 {
        return Err(root_fixed32_length_error());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn parse_fixed_slice<const N: usize>(value: &CborValue) -> Result<[u8; N], MnemeError> {
    let bytes = value.as_bytes().ok_or_else(root_fixed_slice_bytes_error)?;
    if bytes.len() != N {
        return Err(root_fixed_slice_length_error());
    }
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn parse_signature(value: &CborValue) -> Result<Vec<u8>, MnemeError> {
    let bytes = value.as_bytes().ok_or_else(root_signature_bytes_error)?;
    if bytes.len() != ED25519_SIG_LEN {
        return Err(root_signature_length_error());
    }
    Ok(bytes.to_vec())
}

fn parse_bytes(value: &CborValue) -> Result<Vec<u8>, MnemeError> {
    let bytes = value.as_bytes().ok_or_else(root_fixed_slice_bytes_error)?;
    Ok(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_between_markers<'a>(
        source: &'a str,
        start_marker: &str,
        end_marker: &str,
        context: &str,
    ) -> &'a str {
        let start = source
            .find(start_marker)
            .unwrap_or_else(|| panic!("{context} should contain start marker `{start_marker}`"));
        let end_offset = source[start..]
            .find(end_marker)
            .unwrap_or_else(|| panic!("{context} should contain end marker `{end_marker}`"));
        &source[start..start + end_offset]
    }

    #[test]
    fn root_wire_failures_are_classified_not_schema_drift_collapsed() {
        let source = include_str!("wire.rs");
        let decoder = source_between_markers(
            source,
            "impl DcborDecode for StoredRoot",
            "impl StoredRoot",
            "stored root decoder",
        );
        let helpers = source_between_markers(
            source,
            "fn parse_u64_field_key",
            "#[cfg(test)]",
            "stored root parse helpers",
        );
        let invariants = source_between_markers(
            source,
            "impl StoredRoot",
            "fn parse_u64_field_key",
            "stored root invariant validator",
        );

        for section in [decoder, helpers] {
            for forbidden in [
                "ok_or(MnemeError::SchemaDrift)",
                "Err(MnemeError::SchemaDrift)",
                "return Err(MnemeError::SchemaDrift)",
                "map_err(|_| MnemeError::SchemaDrift)",
                "return Err(MnemeError::UnknownField",
            ] {
                assert!(
                    !section.contains(forbidden),
                    "stored root wire decoder should route `{forbidden}` through named classifiers"
                );
            }
        }

        for forbidden in [
            "return Err(MnemeError::UnsupportedVersion",
            "Err(MnemeError::UnsupportedVersion",
        ] {
            assert!(
                !invariants.contains(forbidden),
                "stored root invariant validator should route `{forbidden}` through named classifiers"
            );
        }

        for required in [
            "enum RootWireFailure",
            "fn root_wire_failure_to_mneme(",
            "fn unsupported_root_version_error(",
            "fn root_field_key_error(",
            "fn root_unknown_field_error(",
            "fn missing_root_version_error(",
            "fn missing_root_dag_head_root_error(",
            "fn missing_root_key_index_root_error(",
            "fn missing_root_semantic_commit_error(",
            "fn missing_root_hlc_max_error(",
            "fn missing_root_prev_root_error(",
            "fn missing_root_preimage_hash_error(",
            "fn missing_root_signature_error(",
            "fn missing_root_sequence_error(",
            "fn root_u64_error(",
            "fn root_u16_width_error(",
            "fn root_fixed32_bytes_error(",
            "fn root_fixed32_length_error(",
            "fn root_fixed_slice_bytes_error(",
            "fn root_fixed_slice_length_error(",
            "fn root_signature_bytes_error(",
            "fn root_signature_length_error(",
            "RootWireFailure::UnsupportedVersion",
            "RootWireFailure::FieldKey",
            "RootWireFailure::UnknownField",
            "RootWireFailure::MissingVersion",
            "RootWireFailure::MissingDagHeadRoot",
            "RootWireFailure::MissingKeyIndexRoot",
            "RootWireFailure::MissingSemanticCommit",
            "RootWireFailure::MissingHlcMax",
            "RootWireFailure::MissingPrevRoot",
            "RootWireFailure::MissingPreimageHash",
            "RootWireFailure::MissingSignature",
            "RootWireFailure::MissingSequence",
            "RootWireFailure::U64",
            "RootWireFailure::U16Width",
            "RootWireFailure::Fixed32Bytes",
            "RootWireFailure::Fixed32Length",
            "RootWireFailure::FixedSliceBytes",
            "RootWireFailure::FixedSliceLength",
            "RootWireFailure::SignatureBytes",
            "RootWireFailure::SignatureLength",
        ] {
            assert!(
                source.contains(required),
                "stored root wire failure classification should include `{required}`"
            );
        }
    }

    #[test]
    fn root_wire_failure_classifier_preserves_public_errors() {
        assert_eq!(
            root_wire_failure_to_mneme(RootWireFailure::UnsupportedVersion { version: 99 }),
            MnemeError::UnsupportedVersion { got: 99 }
        );
        assert_eq!(
            unsupported_root_version_error(99),
            MnemeError::UnsupportedVersion { got: 99 }
        );
        assert_eq!(
            root_wire_failure_to_mneme(RootWireFailure::UnknownField { field: 10 }),
            MnemeError::UnknownField { field: 10 }
        );
        assert_eq!(
            root_wire_failure_to_mneme(RootWireFailure::SignatureLength),
            MnemeError::RootSigInvalid
        );

        for failure in [
            RootWireFailure::FieldKey,
            RootWireFailure::MissingVersion,
            RootWireFailure::MissingDagHeadRoot,
            RootWireFailure::MissingKeyIndexRoot,
            RootWireFailure::MissingSemanticCommit,
            RootWireFailure::MissingHlcMax,
            RootWireFailure::MissingPrevRoot,
            RootWireFailure::MissingPreimageHash,
            RootWireFailure::MissingSignature,
            RootWireFailure::MissingSequence,
            RootWireFailure::U64,
            RootWireFailure::U16Width,
            RootWireFailure::Fixed32Bytes,
            RootWireFailure::Fixed32Length,
            RootWireFailure::FixedSliceBytes,
            RootWireFailure::FixedSliceLength,
            RootWireFailure::SignatureBytes,
        ] {
            assert_eq!(root_wire_failure_to_mneme(failure), MnemeError::SchemaDrift);
        }
    }

    #[test]
    fn root_wire_version_width_overflow_fails_closed() {
        let mut enc = Encoder::new();
        enc.begin_map(9).expect("begin map");
        enc.encode_unsigned(F_VERSION).expect("version key");
        enc.encode_unsigned(u64::from(u16::MAX) + 1)
            .expect("too-wide version");
        enc.encode_unsigned(F_DAG_HEAD_ROOT)
            .expect("dag_head_root key");
        enc.encode_bytes(&[0x11; 32]).expect("dag_head_root");
        enc.encode_unsigned(F_KEY_INDEX_ROOT)
            .expect("key_index_root key");
        enc.encode_bytes(&[0x22; 32]).expect("key_index_root");
        enc.encode_unsigned(F_SEMANTIC_COMMIT)
            .expect("semantic_commit key");
        enc.encode_bytes(&[0x33; 32]).expect("semantic_commit");
        enc.encode_unsigned(F_HLC_MAX).expect("hlc_max key");
        enc.encode_bytes(&[0x44; HLC_MAX_LEN]).expect("hlc_max");
        enc.encode_unsigned(F_PREV_ROOT).expect("prev_root key");
        enc.encode_bytes(&[0x55; 32]).expect("prev_root");
        enc.encode_unsigned(F_PREIMAGE_HASH)
            .expect("preimage_hash key");
        enc.encode_bytes(&[0x66; 32]).expect("preimage_hash");
        enc.encode_unsigned(F_SIGNATURE).expect("signature key");
        enc.encode_bytes(&[0x77; ED25519_SIG_LEN])
            .expect("signature");
        enc.encode_unsigned(F_SEQUENCE).expect("sequence key");
        enc.encode_unsigned(1).expect("sequence");
        let bytes = enc.finish();

        assert_eq!(StoredRoot::from_bytes(&bytes), Err(MnemeError::SchemaDrift));
    }
}
