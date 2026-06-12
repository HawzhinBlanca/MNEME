//! Core types, errors, canonical serialization, and content addressing (Wave 0/1).

pub mod accountability;
pub mod cognition_bounds;
pub mod context;
pub mod dcbor;
pub mod domain;
pub mod embedding;
pub mod enclave;
pub mod error;
pub mod hex;
pub mod hlc;
pub mod interface;
pub mod object;
pub mod object_path;
pub mod output;
pub mod types;

pub use accountability::{
    ACTION_RECEIPT_VERSION, ActionReceipt, FORGET_PROOF_VERSION, ForgetProof,
    decode_action_receipt, decode_forget_proof, encode_action_receipt, encode_forget_proof,
};
pub use cognition_bounds::{
    EXACT_DOMINANCE_FLOOR_HONESTY, FLOOR_ATTRIBUTION_HONESTY, FLOOR_GAP_HONESTY,
    NON_USE_EPOCH_FLOOR_HONESTY, computational_online_floor_queries, log2_ceil,
    open_log_log_gap_factor, smt_recall_within_named_gap,
};
pub use context::{
    CONTEXT_ATTESTATION_VERSION, decode_context_consumption_attestation,
    encode_context_consumption_attestation,
};
pub use dcbor::{
    CborValue, DcborDecode, DcborEncode, Decoder, Encoder, assert_canonical, decode_strict,
    encode_canonical, from_bytes_strict, fuzz_dcbor_decode, to_bytes_canonical,
};
pub use domain::{
    DomainTag, hash_action_receipt_preimage, hash_cap, hash_certified_memory_set, hash_ckpt,
    hash_context_assembled, hash_dag, hash_model_output, hash_obj, hash_receipt_preimage,
    hash_root_preimage, hash_sem_preimage, hash_smt_internal, hash_smt_leaf,
};
pub use embedding::FixedPointEmbedding;
pub use enclave::{
    ENCLAVE_REPORT_PLACEHOLDER_STATUS, ENCLAVE_REPORT_PLACEHOLDER_VERSION,
    EnclaveReportPlaceholder, decode_enclave_report_placeholder, encode_enclave_report_placeholder,
};
pub use error::MnemeError;
pub use hex::decode_hex32;
pub use hlc::{Hlc, NodeId, cmp_wire};
pub use interface::{
    AsOf, AssemblyProfile, COGNITION_CERT_VERSION, COGNITION_CERT_VERSION_V2_DRAFT,
    CONTRACT_VERSION, CandidateProvenance, Capability, Caveat, ConsistencyProof,
    ContextConsumptionAttestation, DistanceMetric, Draft, Entry, ForgetMode, ForgetTarget,
    LogicalKey, MerkleProof, NonMembershipProof, ObjectId, ObjectRef, OutputBinding, Procedure,
    ProcedureAlgo, ProvenanceFilter, Query, Receipt, RetrievalProofLevel, Root, RootPreimage,
    SyncMessage, TrustTier, VerificationObject,
};
pub use object::{
    EXT_EMBARGO_ROUND, EXT_TLOCK_KEY_CIPHERTEXT, EXT_VALID_TIME_MS, HlcWire, MemoryKind,
    OBJECT_VERSION, ObjectRecord, PayloadEnc, embargo_from_ext, ext_map_with_embargo,
    ext_map_with_valid_time, valid_time_from_ext,
};
pub use object_path::decode_content_addressed_object_path;
pub use output::{OUTPUT_BINDING_VERSION, decode_output_binding, encode_output_binding};
