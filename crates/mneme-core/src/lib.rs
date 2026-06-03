//! Core types, errors, canonical serialization, and content addressing (Wave 0/1).

pub mod accountability;
pub mod context;
pub mod dcbor;
pub mod domain;
pub mod embedding;
pub mod error;
pub mod hex;
pub mod hlc;
pub mod interface;
pub mod object;
pub mod types;

pub use accountability::{
    ACTION_RECEIPT_VERSION, ActionReceipt, FORGET_PROOF_VERSION, ForgetProof,
    decode_action_receipt, decode_forget_proof, encode_action_receipt, encode_forget_proof,
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
    DomainTag, hash_cap, hash_certified_memory_set, hash_ckpt, hash_context_assembled, hash_dag,
    hash_obj, hash_receipt_preimage, hash_root_preimage, hash_sem_preimage, hash_smt_internal,
    hash_smt_leaf,
};
pub use embedding::FixedPointEmbedding;
pub use error::MnemeError;
pub use hex::decode_hex32;
pub use hlc::{Hlc, NodeId};
pub use interface::{
    AsOf, AssemblyProfile, COGNITION_CERT_VERSION, CONTRACT_VERSION, CandidateProvenance,
    Capability, Caveat, ConsistencyProof, ContextConsumptionAttestation, DistanceMetric, Draft,
    Entry, ForgetMode, ForgetTarget, LogicalKey, MerkleProof, NonMembershipProof, ObjectId,
    ObjectRef, Procedure, ProcedureAlgo, ProvenanceFilter, Query, Receipt, RetrievalProofLevel,
    Root, RootPreimage, SyncMessage, TrustTier, VerificationObject,
};
pub use object::{
    EXT_VALID_TIME_MS, HlcWire, MemoryKind, OBJECT_VERSION, ObjectRecord, PayloadEnc,
    ext_map_with_valid_time, valid_time_from_ext,
};
