//! Cryptographic forgetting: key-shredding + SMT tombstones (blueprint §9.5, §13.2).

#![forbid(unsafe_code)]
#![deny(warnings)]

mod absent;
#[cfg(feature = "experimental_redaction")]
#[path = "../../../experimental/redaction/mneme-forget-redact.rs"]
mod redact;
mod shred;

pub use absent::{prove_absent, verify_absence, verify_signed_root};
#[cfg(feature = "experimental_redaction")]
pub use redact::{
    RedactForgetInput, RedactOutcome, RedactionRecord, forget_redact, verify_object_identity,
    verify_redaction_record,
};
pub use shred::{
    ShredForgetInput, ShredOutcome, apply_shred_forget, forget_shred, object_id_for_key,
    payload_aad, payload_unreadable, shred_witness_commit, structure_intact,
};
