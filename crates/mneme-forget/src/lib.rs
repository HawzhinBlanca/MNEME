//! Cryptographic forgetting: key-shredding + SMT tombstones (blueprint §9.5, §13.2).

#![forbid(unsafe_code)]
#![deny(warnings)]

mod absent;
mod redact;
mod shred;

pub use absent::{prove_absent, verify_absence, verify_signed_root};
pub use redact::{
    RedactForgetInput, RedactOutcome, RedactionRecord, forget_redact, verify_object_identity,
    verify_redaction_record,
};
pub use shred::{
    ShredForgetInput, ShredOutcome, apply_shred_forget, forget_shred, object_id_for_key,
    payload_aad, payload_unreadable, structure_intact,
};
