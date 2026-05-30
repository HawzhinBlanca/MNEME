#![forbid(unsafe_code)]
#![deny(warnings)]

//! Fail-closed verifier TCB (blueprint §9.3, §10, INV-5, INV-9).

mod proof;
mod recall;
mod root;
mod semantic;
mod store;

pub use proof::verify_membership_proof;
pub use recall::{RecallContext, RecallInput, verify_recall};
pub use root::verify_root;
pub use semantic::{
    HONESTY_PROCEDURE, SemanticRecallInput, verify_semantic_recall, verify_semantic_receipt,
};
pub use store::{RootReport, SignatureOnlyHead, verify_signed_head_only, verify_store};

/// TCB line budget (§17.6). Raise only with invariant justification.
pub const TCB_LINE_BUDGET: usize = 500;
