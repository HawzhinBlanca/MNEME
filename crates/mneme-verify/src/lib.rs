#![forbid(unsafe_code)]
#![deny(warnings)]

mod proof;
mod recall;
mod root;
#[cfg(feature = "experimental_semantic")]
#[path = "../../../experimental/semantic-retrieval/mneme-verify-semantic.rs"]
mod semantic;
mod store;

pub use proof::verify_membership_proof;
pub use recall::{RecallContext, RecallInput, verify_recall};
pub use root::verify_root;
#[cfg(feature = "experimental_semantic")]
pub use semantic::{
    HONESTY_PROCEDURE, SemanticRecallInput, verify_semantic_recall, verify_semantic_receipt,
};
pub use store::{RootReport, SignatureOnlyHead, verify_signed_head_only, verify_store};

pub const TCB_LINE_BUDGET: usize = 481;
