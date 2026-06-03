//! Independent reference implementation for Appendix B cross-implementation vectors.
//!
//! Does not depend on `mneme-core` or other MNEME implementation crates — only
//! cryptographic primitives and a vendored MNEME-dCBOR subset.

#![deny(warnings)]

pub mod dcbor;
pub mod domain;
pub mod error;
pub mod key;
pub mod mst_merge;
pub mod object_fixture;
pub mod procedure;
pub mod semantic_commit;
pub mod smt;
pub mod wire_cap;
pub mod wire_cert;
pub mod wire_root;

pub use error::CrossrefError;

pub fn vectors_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../proof/vectors")
}
