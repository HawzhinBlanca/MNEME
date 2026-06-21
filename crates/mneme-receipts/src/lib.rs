//! `mneme-receipts` — off-TCB library of MNEME's offline-verifiable receipt and
//! transparency-log types, lifted out of the `mneme` CLI binary (where they were
//! binary-private modules) so every product — Recall Ledger, CreditLedger,
//! Consent Vault, the Desk apps — can construct and verify them as a library,
//! without depending on the CLI.
//!
//! This crate is **outside** the verifier TCB (`mneme-verify`). It builds only on
//! `mneme-core` + `mneme-crypto` (Ed25519, BLAKE3, dCBOR) and adds no new crypto.
//!
//! ## Modules
//! - [`replay`]  — dCBOR reader/writer helpers + counterfactual `ReplayCertV1`
//! - [`mtl`]     — RFC 6962 single-operator transparency log + inclusion / consistency receipts
//! - [`shapley`] — signed CCR-Shapley memory-contribution certificates
//! - [`fcc`]     — forgetting-closure / certified-unlearning certificates
//!
//! ## Honesty boundary (load-bearing — never weaken)
//! Every type here proves integrity / provenance / authorization, or *logging* —
//! never semantic truth, never true nearest-neighbors, never model learning.
//! `authenticated != true`. The per-module `*_HONESTY` strings record the exact
//! limit of each artifact and are re-exported below so callers surface them.

pub mod fcc;
pub mod mtl;
pub mod replay;
pub mod shapley;

// Honesty strings — re-exported at the crate root so every consumer can surface
// the precise limit of the artifact it issues (CLI, daemon, apps, MCP).
pub use fcc::{FCC_HONESTY, UNLEARNING_HONESTY};
pub use mtl::MTL_HONESTY;
pub use replay::REPLAY_HONESTY;
pub use shapley::SHAPLEY_HONESTY;
