//! Provably-complete top-k retrieval (CR-1..CR-4).
//!
//! Proves **completeness of retrieval** (no closer neighbor was hidden), not semantic truth.

mod auth_tree;
mod geometry;

pub use auth_tree::AuthenticatedBallTree;
pub use geometry::{BallTree, brute_force_knn, knn_with_pruning, squared_euclidean};
