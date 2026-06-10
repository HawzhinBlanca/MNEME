//! Provably-complete top-k retrieval (CR-1..CR-4).
//!
//! Proves **completeness of retrieval** (no closer neighbor was hidden), not semantic truth.

mod auth_tree;
mod geometry;
mod prove;
mod verify;

pub use auth_tree::AuthenticatedBallTree;
pub use geometry::{BallTree, brute_force_knn, knn_with_pruning, squared_euclidean};
pub use prove::{CompleteKnnProof, ExcludedLeaf, FrontierNode, ReturnedPoint, prove_complete_knn};
pub use verify::{COMPLETE_KNN_HONESTY, verify_complete_knn, verify_complete_knn_cost_bounded};
