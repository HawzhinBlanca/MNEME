//! Provably-complete top-k retrieval (CR-1..CR-7).
//!
//! Proves **completeness of retrieval** (no closer neighbor was hidden), not semantic truth.
//! JL projection (CR-5) is a research frontier with an explicit conservative ceiling.

mod auth_tree;
mod geometry;
mod jl_projection;
mod prove;
mod verify;

pub use auth_tree::{AuthNodeProof, AuthPathStep, AuthenticatedBallTree};
pub use geometry::{BallTree, brute_force_knn, knn_with_pruning, squared_euclidean};
pub use jl_projection::{
    BeaconSeed, JlProjector, JlPruningMode, build_projected_tree, conservative_matches_exact,
    exact_pruning_matches_brute, frontier_fraction, jl_conservative_frontier_fraction,
    knn_with_jl_pruning,
};
pub use prove::{CompleteKnnProof, ExcludedLeaf, FrontierNode, ReturnedPoint, prove_complete_knn};
pub use verify::{COMPLETE_KNN_HONESTY, verify_complete_knn, verify_complete_knn_cost_bounded};
