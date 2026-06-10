//! Provably-complete top-k retrieval — exact geometry phase (CR-1).

mod geometry;

pub use geometry::{BallTree, brute_force_knn, knn_with_pruning, squared_euclidean};
