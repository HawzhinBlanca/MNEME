//! Integer distances for procedure P (blueprint §5.3, §6.1, INV-10).

use mneme_core::{DistanceMetric, FixedPointEmbedding, MnemeError};

/// Compute pinned integer distance between query and stored embedding.
pub fn integer_distance(
    metric: DistanceMetric,
    query: &FixedPointEmbedding,
    stored: &FixedPointEmbedding,
) -> Result<i64, MnemeError> {
    match metric {
        DistanceMetric::SquaredL2I64 => query.squared_l2_distance(stored),
        DistanceMetric::CosineI64 => {
            // Higher dot product = closer; negate so sort-by-asc works like distance.
            let dot = query.dot_product(stored)?;
            dot.checked_neg().ok_or(MnemeError::SchemaDrift)
        }
    }
}
