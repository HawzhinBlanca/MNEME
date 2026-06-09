//! Integer distances for procedure P (blueprint §5.3, §6.1, INV-10).

use mneme_core::{DistanceMetric, FixedPointEmbedding, MnemeError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DistanceFailure {
    CosineNegationOverflow,
}

fn distance_failure_to_mneme(failure: DistanceFailure) -> MnemeError {
    match failure {
        DistanceFailure::CosineNegationOverflow => MnemeError::SchemaDrift,
    }
}

fn cosine_distance_negation_overflow_error() -> MnemeError {
    distance_failure_to_mneme(DistanceFailure::CosineNegationOverflow)
}

fn cosine_distance_from_dot(dot: i64) -> Result<i64, MnemeError> {
    dot.checked_neg()
        .ok_or_else(cosine_distance_negation_overflow_error)
}

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
            cosine_distance_from_dot(dot)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn distance_production_source() -> &'static str {
        include_str!("distance.rs")
            .split_once("#[cfg(test)]")
            .map(|(production, _tests)| production)
            .expect("distance.rs should keep tests after production code")
    }

    #[test]
    fn distance_failures_are_classified_not_schema_drift_collapsed() {
        let production = distance_production_source();

        for forbidden in [
            "ok_or(MnemeError::SchemaDrift)",
            "Err(MnemeError::SchemaDrift)",
            "return Err(MnemeError::SchemaDrift)",
            "map_err(|_| MnemeError::SchemaDrift)",
        ] {
            assert!(
                !production.contains(forbidden),
                "distance production code still collapses directly through {forbidden}"
            );
        }

        for required in [
            "enum DistanceFailure",
            "fn distance_failure_to_mneme(",
            "fn cosine_distance_negation_overflow_error(",
            "fn cosine_distance_from_dot(",
            "DistanceFailure::CosineNegationOverflow",
        ] {
            assert!(
                production.contains(required),
                "distance production code is missing typed classifier marker {required}"
            );
        }
    }

    #[test]
    fn distance_failure_classifier_preserves_public_schema_drift() {
        assert_eq!(
            distance_failure_to_mneme(DistanceFailure::CosineNegationOverflow),
            MnemeError::SchemaDrift
        );
        assert_eq!(
            cosine_distance_negation_overflow_error(),
            MnemeError::SchemaDrift
        );
    }

    #[test]
    fn cosine_distance_from_dot_rejects_i64_min() {
        assert_eq!(
            cosine_distance_from_dot(i64::MIN),
            Err(MnemeError::SchemaDrift)
        );
    }

    #[test]
    fn cosine_distance_from_dot_negates_regular_dot_product() {
        assert_eq!(cosine_distance_from_dot(42), Ok(-42));
        assert_eq!(cosine_distance_from_dot(-7), Ok(7));
    }

    #[test]
    fn integer_distance_cosine_uses_negated_dot_product() {
        let query = FixedPointEmbedding::new(2, 0, vec![3, -2]).expect("valid query embedding");
        let stored = FixedPointEmbedding::new(2, 0, vec![4, 5]).expect("valid stored embedding");

        assert_eq!(
            integer_distance(DistanceMetric::CosineI64, &query, &stored),
            Ok(-2)
        );
    }
}
