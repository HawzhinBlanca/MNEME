//! Fixed-point embedding representation (blueprint §5.3, INV-10).

use crate::MnemeError;
use crate::domain::hash_sem_preimage;
use std::convert::TryFrom;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EmbeddingFailure {
    DeclaredDimensionMismatch,
    PairProcedureMismatch,
    DistanceTermOverflow,
    DistanceSumOverflow,
    DotProductTermOverflow,
    DotProductSumOverflow,
    QuantizedComponentOutOfRange,
    NonFiniteComponent,
}

fn embedding_failure_to_mneme(failure: EmbeddingFailure) -> MnemeError {
    match failure {
        EmbeddingFailure::DeclaredDimensionMismatch
        | EmbeddingFailure::PairProcedureMismatch
        | EmbeddingFailure::DistanceTermOverflow
        | EmbeddingFailure::DistanceSumOverflow
        | EmbeddingFailure::DotProductTermOverflow
        | EmbeddingFailure::DotProductSumOverflow
        | EmbeddingFailure::QuantizedComponentOutOfRange
        | EmbeddingFailure::NonFiniteComponent => MnemeError::SchemaDrift,
    }
}

fn embedding_declared_dimension_error() -> MnemeError {
    embedding_failure_to_mneme(EmbeddingFailure::DeclaredDimensionMismatch)
}

fn embedding_pair_procedure_error() -> MnemeError {
    embedding_failure_to_mneme(EmbeddingFailure::PairProcedureMismatch)
}

fn embedding_distance_term_overflow_error() -> MnemeError {
    embedding_failure_to_mneme(EmbeddingFailure::DistanceTermOverflow)
}

fn embedding_distance_sum_overflow_error() -> MnemeError {
    embedding_failure_to_mneme(EmbeddingFailure::DistanceSumOverflow)
}

fn embedding_dot_product_term_overflow_error() -> MnemeError {
    embedding_failure_to_mneme(EmbeddingFailure::DotProductTermOverflow)
}

fn embedding_dot_product_sum_overflow_error() -> MnemeError {
    embedding_failure_to_mneme(EmbeddingFailure::DotProductSumOverflow)
}

fn embedding_quantized_component_range_error() -> MnemeError {
    embedding_failure_to_mneme(EmbeddingFailure::QuantizedComponentOutOfRange)
}

fn embedding_non_finite_component_error() -> MnemeError {
    embedding_failure_to_mneme(EmbeddingFailure::NonFiniteComponent)
}

/// Quantized fixed-point embedding: `value = component * 2^scale`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedPointEmbedding {
    pub dim: u32,
    pub scale: i8,
    pub components: Vec<i16>,
}

impl FixedPointEmbedding {
    pub fn new(dim: u32, scale: i8, components: Vec<i16>) -> Result<Self, MnemeError> {
        let declared_dim =
            usize::try_from(dim).map_err(|_| embedding_declared_dimension_error())?;
        if declared_dim == 0 || components.len() != declared_dim {
            return Err(embedding_declared_dimension_error());
        }
        Ok(Self {
            dim,
            scale,
            components,
        })
    }

    /// `embedding_commit = BLAKE3(SEM ‖ dim_le ‖ scale ‖ concat(components_le_i16))`.
    pub fn commit(&self) -> [u8; 32] {
        hash_sem_preimage(self.dim.to_le_bytes(), self.scale, &self.components)
    }

    pub fn validate_shape(&self) -> Result<(), MnemeError> {
        let declared_dim =
            usize::try_from(self.dim).map_err(|_| embedding_declared_dimension_error())?;
        if declared_dim == 0 || self.components.len() != declared_dim {
            return Err(embedding_declared_dimension_error());
        }
        Ok(())
    }

    fn ensure_compatible_pair(&self, other: &Self) -> Result<(), MnemeError> {
        self.validate_shape()?;
        other.validate_shape()?;
        if self.dim != other.dim || self.scale != other.scale {
            return Err(embedding_pair_procedure_error());
        }
        Ok(())
    }

    /// Integer squared-L2 distance in the quantized domain (procedure-pinned).
    pub fn squared_l2_distance(&self, other: &Self) -> Result<i64, MnemeError> {
        self.ensure_compatible_pair(other)?;
        let mut sum: i64 = 0;
        for (a, b) in self.components.iter().zip(&other.components) {
            let diff = i64::from(*a) - i64::from(*b);
            sum = sum
                .checked_add(
                    diff.checked_mul(diff)
                        .ok_or_else(embedding_distance_term_overflow_error)?,
                )
                .ok_or_else(embedding_distance_sum_overflow_error)?;
        }
        Ok(sum)
    }

    /// Integer dot product for cosine-style procedures.
    pub fn dot_product(&self, other: &Self) -> Result<i64, MnemeError> {
        self.ensure_compatible_pair(other)?;
        let mut sum: i64 = 0;
        for (a, b) in self.components.iter().zip(&other.components) {
            sum = sum
                .checked_add(
                    i64::from(*a)
                        .checked_mul(i64::from(*b))
                        .ok_or_else(embedding_dot_product_term_overflow_error)?,
                )
                .ok_or_else(embedding_dot_product_sum_overflow_error)?;
        }
        Ok(sum)
    }

    /// Quantize float values once at write time: `component = round(value / 2^scale)`.
    pub fn quantize_from_f32(values: &[f32], scale: i8) -> Result<Self, MnemeError> {
        let factor = 2f32.powi(i32::from(scale));
        let components: Vec<i16> = values
            .iter()
            .map(|v| {
                let scaled = (*v / factor).round();
                if !scaled.is_finite() {
                    return Err(embedding_non_finite_component_error());
                }
                if scaled < f32::from(i16::MIN) || scaled > f32::from(i16::MAX) {
                    return Err(embedding_quantized_component_range_error());
                }
                Ok(scaled as i16)
            })
            .collect::<Result<_, _>>()?;
        let dim = u32::try_from(values.len()).map_err(|_| embedding_declared_dimension_error())?;
        Self::new(dim, scale, components)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_between_markers<'a>(
        source: &'a str,
        start_marker: &str,
        end_marker: &str,
        context: &str,
    ) -> &'a str {
        let start = source
            .find(start_marker)
            .unwrap_or_else(|| panic!("{context} should contain start marker `{start_marker}`"));
        let end_offset = source[start..]
            .find(end_marker)
            .unwrap_or_else(|| panic!("{context} should contain end marker `{end_marker}`"));
        &source[start..start + end_offset]
    }

    #[test]
    fn embedding_failures_are_classified_not_schema_drift_collapsed() {
        let source = include_str!("embedding.rs");
        let section = source_between_markers(
            source,
            "impl FixedPointEmbedding",
            "#[cfg(test)]",
            "fixed-point embedding impl",
        );

        for forbidden in [
            "ok_or(MnemeError::SchemaDrift)",
            "Err(MnemeError::SchemaDrift)",
            "return Err(MnemeError::SchemaDrift)",
            "map_err(|_| MnemeError::SchemaDrift)",
        ] {
            assert!(
                !section.contains(forbidden),
                "embedding operations should route `{forbidden}` through named classifiers"
            );
        }

        for required in [
            "enum EmbeddingFailure",
            "fn embedding_failure_to_mneme(",
            "fn embedding_declared_dimension_error(",
            "fn embedding_pair_procedure_error(",
            "fn embedding_distance_term_overflow_error(",
            "fn embedding_distance_sum_overflow_error(",
            "fn embedding_dot_product_term_overflow_error(",
            "fn embedding_dot_product_sum_overflow_error(",
            "fn embedding_quantized_component_range_error(",
            "fn embedding_non_finite_component_error(",
            "fn validate_shape(",
            "fn ensure_compatible_pair(",
            "EmbeddingFailure::DeclaredDimensionMismatch",
            "EmbeddingFailure::PairProcedureMismatch",
            "EmbeddingFailure::DistanceTermOverflow",
            "EmbeddingFailure::DistanceSumOverflow",
            "EmbeddingFailure::DotProductTermOverflow",
            "EmbeddingFailure::DotProductSumOverflow",
            "EmbeddingFailure::QuantizedComponentOutOfRange",
            "EmbeddingFailure::NonFiniteComponent",
        ] {
            assert!(
                source.contains(required),
                "embedding failure classification should include `{required}`"
            );
        }
    }

    #[test]
    fn embedding_failure_classifier_preserves_public_schema_drift() {
        for failure in [
            EmbeddingFailure::DeclaredDimensionMismatch,
            EmbeddingFailure::PairProcedureMismatch,
            EmbeddingFailure::DistanceTermOverflow,
            EmbeddingFailure::DistanceSumOverflow,
            EmbeddingFailure::DotProductTermOverflow,
            EmbeddingFailure::DotProductSumOverflow,
            EmbeddingFailure::QuantizedComponentOutOfRange,
            EmbeddingFailure::NonFiniteComponent,
        ] {
            assert_eq!(embedding_failure_to_mneme(failure), MnemeError::SchemaDrift);
        }
    }

    #[test]
    fn fixed_point_embedding_rejects_zero_dimension() {
        assert_eq!(
            FixedPointEmbedding::new(0, 0, Vec::new()),
            Err(MnemeError::SchemaDrift)
        );
    }

    #[test]
    fn quantize_rejects_empty_embedding() {
        assert_eq!(
            FixedPointEmbedding::quantize_from_f32(&[], 0),
            Err(MnemeError::SchemaDrift)
        );
    }

    #[test]
    fn distance_and_dot_reject_public_field_zero_dimension() {
        let malformed = FixedPointEmbedding {
            dim: 0,
            scale: 0,
            components: Vec::new(),
        };

        assert_eq!(
            malformed.squared_l2_distance(&malformed),
            Err(MnemeError::SchemaDrift)
        );
        assert_eq!(
            malformed.dot_product(&malformed),
            Err(MnemeError::SchemaDrift)
        );
    }

    #[test]
    fn distance_and_dot_reject_public_field_shape_mismatch() {
        let malformed = FixedPointEmbedding {
            dim: 2,
            scale: 0,
            components: vec![3],
        };
        let well_formed = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();

        assert_eq!(
            malformed.squared_l2_distance(&well_formed),
            Err(MnemeError::SchemaDrift)
        );
        assert_eq!(
            malformed.dot_product(&well_formed),
            Err(MnemeError::SchemaDrift)
        );
    }

    #[test]
    fn quantize_rejects_non_finite_values() {
        for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            assert_eq!(
                FixedPointEmbedding::quantize_from_f32(&[value], 0),
                Err(MnemeError::SchemaDrift)
            );
        }
    }

    #[test]
    fn embedding_commit_vector_dim3_scale_neg4() {
        let emb = FixedPointEmbedding::new(3, -4, vec![100, -50, 25]).unwrap();
        assert_eq!(
            hex(&emb.commit()),
            "0600dc7f9e36e467b3f8bb38baccf6d35fb119c5fd72e4e0489ec5a93cea6955"
        );
    }

    #[test]
    fn squared_l2_distance_vector() {
        let a = FixedPointEmbedding::new(2, 0, vec![3, 4]).unwrap();
        let b = FixedPointEmbedding::new(2, 0, vec![0, 0]).unwrap();
        assert_eq!(a.squared_l2_distance(&b).unwrap(), 25);
    }

    fn hex(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
