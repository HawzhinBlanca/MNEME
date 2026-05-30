//! Fixed-point embedding representation (blueprint §5.3, INV-10).

use crate::MnemeError;
use crate::domain::hash_sem_preimage;

/// Quantized fixed-point embedding: `value = component * 2^scale`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedPointEmbedding {
    pub dim: u32,
    pub scale: i8,
    pub components: Vec<i16>,
}

impl FixedPointEmbedding {
    pub fn new(dim: u32, scale: i8, components: Vec<i16>) -> Result<Self, MnemeError> {
        if components.len() != dim as usize {
            return Err(MnemeError::SchemaDrift);
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

    /// Integer squared-L2 distance in the quantized domain (procedure-pinned).
    pub fn squared_l2_distance(&self, other: &Self) -> Result<i64, MnemeError> {
        if self.dim != other.dim || self.scale != other.scale {
            return Err(MnemeError::SchemaDrift);
        }
        let mut sum: i64 = 0;
        for (a, b) in self.components.iter().zip(&other.components) {
            let diff = i64::from(*a) - i64::from(*b);
            sum = sum
                .checked_add(diff.checked_mul(diff).ok_or(MnemeError::SchemaDrift)?)
                .ok_or(MnemeError::SchemaDrift)?;
        }
        Ok(sum)
    }

    /// Integer dot product for cosine-style procedures.
    pub fn dot_product(&self, other: &Self) -> Result<i64, MnemeError> {
        if self.dim != other.dim || self.scale != other.scale {
            return Err(MnemeError::SchemaDrift);
        }
        let mut sum: i64 = 0;
        for (a, b) in self.components.iter().zip(&other.components) {
            sum = sum
                .checked_add(
                    i64::from(*a)
                        .checked_mul(i64::from(*b))
                        .ok_or(MnemeError::SchemaDrift)?,
                )
                .ok_or(MnemeError::SchemaDrift)?;
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
                if scaled < f32::from(i16::MIN) || scaled > f32::from(i16::MAX) {
                    return Err(MnemeError::SchemaDrift);
                }
                Ok(scaled as i16)
            })
            .collect::<Result<_, _>>()?;
        Self::new(values.len() as u32, scale, components)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
