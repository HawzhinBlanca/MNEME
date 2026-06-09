use mneme_core::MnemeError;
use thiserror::Error;

/// Index-layer errors outside the verifier TCB.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IndexError {
    #[error("object already indexed")]
    DuplicateObject,
    #[error("object not indexed")]
    ObjectNotIndexed,
    #[error("embedding shape invalid")]
    EmbeddingShape,
    #[error("semantic/ANN index not implemented")]
    SemanticNotImplemented,
}

impl From<MnemeError> for IndexError {
    fn from(err: MnemeError) -> Self {
        match err {
            MnemeError::SchemaDrift => IndexError::EmbeddingShape,
            _ => IndexError::ObjectNotIndexed,
        }
    }
}
