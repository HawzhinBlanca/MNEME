#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrossrefError {
    SerializationNonCanonical,
    SchemaDrift,
    SigInvalid,
    PathInvalid,
    CapDenied,
    CapExpired,
}

impl std::fmt::Display for CrossrefError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for CrossrefError {}
