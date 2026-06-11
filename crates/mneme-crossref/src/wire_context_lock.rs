use crate::dcbor::{CborValue, Decoder};
use crate::error::CrossrefError;
pub const F_SET_COMMIT: u64 = 1;
pub const F_CONTEXT_COMMIT: u64 = 2;
pub const F_PROOF_BYTES: u64 = 3;
pub const CONTEXT_SET_LOCK_PROOF_LEN: usize = 96;
pub const PUBLIC_COMMIT_LEN: usize = 32;
pub const CONTEXT_SET_LOCK_HONESTY: &str = "Context-set lock scaffold: crossref wire shape only; not semantic truth, not recall_verified TCB.";
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContextSetLockSidecar {
    pub set_commit: [u8; 32],
    pub context_commit: [u8; 32],
    pub proof_bytes: Vec<u8>,
}
pub fn decode_context_set_lock_sidecar(
    bytes: &[u8],
) -> Result<ContextSetLockSidecar, CrossrefError> {
    let mut dec = Decoder::new(bytes);
    let map = dec.decode_map()?;
    dec.ensure_consumed()?;
    let mut set_commit = None;
    let mut context_commit = None;
    let mut proof_bytes = None;
    for (k, v) in map {
        match k.as_u64().ok_or(CrossrefError::SchemaDrift)? {
            F_SET_COMMIT => set_commit = Some(parse_fixed32(&v)?),
            F_CONTEXT_COMMIT => context_commit = Some(parse_fixed32(&v)?),
            F_PROOF_BYTES => {
                proof_bytes = Some(v.as_bytes().ok_or(CrossrefError::SchemaDrift)?.to_vec())
            }
            _ => return Err(CrossrefError::SchemaDrift),
        }
    }
    Ok(ContextSetLockSidecar {
        set_commit: set_commit.ok_or(CrossrefError::SchemaDrift)?,
        context_commit: context_commit.ok_or(CrossrefError::SchemaDrift)?,
        proof_bytes: proof_bytes.ok_or(CrossrefError::SchemaDrift)?,
    })
}
pub fn verify_context_set_lock_stub(s: &ContextSetLockSidecar) -> Result<(), CrossrefError> {
    if s.proof_bytes.len() != CONTEXT_SET_LOCK_PROOF_LEN || s.proof_bytes[0..32] != s.context_commit
    {
        return Err(CrossrefError::SchemaDrift);
    }
    Ok(())
}
fn parse_fixed32(v: &CborValue) -> Result<[u8; 32], CrossrefError> {
    let b = v.as_bytes().ok_or(CrossrefError::SchemaDrift)?;
    if b.len() != 32 {
        return Err(CrossrefError::SchemaDrift);
    }
    let mut o = [0u8; 32];
    o.copy_from_slice(b);
    Ok(o)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::dcbor::Encoder;
    #[test]
    fn decode_sidecar_roundtrip_map() {
        let mut enc = Encoder::new();
        enc.begin_map(3).unwrap();
        enc.encode_unsigned(F_SET_COMMIT).unwrap();
        enc.encode_bytes(&[1; 32]).unwrap();
        enc.encode_unsigned(F_CONTEXT_COMMIT).unwrap();
        enc.encode_bytes(&[2; 32]).unwrap();
        enc.encode_unsigned(F_PROOF_BYTES).unwrap();
        let mut p = vec![2; 32];
        p.extend_from_slice(&[3; 32]);
        p.extend_from_slice(&[4; 32]);
        enc.encode_bytes(&p).unwrap();
        verify_context_set_lock_stub(&decode_context_set_lock_sidecar(&enc.finish()).unwrap())
            .unwrap();
    }
    #[test]
    fn stub_rejects_mismatched_context_in_proof_prefix() {
        let s = ContextSetLockSidecar {
            set_commit: [0xAA; 32],
            context_commit: [0xBB; 32],
            proof_bytes: vec![0xCC; 96],
        };
        assert!(verify_context_set_lock_stub(&s).is_err());
    }
}
