//! Convergence certificate sidecar (VCP D1).
use crate::mset::ObjectMultiset;
use mneme_core::{CborValue, Decoder, Encoder, MnemeError};

pub const CONV_CERT_VERSION: u8 = 1;
pub const CONV_CERT_HONESTY: &str = concat!(
    "Convergence cert proves object-multiset equality only (MuHash/LtHash over Ristretto, ",
    "computational DLP+ROM) — NOT membership, NOT an accumulator, NOT semantic truth; ",
    "authenticated ≠ true; no soundness vs a corrupted or withholding signer; ",
    "complement to per-recall receipts (surrenders mid-epoch fail-closed — Connection 4); ",
    "equal commitments ⟹ equal multisets only under ECMH collision resistance; ",
    "snapshot-only merge may not converge full object sets until manifest-delta (D2/T5); ",
    "sidecar commitment is not yet bound in signed Root preimage",
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConvergenceVerify { Converged, VersionMismatch, KeyIndexRootMismatch, DagHeadRootMismatch, ObjectMsetMismatch }
impl ConvergenceVerify { pub fn is_converged(self) -> bool { matches!(self, Self::Converged) } }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConvergenceCert {
    pub version: u8, pub key_index_root: [u8; 32], pub dag_head_root: [u8; 32],
    pub object_mset_commit: [u8; 32], pub object_count: u64,
}

impl ConvergenceCert {
    pub fn build(key_index_root: [u8; 32], dag_head_root: [u8; 32], object_ids: impl IntoIterator<Item = [u8; 32]>) -> Self {
        let ids: Vec<[u8; 32]> = object_ids.into_iter().collect();
        let mset = ObjectMultiset::from_object_ids(ids.iter());
        Self { version: CONV_CERT_VERSION, key_index_root, dag_head_root, object_mset_commit: mset.commitment(), object_count: ids.len() as u64 }
    }
}

pub fn verify_convergence(local: &ConvergenceCert, peer: &ConvergenceCert) -> ConvergenceVerify {
    if local.version != peer.version { return ConvergenceVerify::VersionMismatch; }
    if local.key_index_root != peer.key_index_root { return ConvergenceVerify::KeyIndexRootMismatch; }
    if local.dag_head_root != peer.dag_head_root { return ConvergenceVerify::DagHeadRootMismatch; }
    if local.object_mset_commit != peer.object_mset_commit { return ConvergenceVerify::ObjectMsetMismatch; }
    ConvergenceVerify::Converged
}

fn encode_text_map(
    enc: &mut Encoder,
    mut entries: Vec<(&str, CborValue)>,
) -> Result<(), MnemeError> {
    entries.sort_by(|a, b| {
        let mut ea = Encoder::new();
        let mut eb = Encoder::new();
        ea.encode_text(a.0).expect("key");
        eb.encode_text(b.0).expect("key");
        ea.finish().cmp(&eb.finish())
    });
    enc.begin_map(entries.len() as u64)?;
    for (key, value) in entries {
        enc.encode_text(key)?;
        match value {
            CborValue::Unsigned(v) => enc.encode_unsigned(v)?,
            CborValue::Bytes(v) => enc.encode_bytes(&v)?,
            _ => return Err(MnemeError::SchemaDrift),
        }
    }
    Ok(())
}

pub fn encode_convergence_cert(cert: &ConvergenceCert) -> Result<Vec<u8>, MnemeError> {
    let mut enc = Encoder::new();
    encode_text_map(
        &mut enc,
        vec![
            ("dag_head_root", CborValue::Bytes(cert.dag_head_root.to_vec())),
            ("key_index_root", CborValue::Bytes(cert.key_index_root.to_vec())),
            ("object_count", CborValue::Unsigned(cert.object_count)),
            ("object_mset_commit", CborValue::Bytes(cert.object_mset_commit.to_vec())),
            ("version", CborValue::Unsigned(u64::from(cert.version))),
        ],
    )?;
    Ok(enc.finish())
}

pub fn decode_convergence_cert(bytes: &[u8]) -> Result<ConvergenceCert, MnemeError> {
    let mut dec = Decoder::new(bytes); let map = dec.decode_map()?;
    let mut version = None; let mut key_index_root = None; let mut dag_head_root = None;
    let mut object_mset_commit = None; let mut object_count = None;
    for (key, value) in map {
        match key.as_text().ok_or(MnemeError::SchemaDrift)? {
            "version" => version = Some(parse_u8_value(&value)?),
            "key_index_root" => key_index_root = Some(parse_fixed32_value(&value)?),
            "dag_head_root" => dag_head_root = Some(parse_fixed32_value(&value)?),
            "object_mset_commit" => object_mset_commit = Some(parse_fixed32_value(&value)?),
            "object_count" => object_count = Some(parse_u64_value(&value)?),
            _ => return Err(MnemeError::SchemaDrift),
        }
    }
    dec.ensure_consumed()?;
    Ok(ConvergenceCert {
        version: version.ok_or(MnemeError::SchemaDrift)?,
        key_index_root: key_index_root.ok_or(MnemeError::SchemaDrift)?,
        dag_head_root: dag_head_root.ok_or(MnemeError::SchemaDrift)?,
        object_mset_commit: object_mset_commit.ok_or(MnemeError::SchemaDrift)?,
        object_count: object_count.ok_or(MnemeError::SchemaDrift)?,
    })
}

fn parse_u8_value(value: &CborValue) -> Result<u8, MnemeError> { u8::try_from(parse_u64_value(value)?).map_err(|_| MnemeError::SchemaDrift) }
fn parse_u64_value(value: &CborValue) -> Result<u64, MnemeError> { value.as_u64().ok_or(MnemeError::SchemaDrift) }
fn parse_fixed32_value(value: &CborValue) -> Result<[u8; 32], MnemeError> {
    let b = value.as_bytes().ok_or(MnemeError::SchemaDrift)?; if b.len() != 32 { return Err(MnemeError::SchemaDrift); }
    let mut out = [0u8; 32]; out.copy_from_slice(b); Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn conv_cert_honesty_ceiling_t6() {
        assert!(CONV_CERT_HONESTY.contains("equality only"));
        assert!(CONV_CERT_HONESTY.contains("NOT membership"));
        assert!(CONV_CERT_HONESTY.contains("NOT an accumulator"));
        assert!(CONV_CERT_HONESTY.contains("complement to per-recall receipts"));
        assert!(CONV_CERT_HONESTY.contains("authenticated ≠ true"));
        assert!(CONV_CERT_HONESTY.contains("not yet bound in signed Root"));
    }
    #[test] fn conv_cert_wire_roundtrip() {
        let cert = ConvergenceCert::build([1u8; 32], [2u8; 32], [[3u8; 32], [4u8; 32]]);
        assert_eq!(decode_convergence_cert(&encode_convergence_cert(&cert).expect("encode")).expect("decode"), cert);
    }
    #[test] fn conv_cert_verify_detects_mset_mismatch() {
        let roots = ([0x11u8; 32], [0x22u8; 32]);
        assert_eq!(verify_convergence(&ConvergenceCert::build(roots.0, roots.1, [[0x01u8; 32]]), &ConvergenceCert::build(roots.0, roots.1, [[0x02u8; 32]])), ConvergenceVerify::ObjectMsetMismatch);
    }
    #[test] fn conv_cert_verify_converged_same_multiset() {
        let roots = ([0x11u8; 32], [0x22u8; 32]); let ids = [[0xaa_u8; 32], [0xbb_u8; 32]];
        assert_eq!(verify_convergence(&ConvergenceCert::build(roots.0, roots.1, ids), &ConvergenceCert::build(roots.0, roots.1, ids.iter().copied().rev())), ConvergenceVerify::Converged);
    }
}
