//! ROBR (Recall-to-Output Binding Receipt) reference verifier.

use crate::error::CrossrefError;
use ed25519_dalek::{Signature, VerifyingKey};

pub const ROBR_RECEIPT_VERSION: u16 = 1;
const PAYLOAD_DOMAIN: &[u8] = b"MNEME-robr-receipt-v1";
const ENVELOPE_DOMAIN: &[u8] = b"MNEME-robr-envelope-v1";
const CONTEXT_DOMAIN: &[u8] = b"MNEME-robr-context-v1";

pub fn context_hash(entries: &[([u8; 32], Vec<u8>)]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(CONTEXT_DOMAIN);
    h.update(&(entries.len() as u64).to_le_bytes());
    for (id, body) in entries {
        h.update(id);
        h.update(&(body.len() as u64).to_le_bytes());
        h.update(body);
    }
    *h.finalize().as_bytes()
}

pub fn envelope_hash(
    root_preimage: &[u8; 32],
    prompt_hash: &[u8; 32],
    weight_measurement: &[u8; 32],
    sampling_params: &str,
    context_hash: &[u8; 32],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(ENVELOPE_DOMAIN);
    h.update(root_preimage);
    h.update(prompt_hash);
    h.update(weight_measurement);
    let sp = sampling_params.as_bytes();
    h.update(&(sp.len() as u64).to_le_bytes());
    h.update(sp);
    h.update(context_hash);
    *h.finalize().as_bytes()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRobrReceipt {
    pub root_seq: u64,
    pub root_preimage: [u8; 32],
    pub prompt_hash: [u8; 32],
    pub weight_measurement: [u8; 32],
    pub sampling_params: String,
    pub context_ids: Vec<[u8; 32]>,
    pub context_hash: [u8; 32],
    pub envelope_hash: [u8; 32],
    pub output_token_commit: [u8; 32],
    pub operator_pk: [u8; 32],
    pub sig: [u8; 64],
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn consumed(&self) -> usize {
        self.pos
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], CrossrefError> {
        let end = self.pos.checked_add(n).ok_or(CrossrefError::SchemaDrift)?;
        let s = self
            .buf
            .get(self.pos..end)
            .ok_or(CrossrefError::SchemaDrift)?;
        self.pos = end;
        Ok(s)
    }
    fn take_arr<const N: usize>(&mut self) -> Result<[u8; N], CrossrefError> {
        let s = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(s);
        Ok(out)
    }
    fn expect(&mut self, tag: &[u8]) -> Result<(), CrossrefError> {
        if self.take(tag.len())? != tag {
            return Err(CrossrefError::SchemaDrift);
        }
        Ok(())
    }
    fn take_str(&mut self) -> Result<String, CrossrefError> {
        let len = u16::from_le_bytes(self.take_arr::<2>()?);
        let bytes = self.take(usize::from(len))?;
        String::from_utf8(bytes.to_vec()).map_err(|_| CrossrefError::SchemaDrift)
    }
    fn take_id_list(&mut self) -> Result<Vec<[u8; 32]>, CrossrefError> {
        let len = u16::from_le_bytes(self.take_arr::<2>()?);
        let mut out = Vec::with_capacity(usize::from(len));
        for _ in 0..len {
            out.push(self.take_arr::<32>()?);
        }
        Ok(out)
    }
    fn expect_end(&self) -> Result<(), CrossrefError> {
        if self.pos != self.buf.len() {
            return Err(CrossrefError::SchemaDrift);
        }
        Ok(())
    }
}

pub fn verify_robr_receipt(
    wire: &[u8],
    pinned_pk: Option<&[u8; 32]>,
) -> Result<StoredRobrReceipt, CrossrefError> {
    let mut r = Reader::new(wire);
    r.expect(PAYLOAD_DOMAIN)?;
    let version = u16::from_le_bytes(r.take_arr::<2>()?);
    if version != ROBR_RECEIPT_VERSION {
        return Err(CrossrefError::SchemaDrift);
    }
    let root_seq = u64::from_le_bytes(r.take_arr::<8>()?);
    let root_preimage = r.take_arr::<32>()?;
    let prompt_hash = r.take_arr::<32>()?;
    let weight_measurement = r.take_arr::<32>()?;
    let sampling_params = r.take_str()?;
    let context_ids = r.take_id_list()?;
    let context_hash = r.take_arr::<32>()?;
    let envelope_hash_field = r.take_arr::<32>()?;
    let output_token_commit = r.take_arr::<32>()?;
    let operator_pk = r.take_arr::<32>()?;
    let payload_len = r.consumed();
    let sig = r.take_arr::<64>()?;
    r.expect_end()?;

    if let Some(pk) = pinned_pk {
        if pk != &operator_pk {
            return Err(CrossrefError::SigInvalid);
        }
    }

    let vk = VerifyingKey::from_bytes(&operator_pk).map_err(|_| CrossrefError::SigInvalid)?;
    let signature = Signature::from_bytes(&sig);
    vk.verify_strict(&wire[..payload_len], &signature)
        .map_err(|_| CrossrefError::SigInvalid)?;

    let recomputed = envelope_hash(
        &root_preimage,
        &prompt_hash,
        &weight_measurement,
        &sampling_params,
        &context_hash,
    );
    if recomputed != envelope_hash_field {
        return Err(CrossrefError::SchemaDrift);
    }

    Ok(StoredRobrReceipt {
        root_seq,
        root_preimage,
        prompt_hash,
        weight_measurement,
        sampling_params,
        context_ids,
        context_hash,
        envelope_hash: envelope_hash_field,
        output_token_commit,
        operator_pk,
        sig,
    })
}
