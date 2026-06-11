//! Certified Counterfactual Replay (CCR) — weak mode (context counterfactual).
//!
//! `mneme replay` assembles a context from N fail-closed verified recalls under the
//! current signed root, then re-assembles it **without** one named entry, and emits a
//! signed, offline-verifiable certificate binding both context hashes to the root:
//! "under root R and this declared key procedure, the assembled context with and
//! without entry X is H_f / H_cf (differs: yes/no)".
//!
//! HONESTY BOUNDARY (do not weaken): weak mode proves the **context** counterfactual —
//! which verified memories entered the assembled context and that removing X changes it.
//! It does NOT prove model-output causation (that is strong mode, gated on deterministic
//! inference) and it NEVER proves semantic truth. Authenticated ≠ true.
//!
//! Wire: deterministic length-prefixed v1 layout, strict fail-closed decode (unknown
//! version, length mismatch, or trailing bytes ⇒ typed error). dCBOR alignment is a
//! follow-up once the field set freezes; the signature covers the full payload either way.

use mneme_core::MnemeError;
use mneme_crypto::{KeyPair, sign_message, verify_signature_bytes, verifying_key_from_bytes};

pub const REPLAY_CERT_VERSION: u16 = 1;
const PAYLOAD_DOMAIN: &[u8] = b"MNEME-replay-cert-v1";

pub const REPLAY_HONESTY: &str = "counterfactual context only: proves which verified memories \
entered the assembled context under the signed root and that removing the excluded entry \
changes it; not model-output causation (strong mode pending deterministic inference), not \
semantic truth — authenticated != true";

/// Offline-verifiable weak-mode CCR certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayCertV1 {
    pub root_seq: u64,
    pub root_preimage: [u8; 32],
    pub namespace: String,
    pub keys: Vec<String>,
    pub min_tier: u8,
    pub excluded: [u8; 32],
    pub factual_ids: Vec<[u8; 32]>,
    pub counterfactual_ids: Vec<[u8; 32]>,
    pub factual_hash: [u8; 32],
    pub counterfactual_hash: [u8; 32],
    pub differs: bool,
    pub operator_pk: [u8; 32],
    pub sig: [u8; 64],
}

/// Chained context hash over (id, body) pairs in recall order.
pub fn context_hash(entries: &[([u8; 32], Vec<u8>)]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"MNEME-replay-context-v1");
    h.update(&(entries.len() as u64).to_le_bytes());
    for (id, body) in entries {
        h.update(id);
        h.update(&(body.len() as u64).to_le_bytes());
        h.update(body);
    }
    *h.finalize().as_bytes()
}

pub(crate) fn put_str(out: &mut Vec<u8>, s: &str) -> Result<(), MnemeError> {
    let b = s.as_bytes();
    let len: u16 = b.len().try_into().map_err(|_| MnemeError::SchemaDrift)?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(b);
    Ok(())
}

pub(crate) fn put_id_list(out: &mut Vec<u8>, ids: &[[u8; 32]]) -> Result<(), MnemeError> {
    let len: u16 = ids.len().try_into().map_err(|_| MnemeError::SchemaDrift)?;
    out.extend_from_slice(&len.to_le_bytes());
    for id in ids {
        out.extend_from_slice(id);
    }
    Ok(())
}

impl ReplayCertV1 {
    fn payload(&self) -> Result<Vec<u8>, MnemeError> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(PAYLOAD_DOMAIN);
        out.extend_from_slice(&REPLAY_CERT_VERSION.to_le_bytes());
        out.extend_from_slice(&self.root_seq.to_le_bytes());
        out.extend_from_slice(&self.root_preimage);
        out.push(self.min_tier);
        put_str(&mut out, &self.namespace)?;
        let nkeys: u16 = self
            .keys
            .len()
            .try_into()
            .map_err(|_| MnemeError::SchemaDrift)?;
        out.extend_from_slice(&nkeys.to_le_bytes());
        for k in &self.keys {
            put_str(&mut out, k)?;
        }
        out.extend_from_slice(&self.excluded);
        put_id_list(&mut out, &self.factual_ids)?;
        put_id_list(&mut out, &self.counterfactual_ids)?;
        out.extend_from_slice(&self.factual_hash);
        out.extend_from_slice(&self.counterfactual_hash);
        out.push(u8::from(self.differs));
        out.extend_from_slice(&self.operator_pk);
        Ok(out)
    }

    /// Sign the payload with the operator key and produce the final wire bytes.
    pub fn sign_and_encode(mut self, operator: &KeyPair) -> Result<Vec<u8>, MnemeError> {
        self.operator_pk = operator.public_key_bytes();
        let payload = self.payload()?;
        self.sig = sign_message(operator.signing_key(), &payload);
        let mut wire = payload;
        wire.extend_from_slice(&self.sig);
        Ok(wire)
    }

    /// Strict fail-closed decode + signature + internal-consistency verification.
    ///
    /// `pinned_pk`: optional out-of-band operator public key; if provided it must match
    /// the embedded key (otherwise the certificate only proves integrity under the
    /// embedded key, which the caller must check out-of-band).
    pub fn verify(wire: &[u8], pinned_pk: Option<&[u8; 32]>) -> Result<Self, MnemeError> {
        let mut r = Reader::new(wire);
        r.expect(PAYLOAD_DOMAIN)?;
        let version = u16::from_le_bytes(r.take_arr::<2>()?);
        if version != REPLAY_CERT_VERSION {
            return Err(MnemeError::UnsupportedVersion { got: version });
        }
        let root_seq = u64::from_le_bytes(r.take_arr::<8>()?);
        let root_preimage = r.take_arr::<32>()?;
        let min_tier = r.take_arr::<1>()?[0];
        let namespace = r.take_str()?;
        let nkeys = u16::from_le_bytes(r.take_arr::<2>()?);
        let mut keys = Vec::with_capacity(usize::from(nkeys));
        for _ in 0..nkeys {
            keys.push(r.take_str()?);
        }
        let excluded = r.take_arr::<32>()?;
        let factual_ids = r.take_id_list()?;
        let counterfactual_ids = r.take_id_list()?;
        let factual_hash = r.take_arr::<32>()?;
        let counterfactual_hash = r.take_arr::<32>()?;
        let differs = match r.take_arr::<1>()?[0] {
            0 => false,
            1 => true,
            _ => return Err(MnemeError::SchemaDrift),
        };
        let operator_pk = r.take_arr::<32>()?;
        let payload_len = r.consumed();
        let sig = r.take_arr::<64>()?;
        r.expect_end()?;

        if let Some(pk) = pinned_pk {
            if pk != &operator_pk {
                return Err(MnemeError::RootSigInvalid);
            }
        }
        let vk = verifying_key_from_bytes(&operator_pk)?;
        verify_signature_bytes(&vk, &wire[..payload_len], &sig)?;

        // Internal consistency — every relation the certificate asserts must hold.
        let expected_cf: Vec<[u8; 32]> = factual_ids
            .iter()
            .copied()
            .filter(|id| id != &excluded)
            .collect();
        let excluded_present = factual_ids.iter().any(|id| id == &excluded);
        if counterfactual_ids != expected_cf
            || differs != excluded_present
            || differs != (factual_hash != counterfactual_hash)
        {
            return Err(MnemeError::SchemaDrift);
        }

        Ok(Self {
            root_seq,
            root_preimage,
            namespace,
            keys,
            min_tier,
            excluded,
            factual_ids,
            counterfactual_ids,
            factual_hash,
            counterfactual_hash,
            differs,
            operator_pk,
            sig,
        })
    }
}

/// Strict cursor: every read is bounds-checked; trailing bytes are rejected.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    pub(crate) fn consumed(&self) -> usize {
        self.pos
    }
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], MnemeError> {
        let end = self.pos.checked_add(n).ok_or(MnemeError::SchemaDrift)?;
        let s = self.buf.get(self.pos..end).ok_or(MnemeError::SchemaDrift)?;
        self.pos = end;
        Ok(s)
    }
    pub(crate) fn take_arr<const N: usize>(&mut self) -> Result<[u8; N], MnemeError> {
        let s = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(s);
        Ok(out)
    }
    pub(crate) fn expect(&mut self, tag: &[u8]) -> Result<(), MnemeError> {
        if self.take(tag.len())? != tag {
            return Err(MnemeError::SchemaDrift);
        }
        Ok(())
    }
    pub(crate) fn take_str(&mut self) -> Result<String, MnemeError> {
        let len = u16::from_le_bytes(self.take_arr::<2>()?);
        let bytes = self.take(usize::from(len))?;
        String::from_utf8(bytes.to_vec()).map_err(|_| MnemeError::SchemaDrift)
    }
    pub(crate) fn take_id_list(&mut self) -> Result<Vec<[u8; 32]>, MnemeError> {
        let len = u16::from_le_bytes(self.take_arr::<2>()?);
        let mut out = Vec::with_capacity(usize::from(len));
        for _ in 0..len {
            out.push(self.take_arr::<32>()?);
        }
        Ok(out)
    }
    pub(crate) fn expect_end(&self) -> Result<(), MnemeError> {
        if self.pos != self.buf.len() {
            return Err(MnemeError::SchemaDrift);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(operator: &KeyPair) -> ReplayCertV1 {
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        let factual = vec![(a, b"alpha".to_vec()), (b, b"beta".to_vec())];
        let counterfactual = vec![(a, b"alpha".to_vec())];
        ReplayCertV1 {
            root_seq: 7,
            root_preimage: [0xab; 32],
            namespace: "user".into(),
            keys: vec!["k1".into(), "k2".into()],
            min_tier: 2,
            excluded: b,
            factual_ids: vec![a, b],
            counterfactual_ids: vec![a],
            factual_hash: context_hash(&factual),
            counterfactual_hash: context_hash(&counterfactual),
            differs: true,
            operator_pk: operator.public_key_bytes(),
            sig: [0; 64],
        }
    }

    #[test]
    fn roundtrip_sign_verify() {
        let op = KeyPair::from_seed([7u8; 32]);
        let wire = sample(&op).sign_and_encode(&op).expect("encode");
        let cert = ReplayCertV1::verify(&wire, Some(&op.public_key_bytes())).expect("verify clean");
        assert!(cert.differs);
        assert_eq!(cert.keys, vec!["k1".to_string(), "k2".to_string()]);
    }

    #[test]
    fn every_byte_flip_fails_closed() {
        let op = KeyPair::from_seed([7u8; 32]);
        let wire = sample(&op).sign_and_encode(&op).expect("encode");
        for i in 0..wire.len() {
            let mut bad = wire.clone();
            bad[i] ^= 0x01;
            assert!(
                ReplayCertV1::verify(&bad, Some(&op.public_key_bytes())).is_err(),
                "byte flip at {i} must fail closed"
            );
        }
    }

    #[test]
    fn truncation_and_trailing_fail_closed() {
        let op = KeyPair::from_seed([7u8; 32]);
        let wire = sample(&op).sign_and_encode(&op).expect("encode");
        assert!(ReplayCertV1::verify(&wire[..wire.len() - 1], None).is_err());
        let mut extra = wire.clone();
        extra.push(0);
        assert!(ReplayCertV1::verify(&extra, None).is_err());
    }

    #[test]
    fn wrong_pinned_pk_rejected() {
        let op = KeyPair::from_seed([7u8; 32]);
        let other = KeyPair::from_seed([8u8; 32]);
        let wire = sample(&op).sign_and_encode(&op).expect("encode");
        assert!(matches!(
            ReplayCertV1::verify(&wire, Some(&other.public_key_bytes())),
            Err(MnemeError::RootSigInvalid)
        ));
    }

    #[test]
    fn inconsistent_relations_rejected_even_if_signed() {
        let op = KeyPair::from_seed([7u8; 32]);
        let mut c = sample(&op);
        c.differs = false; // contradicts excluded-present and hash inequality
        let wire = c.sign_and_encode(&op).expect("encode");
        assert!(matches!(
            ReplayCertV1::verify(&wire, None),
            Err(MnemeError::SchemaDrift)
        ));
    }
}
