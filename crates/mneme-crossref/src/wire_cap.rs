//! Capability wire decode + cap_id / sig-chain verification (reference path).

use crate::dcbor::{CborValue, DcborEncode, Decoder, Encoder, encode_canonical};
use crate::domain::hash_cap;
use crate::error::CrossrefError;
use ed25519_dalek::{Signature, VerifyingKey};

pub const SIG_LEN: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hlc {
    pub wall_ms: u64,
    pub counter: u32,
    pub node_id: [u8; 16],
}

impl Hlc {
    pub fn is_before(&self, other: &Self) -> bool {
        (self.wall_ms, self.counter, &self.node_id) < (other.wall_ms, other.counter, &other.node_id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Caveat {
    NotAfter(Hlc),
    CreatedBefore(Hlc),
    NamespacePrefix(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capability {
    pub issuer: [u8; 32],
    pub subject: [u8; 32],
    pub namespaces: Vec<String>,
    pub kinds: Vec<u8>,
    pub tier_max: u8,
    pub tier_default: u8,
    pub permissions: u8,
    pub caveats: Vec<Caveat>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapPreimage {
    pub issuer: [u8; 32],
    pub subject: [u8; 32],
    pub namespaces: Vec<String>,
    pub kinds: Vec<u8>,
    pub tier_max: u8,
    pub tier_default: u8,
    pub permissions: u8,
    pub caveats: Vec<Caveat>,
}

impl DcborEncode for CapPreimage {
    fn dcbor_encode(&self, enc: &mut Encoder) -> Result<(), CrossrefError> {
        enc.begin_map(8)?;
        encode_u8_array(enc, "kinds", &self.kinds)?;
        enc.encode_text("issuer")?;
        enc.encode_bytes(&self.issuer)?;
        encode_caveats(enc, &self.caveats)?;
        enc.encode_text("subject")?;
        enc.encode_bytes(&self.subject)?;
        enc.encode_text("tier_max")?;
        enc.encode_unsigned(u64::from(self.tier_max))?;
        encode_text_array(enc, "namespaces", &self.namespaces)?;
        enc.encode_text("permissions")?;
        enc.encode_unsigned(u64::from(self.permissions))?;
        enc.encode_text("tier_default")?;
        enc.encode_unsigned(u64::from(self.tier_default))?;
        Ok(())
    }
}

impl Capability {
    pub fn decode(bytes: &[u8]) -> Result<Self, CrossrefError> {
        let mut dec = Decoder::new(bytes);
        let map = dec.decode_map()?;
        dec.ensure_consumed()?;
        let mut issuer = None;
        let mut subject = None;
        let mut namespaces = None;
        let mut kinds = None;
        let mut tier_max = None;
        let mut tier_default = None;
        let mut permissions = None;
        let mut caveats = None;
        let mut signature = None;
        for (key, value) in map {
            let name = key.as_text().ok_or(CrossrefError::SchemaDrift)?;
            match name {
                "caveats" => caveats = Some(decode_caveats(&value)?),
                "issuer" => issuer = Some(parse_fixed32(&value)?),
                "kinds" => kinds = Some(parse_u8_array(&value)?),
                "namespaces" => namespaces = Some(parse_text_array(&value)?),
                "permissions" => permissions = Some(parse_u8(&value)?),
                "signature" => signature = Some(parse_bytes(&value)?),
                "subject" => subject = Some(parse_fixed32(&value)?),
                "tier_default" => tier_default = Some(parse_u8(&value)?),
                "tier_max" => tier_max = Some(parse_u8(&value)?),
                _ => return Err(CrossrefError::SchemaDrift),
            }
        }
        Ok(Self {
            issuer: issuer.ok_or(CrossrefError::SchemaDrift)?,
            subject: subject.ok_or(CrossrefError::SchemaDrift)?,
            namespaces: namespaces.ok_or(CrossrefError::SchemaDrift)?,
            kinds: kinds.ok_or(CrossrefError::SchemaDrift)?,
            tier_max: tier_max.ok_or(CrossrefError::SchemaDrift)?,
            tier_default: tier_default.ok_or(CrossrefError::SchemaDrift)?,
            permissions: permissions.ok_or(CrossrefError::SchemaDrift)?,
            caveats: caveats.unwrap_or_default(),
            signature: signature.ok_or(CrossrefError::SchemaDrift)?,
        })
    }

    pub fn cap_id_for_caveats(&self, caveat_count: usize) -> Result<[u8; 32], CrossrefError> {
        let mut preimage = CapPreimage {
            issuer: self.issuer,
            subject: self.subject,
            namespaces: self.namespaces.clone(),
            kinds: self.kinds.clone(),
            tier_max: self.tier_max,
            tier_default: self.tier_default,
            permissions: self.permissions,
            caveats: self.caveats.clone(),
        };
        preimage.caveats.truncate(caveat_count);
        let canonical = encode_canonical(&preimage)?;
        Ok(hash_cap(&canonical))
    }

    pub fn sig_chain(&self) -> Result<Vec<[u8; SIG_LEN]>, CrossrefError> {
        if self.signature.is_empty() || self.signature.len() % SIG_LEN != 0 {
            return Err(CrossrefError::SchemaDrift);
        }
        self.signature
            .chunks_exact(SIG_LEN)
            .map(|c| c.try_into().map_err(|_| CrossrefError::SchemaDrift))
            .collect()
    }

    pub fn verify_sig_chain(&self) -> Result<(), CrossrefError> {
        let chain = self.sig_chain()?;
        let issuer_pk =
            VerifyingKey::from_bytes(&self.issuer).map_err(|_| CrossrefError::CapDenied)?;
        let subject_pk =
            VerifyingKey::from_bytes(&self.subject).map_err(|_| CrossrefError::CapDenied)?;
        for (i, sig_bytes) in chain.iter().enumerate() {
            let caveat_count = self
                .caveats
                .len()
                .saturating_sub(chain.len() - 1)
                .saturating_add(i);
            let cap_id = self.cap_id_for_caveats(caveat_count)?;
            let pk = if i == 0 { &issuer_pk } else { &subject_pk };
            let sig = Signature::from_bytes(sig_bytes);
            pk.verify_strict(&cap_id, &sig)
                .map_err(|_| CrossrefError::CapDenied)?;
        }
        Ok(())
    }

    pub fn evaluate_not_after(&self, now: &Hlc) -> Result<(), CrossrefError> {
        for caveat in &self.caveats {
            if let Caveat::NotAfter(limit) = caveat {
                if !now.is_before(limit) {
                    return Err(CrossrefError::CapExpired);
                }
            }
        }
        Ok(())
    }
}

pub fn verify_committed_capability(
    bytes: &[u8],
    issuer_pubkey: &[u8; 32],
    expected_cap_id_hex: &str,
    sig_chain_len: usize,
) -> Result<(), CrossrefError> {
    let cap = Capability::decode(bytes)?;
    if cap.issuer != *issuer_pubkey {
        return Err(CrossrefError::CapDenied);
    }
    let expected_id = crate::wire_root::hex32(expected_cap_id_hex)?;
    let cap_id = cap.cap_id_for_caveats(cap.caveats.len())?;
    if cap_id != expected_id {
        return Err(CrossrefError::SchemaDrift);
    }
    if cap.sig_chain()?.len() != sig_chain_len {
        return Err(CrossrefError::SchemaDrift);
    }
    cap.verify_sig_chain()
}

fn encode_u8_array(enc: &mut Encoder, key: &str, values: &[u8]) -> Result<(), CrossrefError> {
    enc.encode_text(key)?;
    enc.begin_array(values.len() as u64)?;
    for v in values {
        enc.encode_unsigned(u64::from(*v))?;
    }
    Ok(())
}

fn encode_text_array(enc: &mut Encoder, key: &str, values: &[String]) -> Result<(), CrossrefError> {
    enc.encode_text(key)?;
    enc.begin_array(values.len() as u64)?;
    for v in values {
        enc.encode_text(v)?;
    }
    Ok(())
}

fn encode_caveats(enc: &mut Encoder, caveats: &[Caveat]) -> Result<(), CrossrefError> {
    enc.encode_text("caveats")?;
    enc.begin_array(caveats.len() as u64)?;
    for c in caveats {
        encode_caveat(enc, c)?;
    }
    Ok(())
}

fn encode_caveat(enc: &mut Encoder, caveat: &Caveat) -> Result<(), CrossrefError> {
    match caveat {
        Caveat::NotAfter(hlc) => {
            enc.begin_map(1)?;
            enc.encode_text("NotAfter")?;
            encode_hlc(enc, hlc)?;
        }
        Caveat::CreatedBefore(hlc) => {
            enc.begin_map(1)?;
            enc.encode_text("CreatedBefore")?;
            encode_hlc(enc, hlc)?;
        }
        Caveat::NamespacePrefix(prefix) => {
            enc.begin_map(1)?;
            enc.encode_text("NamespacePrefix")?;
            enc.encode_text(prefix)?;
        }
    }
    Ok(())
}

fn encode_hlc(enc: &mut Encoder, hlc: &Hlc) -> Result<(), CrossrefError> {
    enc.begin_map(3)?;
    enc.encode_text("counter")?;
    enc.encode_unsigned(u64::from(hlc.counter))?;
    enc.encode_text("node_id")?;
    enc.encode_bytes(&hlc.node_id)?;
    enc.encode_text("wall_ms")?;
    enc.encode_unsigned(hlc.wall_ms)?;
    Ok(())
}

fn decode_caveats(value: &CborValue) -> Result<Vec<Caveat>, CrossrefError> {
    let items = value.as_array().ok_or(CrossrefError::SchemaDrift)?;
    items.iter().map(decode_caveat).collect()
}

fn decode_caveat(value: &CborValue) -> Result<Caveat, CrossrefError> {
    let map = value.as_map().ok_or(CrossrefError::SchemaDrift)?;
    if map.len() != 1 {
        return Err(CrossrefError::SchemaDrift);
    }
    let (key, val) = &map[0];
    let name = key.as_text().ok_or(CrossrefError::SchemaDrift)?;
    match name {
        "NotAfter" => Ok(Caveat::NotAfter(decode_hlc(val)?)),
        "CreatedBefore" => Ok(Caveat::CreatedBefore(decode_hlc(val)?)),
        "NamespacePrefix" => {
            let prefix = val.as_text().ok_or(CrossrefError::SchemaDrift)?.to_string();
            Ok(Caveat::NamespacePrefix(prefix))
        }
        _ => Err(CrossrefError::SchemaDrift),
    }
}

fn decode_hlc(value: &CborValue) -> Result<Hlc, CrossrefError> {
    let map = value.as_map().ok_or(CrossrefError::SchemaDrift)?;
    let mut wall_ms = None;
    let mut counter = None;
    let mut node_id = None;
    for (key, val) in map {
        match key.as_text().ok_or(CrossrefError::SchemaDrift)? {
            "wall_ms" => wall_ms = Some(val.as_u64().ok_or(CrossrefError::SchemaDrift)?),
            "counter" => {
                counter = Some(
                    u32::try_from(val.as_u64().ok_or(CrossrefError::SchemaDrift)?)
                        .map_err(|_| CrossrefError::SchemaDrift)?,
                );
            }
            "node_id" => node_id = Some(parse_fixed16(val)?),
            _ => return Err(CrossrefError::SchemaDrift),
        }
    }
    Ok(Hlc {
        wall_ms: wall_ms.ok_or(CrossrefError::SchemaDrift)?,
        counter: counter.ok_or(CrossrefError::SchemaDrift)?,
        node_id: node_id.ok_or(CrossrefError::SchemaDrift)?,
    })
}

fn parse_u8(v: &CborValue) -> Result<u8, CrossrefError> {
    let n = v.as_u64().ok_or(CrossrefError::SchemaDrift)?;
    u8::try_from(n).map_err(|_| CrossrefError::SchemaDrift)
}

fn parse_u8_array(v: &CborValue) -> Result<Vec<u8>, CrossrefError> {
    let items = v.as_array().ok_or(CrossrefError::SchemaDrift)?;
    items.iter().map(parse_u8).collect()
}

fn parse_text_array(v: &CborValue) -> Result<Vec<String>, CrossrefError> {
    let items = v.as_array().ok_or(CrossrefError::SchemaDrift)?;
    items
        .iter()
        .map(|i| {
            i.as_text()
                .map(|s| s.to_string())
                .ok_or(CrossrefError::SchemaDrift)
        })
        .collect()
}

fn parse_bytes(v: &CborValue) -> Result<Vec<u8>, CrossrefError> {
    v.as_bytes()
        .map(|b| b.to_vec())
        .ok_or(CrossrefError::SchemaDrift)
}

fn parse_fixed32(v: &CborValue) -> Result<[u8; 32], CrossrefError> {
    v.as_bytes()
        .ok_or(CrossrefError::SchemaDrift)?
        .try_into()
        .map_err(|_| CrossrefError::SchemaDrift)
}

fn parse_fixed16(v: &CborValue) -> Result<[u8; 16], CrossrefError> {
    v.as_bytes()
        .ok_or(CrossrefError::SchemaDrift)?
        .try_into()
        .map_err(|_| CrossrefError::SchemaDrift)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn hlc(wall_ms: u64, counter: u32) -> Hlc {
        Hlc {
            wall_ms,
            counter,
            node_id: [0u8; 16],
        }
    }

    fn make_cap_no_sig(issuer: [u8; 32], subject: [u8; 32]) -> Capability {
        Capability {
            issuer,
            subject,
            namespaces: vec!["ns1".into()],
            kinds: vec![1, 2],
            tier_max: 3,
            tier_default: 1,
            permissions: 0xFF,
            caveats: vec![],
            signature: vec![0u8; SIG_LEN], // placeholder — not used in most tests
        }
    }

    /// CAP-1: Hlc::is_before orders by (wall_ms, counter, node_id).
    #[test]
    fn hlc_is_before_ordering() {
        let a = hlc(100, 0);
        let b = hlc(200, 0);
        let c = hlc(100, 1);
        assert!(a.is_before(&b), "lower wall_ms must be before");
        assert!(!b.is_before(&a), "is_before must not hold in reverse");
        assert!(
            a.is_before(&c),
            "same wall_ms, lower counter must be before"
        );
        assert!(!a.is_before(&a), "hlc must not be before itself");
    }

    /// CAP-2: sig_chain rejects empty or non-multiple-of-64 signature bytes.
    #[test]
    fn sig_chain_rejects_bad_length() {
        let mut cap = make_cap_no_sig([0x01; 32], [0x02; 32]);
        cap.signature = vec![];
        assert!(cap.sig_chain().is_err(), "empty signature must be rejected");
        cap.signature = vec![0u8; 63]; // not a multiple of 64
        assert!(
            cap.sig_chain().is_err(),
            "63-byte signature must be rejected"
        );
        cap.signature = vec![0u8; SIG_LEN];
        assert!(
            cap.sig_chain().is_ok(),
            "64-byte signature must produce one-element chain"
        );
    }

    /// CAP-3: evaluate_not_after passes before the limit and fails at/after.
    #[test]
    fn evaluate_not_after_passes_before_fails_at_or_after() {
        let limit = hlc(100, 0);
        let mut cap = make_cap_no_sig([0x01; 32], [0x02; 32]);
        cap.caveats = vec![Caveat::NotAfter(limit.clone())];

        let before = hlc(50, 0);
        cap.evaluate_not_after(&before)
            .expect("before limit must pass");

        let at = hlc(100, 0);
        assert!(
            cap.evaluate_not_after(&at).is_err(),
            "exactly at limit must fail (not strictly before)"
        );

        let after = hlc(200, 0);
        assert!(
            cap.evaluate_not_after(&after).is_err(),
            "after limit must fail"
        );
    }

    /// CAP-4: cap_id_for_caveats is deterministic for the same capability.
    #[test]
    fn cap_id_for_caveats_is_deterministic() {
        let cap = make_cap_no_sig([0xAA; 32], [0xBB; 32]);
        let id1 = cap.cap_id_for_caveats(0).expect("cap_id must compute");
        let id2 = cap.cap_id_for_caveats(0).expect("cap_id must compute");
        assert_eq!(id1, id2, "cap_id_for_caveats must be deterministic");
        assert_ne!(id1, [0u8; 32], "cap_id must not be all-zeros");
    }

    /// CAP-5: cap_id_for_caveats differs for different issuer/subject pairs.
    #[test]
    fn cap_id_different_issuer_yields_different_id() {
        let cap1 = make_cap_no_sig([0x01; 32], [0x02; 32]);
        let cap2 = make_cap_no_sig([0x03; 32], [0x02; 32]);
        let id1 = cap1.cap_id_for_caveats(0).unwrap();
        let id2 = cap2.cap_id_for_caveats(0).unwrap();
        assert_ne!(id1, id2, "different issuers must produce different cap IDs");
    }

    /// CAP-6: verify_sig_chain succeeds for a properly constructed single-signature capability.
    #[test]
    fn verify_sig_chain_succeeds_for_valid_issuer_sig() {
        let issuer_sk = SigningKey::from_bytes(&[0x11; 32]);
        let issuer_pk = issuer_sk.verifying_key().to_bytes();
        let subject_pk = SigningKey::from_bytes(&[0x22; 32])
            .verifying_key()
            .to_bytes();

        // Build the capability with a placeholder signature.
        let mut cap = Capability {
            issuer: issuer_pk,
            subject: subject_pk,
            namespaces: vec!["ns".into()],
            kinds: vec![1],
            tier_max: 2,
            tier_default: 1,
            permissions: 0x01,
            caveats: vec![],
            signature: vec![0u8; SIG_LEN], // placeholder
        };

        // Compute the cap_id (with 0 caveats, chain length 1 → caveat_count = 0).
        let cap_id = cap.cap_id_for_caveats(0).expect("cap_id must compute");
        // Sign the cap_id with the issuer key.
        let sig: [u8; SIG_LEN] = issuer_sk.sign(&cap_id).to_bytes();
        cap.signature = sig.to_vec();

        cap.verify_sig_chain()
            .expect("valid issuer-signed capability must verify");
    }

    /// CAP-7: verify_sig_chain rejects a tampered cap (changed issuer byte → wrong cap_id).
    #[test]
    fn verify_sig_chain_rejects_tampered_capability() {
        let issuer_sk = SigningKey::from_bytes(&[0x33; 32]);
        let issuer_pk = issuer_sk.verifying_key().to_bytes();
        let subject_pk = SigningKey::from_bytes(&[0x44; 32])
            .verifying_key()
            .to_bytes();

        let mut cap = Capability {
            issuer: issuer_pk,
            subject: subject_pk,
            namespaces: vec!["ns".into()],
            kinds: vec![1],
            tier_max: 2,
            tier_default: 1,
            permissions: 0x01,
            caveats: vec![],
            signature: vec![0u8; SIG_LEN],
        };

        let cap_id = cap.cap_id_for_caveats(0).unwrap();
        let sig: [u8; SIG_LEN] = issuer_sk.sign(&cap_id).to_bytes();
        cap.signature = sig.to_vec();

        // Tamper: flip one bit in the namespace.
        cap.namespaces[0] = "TAMPERED".into();

        assert!(
            cap.verify_sig_chain().is_err(),
            "tampered capability must fail sig verification"
        );
    }
}
