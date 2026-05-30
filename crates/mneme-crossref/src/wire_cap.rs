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
