//! MNEME-dCBOR wire encoding for capability tokens (§12, frozen seam fields).

use mneme_core::{
    Caveat, CborValue, DcborEncode, Decoder, Encoder, Hlc, MnemeError, NodeId,
    interface::Capability,
};

/// Capability body without `signature` (sig-chain preimage for `cap_id`).
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

impl From<&Capability> for CapPreimage {
    fn from(cap: &Capability) -> Self {
        Self {
            issuer: cap.issuer,
            subject: cap.subject,
            namespaces: cap.namespaces.clone(),
            kinds: cap.kinds.clone(),
            tier_max: cap.tier_max,
            tier_default: cap.tier_default,
            permissions: cap.permissions,
            caveats: cap.caveats.clone(),
        }
    }
}

impl DcborEncode for CapPreimage {
    fn dcbor_encode(&self, enc: &mut Encoder) -> Result<(), MnemeError> {
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

pub fn decode_capability(bytes: &[u8]) -> Result<Capability, MnemeError> {
    let mut dec = Decoder::new(bytes);
    let map = dec.decode_map()?;
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
        let name = key.as_text().ok_or(MnemeError::SchemaDrift)?;
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
            _ => return Err(MnemeError::SchemaDrift),
        }
    }
    dec.ensure_consumed()?;

    Ok(Capability {
        issuer: issuer.ok_or(MnemeError::SchemaDrift)?,
        subject: subject.ok_or(MnemeError::SchemaDrift)?,
        namespaces: namespaces.ok_or(MnemeError::SchemaDrift)?,
        kinds: kinds.ok_or(MnemeError::SchemaDrift)?,
        tier_max: tier_max.ok_or(MnemeError::SchemaDrift)?,
        tier_default: tier_default.ok_or(MnemeError::SchemaDrift)?,
        permissions: permissions.ok_or(MnemeError::SchemaDrift)?,
        caveats: caveats.unwrap_or_default(),
        signature: signature.ok_or(MnemeError::SchemaDrift)?,
    })
}

pub fn encode_capability(cap: &Capability) -> Result<Vec<u8>, MnemeError> {
    let mut enc = Encoder::new();
    enc.begin_map(9)?;
    encode_u8_array(&mut enc, "kinds", &cap.kinds)?;
    enc.encode_text("issuer")?;
    enc.encode_bytes(&cap.issuer)?;
    encode_caveats(&mut enc, &cap.caveats)?;
    enc.encode_text("subject")?;
    enc.encode_bytes(&cap.subject)?;
    enc.encode_text("tier_max")?;
    enc.encode_unsigned(u64::from(cap.tier_max))?;
    enc.encode_text("signature")?;
    enc.encode_bytes(&cap.signature)?;
    encode_text_array(&mut enc, "namespaces", &cap.namespaces)?;
    enc.encode_text("permissions")?;
    enc.encode_unsigned(u64::from(cap.permissions))?;
    enc.encode_text("tier_default")?;
    enc.encode_unsigned(u64::from(cap.tier_default))?;
    Ok(enc.finish())
}

fn encode_caveat(enc: &mut Encoder, caveat: &Caveat) -> Result<(), MnemeError> {
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
        Caveat::OnlyEpisodic => {
            enc.begin_map(1)?;
            enc.encode_text("OnlyEpisodic")?;
            enc.encode_bool(true)?;
        }
        Caveat::NamespacePrefix(prefix) => {
            enc.begin_map(1)?;
            enc.encode_text("NamespacePrefix")?;
            enc.encode_text(prefix)?;
        }
        Caveat::RateLimited(n) => {
            enc.begin_map(1)?;
            enc.encode_text("RateLimited")?;
            enc.encode_unsigned(u64::from(*n))?;
        }
    }
    Ok(())
}

fn decode_caveat(value: &CborValue) -> Result<Caveat, MnemeError> {
    let map = value.as_map().ok_or(MnemeError::SchemaDrift)?;
    if map.len() != 1 {
        return Err(MnemeError::SchemaDrift);
    }
    let (key, val) = map.iter().next().ok_or(MnemeError::SchemaDrift)?;
    let name = key.as_text().ok_or(MnemeError::SchemaDrift)?;
    match name {
        "NotAfter" => Ok(Caveat::NotAfter(decode_hlc(val)?)),
        "CreatedBefore" => Ok(Caveat::CreatedBefore(decode_hlc(val)?)),
        "OnlyEpisodic" => match val {
            CborValue::Bool(true) => Ok(Caveat::OnlyEpisodic),
            _ => Err(MnemeError::SchemaDrift),
        },
        "NamespacePrefix" => {
            let prefix = val.as_text().ok_or(MnemeError::SchemaDrift)?.to_string();
            Ok(Caveat::NamespacePrefix(prefix))
        }
        "RateLimited" => {
            let n = u32::try_from(val.as_u64().ok_or(MnemeError::SchemaDrift)?)
                .map_err(|_| MnemeError::SchemaDrift)?;
            Ok(Caveat::RateLimited(n))
        }
        _ => Err(MnemeError::SchemaDrift),
    }
}

fn decode_caveats(value: &CborValue) -> Result<Vec<Caveat>, MnemeError> {
    let items = value.as_array().ok_or(MnemeError::SchemaDrift)?;
    items.iter().map(decode_caveat).collect()
}

fn encode_caveats(enc: &mut Encoder, caveats: &[Caveat]) -> Result<(), MnemeError> {
    enc.encode_text("caveats")?;
    enc.begin_array(caveats.len() as u64)?;
    for caveat in caveats {
        encode_caveat(enc, caveat)?;
    }
    Ok(())
}

fn encode_hlc(enc: &mut Encoder, hlc: &Hlc) -> Result<(), MnemeError> {
    enc.begin_map(3)?;
    enc.encode_text("counter")?;
    enc.encode_unsigned(u64::from(hlc.counter))?;
    enc.encode_text("node_id")?;
    enc.encode_bytes(&hlc.node_id.0)?;
    enc.encode_text("wall_ms")?;
    enc.encode_unsigned(hlc.wall_ms)?;
    Ok(())
}

fn decode_hlc(value: &CborValue) -> Result<Hlc, MnemeError> {
    let map = value.as_map().ok_or(MnemeError::SchemaDrift)?;
    let mut wall_ms = None;
    let mut counter = None;
    let mut node_id = None;
    for (key, val) in map {
        let name = key.as_text().ok_or(MnemeError::SchemaDrift)?;
        match name {
            "wall_ms" => wall_ms = Some(val.as_u64().ok_or(MnemeError::SchemaDrift)?),
            "counter" => {
                counter = Some(
                    u32::try_from(val.as_u64().ok_or(MnemeError::SchemaDrift)?)
                        .map_err(|_| MnemeError::SchemaDrift)?,
                );
            }
            "node_id" => node_id = Some(parse_fixed16(val)?),
            _ => return Err(MnemeError::SchemaDrift),
        }
    }
    Ok(Hlc {
        wall_ms: wall_ms.ok_or(MnemeError::SchemaDrift)?,
        counter: counter.ok_or(MnemeError::SchemaDrift)?,
        node_id: NodeId(node_id.ok_or(MnemeError::SchemaDrift)?),
    })
}

fn encode_u8_array(enc: &mut Encoder, key: &str, values: &[u8]) -> Result<(), MnemeError> {
    enc.encode_text(key)?;
    enc.begin_array(values.len() as u64)?;
    for v in values {
        enc.encode_unsigned(u64::from(*v))?;
    }
    Ok(())
}

fn encode_text_array(enc: &mut Encoder, key: &str, values: &[String]) -> Result<(), MnemeError> {
    enc.encode_text(key)?;
    enc.begin_array(values.len() as u64)?;
    for v in values {
        enc.encode_text(v)?;
    }
    Ok(())
}

fn parse_u8(value: &CborValue) -> Result<u8, MnemeError> {
    u8::try_from(value.as_u64().ok_or(MnemeError::SchemaDrift)?)
        .map_err(|_| MnemeError::SchemaDrift)
}

fn parse_bytes(value: &CborValue) -> Result<Vec<u8>, MnemeError> {
    value
        .as_bytes()
        .map(|b| b.to_vec())
        .ok_or(MnemeError::SchemaDrift)
}

fn parse_fixed32(value: &CborValue) -> Result<[u8; 32], MnemeError> {
    let bytes = parse_bytes(value)?;
    if bytes.len() != 32 {
        return Err(MnemeError::SchemaDrift);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_fixed16(value: &CborValue) -> Result<[u8; 16], MnemeError> {
    let bytes = parse_bytes(value)?;
    if bytes.len() != 16 {
        return Err(MnemeError::SchemaDrift);
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_text_array(value: &CborValue) -> Result<Vec<String>, MnemeError> {
    let items = value.as_array().ok_or(MnemeError::SchemaDrift)?;
    items
        .iter()
        .map(|v| {
            v.as_text()
                .map(|s| s.to_string())
                .ok_or(MnemeError::SchemaDrift)
        })
        .collect()
}

fn parse_u8_array(value: &CborValue) -> Result<Vec<u8>, MnemeError> {
    let items = value.as_array().ok_or(MnemeError::SchemaDrift)?;
    items.iter().map(parse_u8).collect()
}

/// Fuzz entry: capability dCBOR decode; never panics (§17.4).
pub fn fuzz_decode_capability(bytes: &[u8]) {
    let _ = decode_capability(bytes);
}
