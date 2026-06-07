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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CapabilityWireFailure {
    CapabilityFieldKeyText,
    CapabilityUnknownField,
    MissingCapabilityIssuer,
    MissingCapabilitySubject,
    MissingCapabilityNamespaces,
    MissingCapabilityKinds,
    MissingCapabilityTierMax,
    MissingCapabilityTierDefault,
    MissingCapabilityPermissions,
    MissingCapabilitySignature,
    CaveatMap,
    CaveatMapArity,
    CaveatTagText,
    CaveatOnlyEpisodicPayload,
    CaveatNamespacePrefixText,
    CaveatRateLimitedUnsigned,
    CaveatRateLimitedWidth,
    CaveatUnknownTag,
    CaveatsArray,
    HlcMap,
    HlcFieldKeyText,
    HlcWallMsUnsigned,
    HlcCounterUnsigned,
    HlcCounterWidth,
    HlcUnknownField,
    MissingHlcWallMs,
    MissingHlcCounter,
    MissingHlcNodeId,
    U8Unsigned,
    U8Width,
    Bytes,
    Fixed32Length,
    Fixed16Length,
    TextArray,
    TextArrayItem,
    U8Array,
}

fn capability_wire_failure_to_mneme(failure: CapabilityWireFailure) -> MnemeError {
    match failure {
        CapabilityWireFailure::CapabilityFieldKeyText
        | CapabilityWireFailure::CapabilityUnknownField
        | CapabilityWireFailure::MissingCapabilityIssuer
        | CapabilityWireFailure::MissingCapabilitySubject
        | CapabilityWireFailure::MissingCapabilityNamespaces
        | CapabilityWireFailure::MissingCapabilityKinds
        | CapabilityWireFailure::MissingCapabilityTierMax
        | CapabilityWireFailure::MissingCapabilityTierDefault
        | CapabilityWireFailure::MissingCapabilityPermissions
        | CapabilityWireFailure::MissingCapabilitySignature
        | CapabilityWireFailure::CaveatMap
        | CapabilityWireFailure::CaveatMapArity
        | CapabilityWireFailure::CaveatTagText
        | CapabilityWireFailure::CaveatOnlyEpisodicPayload
        | CapabilityWireFailure::CaveatNamespacePrefixText
        | CapabilityWireFailure::CaveatRateLimitedUnsigned
        | CapabilityWireFailure::CaveatRateLimitedWidth
        | CapabilityWireFailure::CaveatUnknownTag
        | CapabilityWireFailure::CaveatsArray
        | CapabilityWireFailure::HlcMap
        | CapabilityWireFailure::HlcFieldKeyText
        | CapabilityWireFailure::HlcWallMsUnsigned
        | CapabilityWireFailure::HlcCounterUnsigned
        | CapabilityWireFailure::HlcCounterWidth
        | CapabilityWireFailure::HlcUnknownField
        | CapabilityWireFailure::MissingHlcWallMs
        | CapabilityWireFailure::MissingHlcCounter
        | CapabilityWireFailure::MissingHlcNodeId
        | CapabilityWireFailure::U8Unsigned
        | CapabilityWireFailure::U8Width
        | CapabilityWireFailure::Bytes
        | CapabilityWireFailure::Fixed32Length
        | CapabilityWireFailure::Fixed16Length
        | CapabilityWireFailure::TextArray
        | CapabilityWireFailure::TextArrayItem
        | CapabilityWireFailure::U8Array => MnemeError::SchemaDrift,
    }
}

fn capability_field_key_text_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::CapabilityFieldKeyText)
}

fn capability_unknown_field_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::CapabilityUnknownField)
}

fn missing_capability_issuer_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::MissingCapabilityIssuer)
}

fn missing_capability_subject_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::MissingCapabilitySubject)
}

fn missing_capability_namespaces_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::MissingCapabilityNamespaces)
}

fn missing_capability_kinds_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::MissingCapabilityKinds)
}

fn missing_capability_tier_max_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::MissingCapabilityTierMax)
}

fn missing_capability_tier_default_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::MissingCapabilityTierDefault)
}

fn missing_capability_permissions_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::MissingCapabilityPermissions)
}

fn missing_capability_signature_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::MissingCapabilitySignature)
}

fn caveat_map_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::CaveatMap)
}

fn caveat_map_arity_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::CaveatMapArity)
}

fn caveat_tag_text_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::CaveatTagText)
}

fn caveat_only_episodic_payload_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::CaveatOnlyEpisodicPayload)
}

fn caveat_namespace_prefix_text_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::CaveatNamespacePrefixText)
}

fn caveat_rate_limited_unsigned_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::CaveatRateLimitedUnsigned)
}

fn caveat_rate_limited_width_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::CaveatRateLimitedWidth)
}

fn caveat_unknown_tag_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::CaveatUnknownTag)
}

fn caveats_array_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::CaveatsArray)
}

fn hlc_map_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::HlcMap)
}

fn hlc_field_key_text_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::HlcFieldKeyText)
}

fn hlc_wall_ms_unsigned_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::HlcWallMsUnsigned)
}

fn hlc_counter_unsigned_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::HlcCounterUnsigned)
}

fn hlc_counter_width_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::HlcCounterWidth)
}

fn hlc_unknown_field_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::HlcUnknownField)
}

fn missing_hlc_wall_ms_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::MissingHlcWallMs)
}

fn missing_hlc_counter_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::MissingHlcCounter)
}

fn missing_hlc_node_id_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::MissingHlcNodeId)
}

fn u8_unsigned_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::U8Unsigned)
}

fn u8_width_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::U8Width)
}

fn bytes_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::Bytes)
}

fn fixed32_length_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::Fixed32Length)
}

fn fixed16_length_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::Fixed16Length)
}

fn text_array_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::TextArray)
}

fn text_array_item_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::TextArrayItem)
}

fn u8_array_error() -> MnemeError {
    capability_wire_failure_to_mneme(CapabilityWireFailure::U8Array)
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
        let name = key.as_text().ok_or_else(capability_field_key_text_error)?;
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
            _ => return Err(capability_unknown_field_error()),
        }
    }
    dec.ensure_consumed()?;

    Ok(Capability {
        issuer: issuer.ok_or_else(missing_capability_issuer_error)?,
        subject: subject.ok_or_else(missing_capability_subject_error)?,
        namespaces: namespaces.ok_or_else(missing_capability_namespaces_error)?,
        kinds: kinds.ok_or_else(missing_capability_kinds_error)?,
        tier_max: tier_max.ok_or_else(missing_capability_tier_max_error)?,
        tier_default: tier_default.ok_or_else(missing_capability_tier_default_error)?,
        permissions: permissions.ok_or_else(missing_capability_permissions_error)?,
        caveats: caveats.unwrap_or_default(),
        signature: signature.ok_or_else(missing_capability_signature_error)?,
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
    let map = value.as_map().ok_or_else(caveat_map_error)?;
    if map.len() != 1 {
        return Err(caveat_map_arity_error());
    }
    let (key, val) = map.iter().next().ok_or_else(caveat_map_arity_error)?;
    let name = key.as_text().ok_or_else(caveat_tag_text_error)?;
    match name {
        "NotAfter" => Ok(Caveat::NotAfter(decode_hlc(val)?)),
        "CreatedBefore" => Ok(Caveat::CreatedBefore(decode_hlc(val)?)),
        "OnlyEpisodic" => match val {
            CborValue::Bool(true) => Ok(Caveat::OnlyEpisodic),
            _ => Err(caveat_only_episodic_payload_error()),
        },
        "NamespacePrefix" => {
            let prefix = val
                .as_text()
                .ok_or_else(caveat_namespace_prefix_text_error)?
                .to_string();
            Ok(Caveat::NamespacePrefix(prefix))
        }
        "RateLimited" => {
            let n = u32::try_from(
                val.as_u64()
                    .ok_or_else(caveat_rate_limited_unsigned_error)?,
            )
            .map_err(|_| caveat_rate_limited_width_error())?;
            Ok(Caveat::RateLimited(n))
        }
        _ => Err(caveat_unknown_tag_error()),
    }
}

fn decode_caveats(value: &CborValue) -> Result<Vec<Caveat>, MnemeError> {
    let items = value.as_array().ok_or_else(caveats_array_error)?;
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
    let map = value.as_map().ok_or_else(hlc_map_error)?;
    let mut wall_ms = None;
    let mut counter = None;
    let mut node_id = None;
    for (key, val) in map {
        let name = key.as_text().ok_or_else(hlc_field_key_text_error)?;
        match name {
            "wall_ms" => wall_ms = Some(val.as_u64().ok_or_else(hlc_wall_ms_unsigned_error)?),
            "counter" => {
                counter = Some(
                    u32::try_from(val.as_u64().ok_or_else(hlc_counter_unsigned_error)?)
                        .map_err(|_| hlc_counter_width_error())?,
                );
            }
            "node_id" => node_id = Some(parse_fixed16(val)?),
            _ => return Err(hlc_unknown_field_error()),
        }
    }
    Ok(Hlc {
        wall_ms: wall_ms.ok_or_else(missing_hlc_wall_ms_error)?,
        counter: counter.ok_or_else(missing_hlc_counter_error)?,
        node_id: NodeId(node_id.ok_or_else(missing_hlc_node_id_error)?),
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
    u8::try_from(value.as_u64().ok_or_else(u8_unsigned_error)?).map_err(|_| u8_width_error())
}

fn parse_bytes(value: &CborValue) -> Result<Vec<u8>, MnemeError> {
    value.as_bytes().map(|b| b.to_vec()).ok_or_else(bytes_error)
}

fn parse_fixed32(value: &CborValue) -> Result<[u8; 32], MnemeError> {
    let bytes = parse_bytes(value)?;
    if bytes.len() != 32 {
        return Err(fixed32_length_error());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_fixed16(value: &CborValue) -> Result<[u8; 16], MnemeError> {
    let bytes = parse_bytes(value)?;
    if bytes.len() != 16 {
        return Err(fixed16_length_error());
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_text_array(value: &CborValue) -> Result<Vec<String>, MnemeError> {
    let items = value.as_array().ok_or_else(text_array_error)?;
    items
        .iter()
        .map(|v| {
            v.as_text()
                .map(|s| s.to_string())
                .ok_or_else(text_array_item_error)
        })
        .collect()
}

fn parse_u8_array(value: &CborValue) -> Result<Vec<u8>, MnemeError> {
    let items = value.as_array().ok_or_else(u8_array_error)?;
    items.iter().map(parse_u8).collect()
}

/// Fuzz entry: capability dCBOR decode; never panics (§17.4).
pub fn fuzz_decode_capability(bytes: &[u8]) {
    let _ = decode_capability(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_between_markers<'a>(
        source: &'a str,
        start_marker: &str,
        end_marker: &str,
        context: &str,
    ) -> &'a str {
        let start = source
            .find(start_marker)
            .unwrap_or_else(|| panic!("{context} should contain start marker `{start_marker}`"));
        let end_offset = source[start..]
            .find(end_marker)
            .unwrap_or_else(|| panic!("{context} should contain end marker `{end_marker}`"));
        &source[start..start + end_offset]
    }

    #[test]
    fn capability_wire_failures_are_classified_not_schema_drift_collapsed() {
        let source = include_str!("wire.rs");
        let section = source_between_markers(
            source,
            "pub fn decode_capability",
            "#[cfg(test)]",
            "capability wire decoder",
        );

        for forbidden in [
            "ok_or(MnemeError::SchemaDrift)",
            "Err(MnemeError::SchemaDrift)",
            "return Err(MnemeError::SchemaDrift)",
            "map_err(|_| MnemeError::SchemaDrift)",
        ] {
            assert!(
                !section.contains(forbidden),
                "capability wire decoder should route `{forbidden}` through named classifiers"
            );
        }

        for required in [
            "enum CapabilityWireFailure",
            "fn capability_wire_failure_to_mneme(",
            "fn capability_field_key_text_error(",
            "fn capability_unknown_field_error(",
            "fn missing_capability_issuer_error(",
            "fn missing_capability_subject_error(",
            "fn missing_capability_namespaces_error(",
            "fn missing_capability_kinds_error(",
            "fn missing_capability_tier_max_error(",
            "fn missing_capability_tier_default_error(",
            "fn missing_capability_permissions_error(",
            "fn missing_capability_signature_error(",
            "fn caveat_map_error(",
            "fn caveat_map_arity_error(",
            "fn caveat_tag_text_error(",
            "fn caveat_only_episodic_payload_error(",
            "fn caveat_namespace_prefix_text_error(",
            "fn caveat_rate_limited_unsigned_error(",
            "fn caveat_rate_limited_width_error(",
            "fn caveat_unknown_tag_error(",
            "fn caveats_array_error(",
            "fn hlc_map_error(",
            "fn hlc_field_key_text_error(",
            "fn hlc_wall_ms_unsigned_error(",
            "fn hlc_counter_unsigned_error(",
            "fn hlc_counter_width_error(",
            "fn hlc_unknown_field_error(",
            "fn missing_hlc_wall_ms_error(",
            "fn missing_hlc_counter_error(",
            "fn missing_hlc_node_id_error(",
            "fn u8_unsigned_error(",
            "fn u8_width_error(",
            "fn bytes_error(",
            "fn fixed32_length_error(",
            "fn fixed16_length_error(",
            "fn text_array_error(",
            "fn text_array_item_error(",
            "fn u8_array_error(",
            "CapabilityWireFailure::CapabilityFieldKeyText",
            "CapabilityWireFailure::CapabilityUnknownField",
            "CapabilityWireFailure::MissingCapabilityIssuer",
            "CapabilityWireFailure::MissingCapabilitySubject",
            "CapabilityWireFailure::MissingCapabilityNamespaces",
            "CapabilityWireFailure::MissingCapabilityKinds",
            "CapabilityWireFailure::MissingCapabilityTierMax",
            "CapabilityWireFailure::MissingCapabilityTierDefault",
            "CapabilityWireFailure::MissingCapabilityPermissions",
            "CapabilityWireFailure::MissingCapabilitySignature",
            "CapabilityWireFailure::CaveatMap",
            "CapabilityWireFailure::CaveatMapArity",
            "CapabilityWireFailure::CaveatTagText",
            "CapabilityWireFailure::CaveatOnlyEpisodicPayload",
            "CapabilityWireFailure::CaveatNamespacePrefixText",
            "CapabilityWireFailure::CaveatRateLimitedUnsigned",
            "CapabilityWireFailure::CaveatRateLimitedWidth",
            "CapabilityWireFailure::CaveatUnknownTag",
            "CapabilityWireFailure::CaveatsArray",
            "CapabilityWireFailure::HlcMap",
            "CapabilityWireFailure::HlcFieldKeyText",
            "CapabilityWireFailure::HlcWallMsUnsigned",
            "CapabilityWireFailure::HlcCounterUnsigned",
            "CapabilityWireFailure::HlcCounterWidth",
            "CapabilityWireFailure::HlcUnknownField",
            "CapabilityWireFailure::MissingHlcWallMs",
            "CapabilityWireFailure::MissingHlcCounter",
            "CapabilityWireFailure::MissingHlcNodeId",
            "CapabilityWireFailure::U8Unsigned",
            "CapabilityWireFailure::U8Width",
            "CapabilityWireFailure::Bytes",
            "CapabilityWireFailure::Fixed32Length",
            "CapabilityWireFailure::Fixed16Length",
            "CapabilityWireFailure::TextArray",
            "CapabilityWireFailure::TextArrayItem",
            "CapabilityWireFailure::U8Array",
        ] {
            assert!(
                source.contains(required),
                "capability wire failure classification should include `{required}`"
            );
        }
    }

    #[test]
    fn capability_wire_failure_classifier_preserves_public_schema_drift() {
        for failure in [
            CapabilityWireFailure::CapabilityFieldKeyText,
            CapabilityWireFailure::CapabilityUnknownField,
            CapabilityWireFailure::MissingCapabilityIssuer,
            CapabilityWireFailure::MissingCapabilitySubject,
            CapabilityWireFailure::MissingCapabilityNamespaces,
            CapabilityWireFailure::MissingCapabilityKinds,
            CapabilityWireFailure::MissingCapabilityTierMax,
            CapabilityWireFailure::MissingCapabilityTierDefault,
            CapabilityWireFailure::MissingCapabilityPermissions,
            CapabilityWireFailure::MissingCapabilitySignature,
            CapabilityWireFailure::CaveatMap,
            CapabilityWireFailure::CaveatMapArity,
            CapabilityWireFailure::CaveatTagText,
            CapabilityWireFailure::CaveatOnlyEpisodicPayload,
            CapabilityWireFailure::CaveatNamespacePrefixText,
            CapabilityWireFailure::CaveatRateLimitedUnsigned,
            CapabilityWireFailure::CaveatRateLimitedWidth,
            CapabilityWireFailure::CaveatUnknownTag,
            CapabilityWireFailure::CaveatsArray,
            CapabilityWireFailure::HlcMap,
            CapabilityWireFailure::HlcFieldKeyText,
            CapabilityWireFailure::HlcWallMsUnsigned,
            CapabilityWireFailure::HlcCounterUnsigned,
            CapabilityWireFailure::HlcCounterWidth,
            CapabilityWireFailure::HlcUnknownField,
            CapabilityWireFailure::MissingHlcWallMs,
            CapabilityWireFailure::MissingHlcCounter,
            CapabilityWireFailure::MissingHlcNodeId,
            CapabilityWireFailure::U8Unsigned,
            CapabilityWireFailure::U8Width,
            CapabilityWireFailure::Bytes,
            CapabilityWireFailure::Fixed32Length,
            CapabilityWireFailure::Fixed16Length,
            CapabilityWireFailure::TextArray,
            CapabilityWireFailure::TextArrayItem,
            CapabilityWireFailure::U8Array,
        ] {
            assert_eq!(
                capability_wire_failure_to_mneme(failure),
                MnemeError::SchemaDrift
            );
        }
    }
}
