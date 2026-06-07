//! §11 sync wire: 1-byte tag + MNEME-dCBOR payload.

use mneme_core::{
    CborValue, ConsistencyProof, Decoder, Encoder, MnemeError, NodeId, Root, SyncMessage,
};

const MAX_SYNC_PAYLOAD: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SyncWireFailure {
    EncodeValue,
    EncodePayloadTooLarge,
    FrameLength,
    UnknownTag,
    MapKeyText,
    UnknownField,
    MissingRoot,
    U64,
    U16Width,
    U32Width,
    Bytes,
    Fixed16Length,
    Fixed32Length,
    Array,
    RootMap,
    RootHlcLength,
    ConsistencyMap,
}

fn sync_wire_failure_to_mneme(failure: SyncWireFailure) -> MnemeError {
    match failure {
        SyncWireFailure::EncodeValue
        | SyncWireFailure::EncodePayloadTooLarge
        | SyncWireFailure::FrameLength
        | SyncWireFailure::UnknownTag
        | SyncWireFailure::MapKeyText
        | SyncWireFailure::UnknownField
        | SyncWireFailure::MissingRoot
        | SyncWireFailure::U64
        | SyncWireFailure::U16Width
        | SyncWireFailure::U32Width
        | SyncWireFailure::Bytes
        | SyncWireFailure::Fixed16Length
        | SyncWireFailure::Fixed32Length
        | SyncWireFailure::Array
        | SyncWireFailure::RootMap
        | SyncWireFailure::RootHlcLength
        | SyncWireFailure::ConsistencyMap => MnemeError::SchemaDrift,
    }
}

fn sync_encode_value_error() -> MnemeError {
    sync_wire_failure_to_mneme(SyncWireFailure::EncodeValue)
}

fn sync_encode_payload_too_large_error() -> MnemeError {
    sync_wire_failure_to_mneme(SyncWireFailure::EncodePayloadTooLarge)
}

fn sync_frame_length_error() -> MnemeError {
    sync_wire_failure_to_mneme(SyncWireFailure::FrameLength)
}

fn sync_unknown_tag_error() -> MnemeError {
    sync_wire_failure_to_mneme(SyncWireFailure::UnknownTag)
}

fn sync_map_key_text_error() -> MnemeError {
    sync_wire_failure_to_mneme(SyncWireFailure::MapKeyText)
}

fn sync_unknown_field_error() -> MnemeError {
    sync_wire_failure_to_mneme(SyncWireFailure::UnknownField)
}

fn missing_sync_root_error() -> MnemeError {
    sync_wire_failure_to_mneme(SyncWireFailure::MissingRoot)
}

fn sync_u64_error() -> MnemeError {
    sync_wire_failure_to_mneme(SyncWireFailure::U64)
}

fn sync_u16_width_error() -> MnemeError {
    sync_wire_failure_to_mneme(SyncWireFailure::U16Width)
}

fn sync_u32_width_error() -> MnemeError {
    sync_wire_failure_to_mneme(SyncWireFailure::U32Width)
}

fn sync_bytes_error() -> MnemeError {
    sync_wire_failure_to_mneme(SyncWireFailure::Bytes)
}

fn sync_fixed16_length_error() -> MnemeError {
    sync_wire_failure_to_mneme(SyncWireFailure::Fixed16Length)
}

fn sync_fixed32_length_error() -> MnemeError {
    sync_wire_failure_to_mneme(SyncWireFailure::Fixed32Length)
}

fn sync_array_error() -> MnemeError {
    sync_wire_failure_to_mneme(SyncWireFailure::Array)
}

fn sync_root_map_error() -> MnemeError {
    sync_wire_failure_to_mneme(SyncWireFailure::RootMap)
}

fn sync_root_hlc_length_error() -> MnemeError {
    sync_wire_failure_to_mneme(SyncWireFailure::RootHlcLength)
}

fn sync_consistency_map_error() -> MnemeError {
    sync_wire_failure_to_mneme(SyncWireFailure::ConsistencyMap)
}

/// Encode map entries sorted by ascending encoded CBOR key bytes (MNEME-dCBOR).
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
        encode_value(&value, enc)?;
    }
    Ok(())
}

fn encode_value(value: &CborValue, enc: &mut Encoder) -> Result<(), MnemeError> {
    match value {
        CborValue::Unsigned(v) => enc.encode_unsigned(*v),
        CborValue::Bytes(v) => enc.encode_bytes(v),
        CborValue::Text(v) => enc.encode_text(v),
        CborValue::Null => enc.encode_null(),
        CborValue::Array(items) => {
            enc.begin_array(items.len() as u64)?;
            for item in items {
                encode_value(item, enc)?;
            }
            Ok(())
        }
        CborValue::Map(_) | CborValue::Negative(_) | CborValue::Bool(_) => {
            Err(sync_encode_value_error())
        }
    }
}

/// Encode `SyncMessage` with type tag prefix.
pub fn encode_sync_message(msg: &SyncMessage) -> Result<Vec<u8>, MnemeError> {
    let tag = match msg {
        SyncMessage::Hello { .. } => SyncMessage::HELLO,
        SyncMessage::RootProof { .. } => SyncMessage::ROOT_PROOF,
        SyncMessage::DiffReq { .. } => SyncMessage::DIFF_REQ,
        SyncMessage::DiffResp { .. } => SyncMessage::DIFF_RESP,
        SyncMessage::WantObjects { .. } => SyncMessage::WANT_OBJECTS,
        SyncMessage::HaveObjects { .. } => SyncMessage::HAVE_OBJECTS,
        SyncMessage::Bye => SyncMessage::BYE,
    };
    let mut enc = Encoder::new();
    encode_sync_payload(msg, &mut enc)?;
    let body = enc.finish();
    if body.len() > MAX_SYNC_PAYLOAD {
        return Err(sync_encode_payload_too_large_error());
    }
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(tag);
    out.extend(body);
    Ok(out)
}

/// Decode tagged sync frame.
pub fn decode_sync_message(bytes: &[u8]) -> Result<SyncMessage, MnemeError> {
    if bytes.is_empty() || bytes.len() > 1 + MAX_SYNC_PAYLOAD {
        return Err(sync_frame_length_error());
    }
    let tag = bytes[0];
    let payload = &bytes[1..];
    match tag {
        SyncMessage::HELLO => decode_hello(payload),
        SyncMessage::ROOT_PROOF => decode_root_proof(payload),
        SyncMessage::DIFF_REQ => decode_diff_req(payload),
        SyncMessage::DIFF_RESP => decode_diff_resp(payload),
        SyncMessage::WANT_OBJECTS => decode_want_objects(payload),
        SyncMessage::HAVE_OBJECTS => decode_have_objects(payload),
        SyncMessage::BYE => Ok(SyncMessage::Bye),
        _ => Err(sync_unknown_tag_error()),
    }
}

/// Fuzz entry (§17.4).
pub fn fuzz_sync_parse(bytes: &[u8]) {
    let _ = decode_sync_message(bytes);
}

fn encode_sync_payload(msg: &SyncMessage, enc: &mut Encoder) -> Result<(), MnemeError> {
    match msg {
        SyncMessage::Hello {
            proto_ver,
            node_id,
            head_root,
            head_sig,
        } => {
            encode_text_map(
                enc,
                vec![
                    ("head_root", CborValue::Bytes(head_root.to_vec())),
                    ("head_sig", CborValue::Bytes(head_sig.clone())),
                    ("node_id", CborValue::Bytes(node_id.0.to_vec())),
                    ("proto_ver", CborValue::Unsigned(u64::from(*proto_ver))),
                ],
            )?;
        }
        SyncMessage::RootProof {
            root,
            consistency_proof,
        } => {
            enc.begin_map(2)?;
            enc.encode_text("consistency_proof")?;
            match consistency_proof {
                Some(p) => encode_consistency_proof(enc, p)?,
                None => enc.encode_null()?,
            }
            enc.encode_text("root")?;
            encode_root(enc, root)?;
        }
        SyncMessage::DiffReq {
            mst_root_local,
            depth_hint,
        } => {
            enc.begin_map(2)?;
            enc.encode_text("depth_hint")?;
            enc.encode_unsigned(u64::from(*depth_hint))?;
            enc.encode_text("mst_root_local")?;
            enc.encode_bytes(mst_root_local)?;
        }
        SyncMessage::DiffResp {
            divergent_subtree_summaries,
        } => {
            enc.begin_map(1)?;
            enc.encode_text("divergent_subtree_summaries")?;
            enc.begin_array(divergent_subtree_summaries.len() as u64)?;
            for s in divergent_subtree_summaries {
                enc.encode_bytes(s)?;
            }
        }
        SyncMessage::WantObjects { ids } => {
            enc.begin_map(1)?;
            enc.encode_text("ids")?;
            enc.begin_array(ids.len() as u64)?;
            for id in ids {
                enc.encode_bytes(id)?;
            }
        }
        SyncMessage::HaveObjects { objects } => {
            enc.begin_map(1)?;
            enc.encode_text("objects")?;
            enc.begin_array(objects.len() as u64)?;
            for o in objects {
                enc.encode_bytes(o)?;
            }
        }
        SyncMessage::Bye => {
            enc.begin_map(0)?;
        }
    }
    Ok(())
}

fn decode_hello(payload: &[u8]) -> Result<SyncMessage, MnemeError> {
    let mut dec = Decoder::new(payload);
    let map = dec.decode_map()?;
    let mut proto_ver = 0u16;
    let mut node_id = [0u8; 16];
    let mut head_root = [0u8; 32];
    let mut head_sig = Vec::new();
    for (key, value) in map {
        match key.as_text().ok_or_else(sync_map_key_text_error)? {
            "proto_ver" => proto_ver = parse_u16(&value)?,
            "node_id" => node_id = parse_fixed16(&value)?,
            "head_root" => head_root = parse_fixed32(&value)?,
            "head_sig" => head_sig = parse_bytes(&value)?,
            _ => return Err(sync_unknown_field_error()),
        }
    }
    dec.ensure_consumed()?;
    Ok(SyncMessage::Hello {
        proto_ver,
        node_id: NodeId(node_id),
        head_root,
        head_sig,
    })
}

fn decode_root_proof(payload: &[u8]) -> Result<SyncMessage, MnemeError> {
    let mut dec = Decoder::new(payload);
    let map = dec.decode_map()?;
    let mut root = None;
    let mut consistency_proof = None;
    for (key, value) in map {
        match key.as_text().ok_or_else(sync_map_key_text_error)? {
            "root" => root = Some(decode_root_value(&value)?),
            "consistency_proof" => {
                consistency_proof = if is_null(&value) {
                    None
                } else {
                    Some(decode_consistency_proof_value(&value)?)
                };
            }
            _ => return Err(sync_unknown_field_error()),
        }
    }
    dec.ensure_consumed()?;
    Ok(SyncMessage::RootProof {
        root: root.ok_or_else(missing_sync_root_error)?,
        consistency_proof,
    })
}

fn decode_diff_req(payload: &[u8]) -> Result<SyncMessage, MnemeError> {
    let mut dec = Decoder::new(payload);
    let map = dec.decode_map()?;
    let mut mst_root_local = [0u8; 32];
    let mut depth_hint = 0u32;
    for (key, value) in map {
        match key.as_text().ok_or_else(sync_map_key_text_error)? {
            "mst_root_local" => mst_root_local = parse_fixed32(&value)?,
            "depth_hint" => depth_hint = parse_u32(&value)?,
            _ => return Err(sync_unknown_field_error()),
        }
    }
    dec.ensure_consumed()?;
    Ok(SyncMessage::DiffReq {
        mst_root_local,
        depth_hint,
    })
}

fn decode_diff_resp(payload: &[u8]) -> Result<SyncMessage, MnemeError> {
    let mut dec = Decoder::new(payload);
    let map = dec.decode_map()?;
    let mut divergent = Vec::new();
    for (key, value) in map {
        if key.as_text() == Some("divergent_subtree_summaries") {
            divergent = parse_vec_fixed32(&value)?;
        } else {
            return Err(sync_unknown_field_error());
        }
    }
    dec.ensure_consumed()?;
    Ok(SyncMessage::DiffResp {
        divergent_subtree_summaries: divergent,
    })
}

fn decode_want_objects(payload: &[u8]) -> Result<SyncMessage, MnemeError> {
    let mut dec = Decoder::new(payload);
    let map = dec.decode_map()?;
    let mut ids = Vec::new();
    for (key, value) in map {
        if key.as_text() == Some("ids") {
            ids = parse_vec_fixed32(&value)?;
        } else {
            return Err(sync_unknown_field_error());
        }
    }
    dec.ensure_consumed()?;
    Ok(SyncMessage::WantObjects { ids })
}

fn decode_have_objects(payload: &[u8]) -> Result<SyncMessage, MnemeError> {
    let mut dec = Decoder::new(payload);
    let map = dec.decode_map()?;
    let mut objects = Vec::new();
    for (key, value) in map {
        if key.as_text() == Some("objects") {
            objects = parse_vec_bytes(&value)?;
        } else {
            return Err(sync_unknown_field_error());
        }
    }
    dec.ensure_consumed()?;
    Ok(SyncMessage::HaveObjects { objects })
}

fn encode_root(enc: &mut Encoder, root: &Root) -> Result<(), MnemeError> {
    enc.begin_map(9)?;
    enc.encode_text("dag_head_root")?;
    enc.encode_bytes(&root.dag_head_root)?;
    enc.encode_text("hlc_max")?;
    enc.encode_bytes(&root.hlc_max)?;
    enc.encode_text("key_index_root")?;
    enc.encode_bytes(&root.key_index_root)?;
    enc.encode_text("preimage_hash")?;
    enc.encode_bytes(&root.preimage_hash)?;
    enc.encode_text("prev_root")?;
    enc.encode_bytes(&root.prev_root)?;
    enc.encode_text("semantic_commit")?;
    enc.encode_bytes(&root.semantic_commit)?;
    enc.encode_text("sequence")?;
    enc.encode_unsigned(root.sequence)?;
    enc.encode_text("signature")?;
    enc.encode_bytes(&root.signature)?;
    enc.encode_text("version")?;
    enc.encode_unsigned(u64::from(root.version))?;
    Ok(())
}

fn encode_consistency_proof(enc: &mut Encoder, p: &ConsistencyProof) -> Result<(), MnemeError> {
    enc.begin_map(3)?;
    enc.encode_text("from_sequence")?;
    enc.encode_unsigned(p.from_sequence)?;
    enc.encode_text("path")?;
    enc.begin_array(p.path.len() as u64)?;
    for node in &p.path {
        enc.encode_bytes(node)?;
    }
    enc.encode_text("to_sequence")?;
    enc.encode_unsigned(p.to_sequence)?;
    Ok(())
}

fn decode_root_value(value: &CborValue) -> Result<Root, MnemeError> {
    let map = value.as_map().ok_or_else(sync_root_map_error)?;
    let mut version = 1u16;
    let mut sequence = 0u64;
    let mut prev_root = [0u8; 32];
    let mut key_index_root = [0u8; 32];
    let mut dag_head_root = [0u8; 32];
    let mut semantic_commit = [0u8; 32];
    let mut hlc_max = [0u8; 14];
    let mut preimage_hash = [0u8; 32];
    let mut signature = Vec::new();
    for (k, v) in map {
        match k.as_text().ok_or_else(sync_map_key_text_error)? {
            "version" => version = parse_u16(v)?,
            "sequence" => sequence = parse_u64(v)?,
            "prev_root" => prev_root = parse_fixed32(v)?,
            "key_index_root" => key_index_root = parse_fixed32(v)?,
            "dag_head_root" => dag_head_root = parse_fixed32(v)?,
            "semantic_commit" => semantic_commit = parse_fixed32(v)?,
            "hlc_max" => {
                let b = parse_bytes(v)?;
                if b.len() != 14 {
                    return Err(sync_root_hlc_length_error());
                }
                hlc_max.copy_from_slice(&b);
            }
            "preimage_hash" => preimage_hash = parse_fixed32(v)?,
            "signature" => signature = parse_bytes(v)?,
            _ => return Err(sync_unknown_field_error()),
        }
    }
    Ok(Root {
        version,
        sequence,
        prev_root,
        key_index_root,
        dag_head_root,
        semantic_commit,
        hlc_max,
        preimage_hash,
        signature,
    })
}

fn decode_consistency_proof_value(value: &CborValue) -> Result<ConsistencyProof, MnemeError> {
    let map = value.as_map().ok_or_else(sync_consistency_map_error)?;
    let mut from_sequence = 0u64;
    let mut to_sequence = 0u64;
    let mut path = Vec::new();
    for (k, v) in map {
        match k.as_text().ok_or_else(sync_map_key_text_error)? {
            "from_sequence" => from_sequence = parse_u64(v)?,
            "to_sequence" => to_sequence = parse_u64(v)?,
            "path" => path = parse_vec_fixed32(v)?,
            _ => return Err(sync_unknown_field_error()),
        }
    }
    Ok(ConsistencyProof {
        from_sequence,
        to_sequence,
        path,
    })
}

fn parse_u16(v: &CborValue) -> Result<u16, MnemeError> {
    u16::try_from(parse_u64(v)?).map_err(|_| sync_u16_width_error())
}

fn parse_u32(v: &CborValue) -> Result<u32, MnemeError> {
    u32::try_from(parse_u64(v)?).map_err(|_| sync_u32_width_error())
}

fn parse_u64(v: &CborValue) -> Result<u64, MnemeError> {
    v.as_u64().ok_or_else(sync_u64_error)
}

fn parse_bytes(v: &CborValue) -> Result<Vec<u8>, MnemeError> {
    v.as_bytes()
        .map(|b| b.to_vec())
        .ok_or_else(sync_bytes_error)
}

fn parse_fixed16(v: &CborValue) -> Result<[u8; 16], MnemeError> {
    let b = parse_bytes(v)?;
    if b.len() != 16 {
        return Err(sync_fixed16_length_error());
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&b);
    Ok(out)
}

fn parse_fixed32(v: &CborValue) -> Result<[u8; 32], MnemeError> {
    let b = parse_bytes(v)?;
    if b.len() != 32 {
        return Err(sync_fixed32_length_error());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    Ok(out)
}

fn parse_vec_fixed32(v: &CborValue) -> Result<Vec<[u8; 32]>, MnemeError> {
    let arr = v.as_array().ok_or_else(sync_array_error)?;
    arr.iter().map(parse_fixed32).collect()
}

fn parse_vec_bytes(v: &CborValue) -> Result<Vec<Vec<u8>>, MnemeError> {
    let arr = v.as_array().ok_or_else(sync_array_error)?;
    arr.iter().map(parse_bytes).collect()
}

fn is_null(v: &CborValue) -> bool {
    matches!(v, CborValue::Null)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_before_tests(source: &str) -> &str {
        let end = source
            .find("#[cfg(test)]")
            .expect("sync wire source should contain test marker");
        &source[..end]
    }

    #[test]
    fn crdt_wire_failures_are_classified_not_schema_drift_collapsed() {
        let source = include_str!("wire.rs");
        let production = source_before_tests(source);

        for forbidden in [
            "ok_or(MnemeError::SchemaDrift)",
            "Err(MnemeError::SchemaDrift)",
            "return Err(MnemeError::SchemaDrift)",
            "map_err(|_| MnemeError::SchemaDrift)",
            "_ => Err(MnemeError::SchemaDrift)",
            "_ => return Err(MnemeError::SchemaDrift)",
        ] {
            assert!(
                !production.contains(forbidden),
                "CRDT sync wire should route `{forbidden}` through named classifiers"
            );
        }

        for required in [
            "enum SyncWireFailure",
            "fn sync_wire_failure_to_mneme(",
            "fn sync_encode_value_error(",
            "fn sync_encode_payload_too_large_error(",
            "fn sync_frame_length_error(",
            "fn sync_unknown_tag_error(",
            "fn sync_map_key_text_error(",
            "fn sync_unknown_field_error(",
            "fn missing_sync_root_error(",
            "fn sync_u64_error(",
            "fn sync_u16_width_error(",
            "fn sync_u32_width_error(",
            "fn sync_bytes_error(",
            "fn sync_fixed16_length_error(",
            "fn sync_fixed32_length_error(",
            "fn sync_array_error(",
            "fn sync_root_map_error(",
            "fn sync_root_hlc_length_error(",
            "fn sync_consistency_map_error(",
            "SyncWireFailure::EncodeValue",
            "SyncWireFailure::EncodePayloadTooLarge",
            "SyncWireFailure::FrameLength",
            "SyncWireFailure::UnknownTag",
            "SyncWireFailure::MapKeyText",
            "SyncWireFailure::UnknownField",
            "SyncWireFailure::MissingRoot",
            "SyncWireFailure::U64",
            "SyncWireFailure::U16Width",
            "SyncWireFailure::U32Width",
            "SyncWireFailure::Bytes",
            "SyncWireFailure::Fixed16Length",
            "SyncWireFailure::Fixed32Length",
            "SyncWireFailure::Array",
            "SyncWireFailure::RootMap",
            "SyncWireFailure::RootHlcLength",
            "SyncWireFailure::ConsistencyMap",
        ] {
            assert!(
                source.contains(required),
                "CRDT sync wire failure classification should include `{required}`"
            );
        }
    }

    #[test]
    fn crdt_wire_failure_classifier_preserves_public_error() {
        for failure in [
            SyncWireFailure::EncodeValue,
            SyncWireFailure::EncodePayloadTooLarge,
            SyncWireFailure::FrameLength,
            SyncWireFailure::UnknownTag,
            SyncWireFailure::MapKeyText,
            SyncWireFailure::UnknownField,
            SyncWireFailure::MissingRoot,
            SyncWireFailure::U64,
            SyncWireFailure::U16Width,
            SyncWireFailure::U32Width,
            SyncWireFailure::Bytes,
            SyncWireFailure::Fixed16Length,
            SyncWireFailure::Fixed32Length,
            SyncWireFailure::Array,
            SyncWireFailure::RootMap,
            SyncWireFailure::RootHlcLength,
            SyncWireFailure::ConsistencyMap,
        ] {
            assert_eq!(sync_wire_failure_to_mneme(failure), MnemeError::SchemaDrift);
        }
    }

    #[test]
    fn crdt_wire_hello_proto_version_width_overflow_fails_closed() {
        let mut enc = Encoder::new();
        encode_text_map(
            &mut enc,
            vec![
                ("head_root", CborValue::Bytes(vec![0x22; 32])),
                ("head_sig", CborValue::Bytes(vec![0x33; 64])),
                ("node_id", CborValue::Bytes(vec![0x11; 16])),
                ("proto_ver", CborValue::Unsigned(u64::from(u16::MAX) + 1)),
            ],
        )
        .expect("encode canonical hello map");

        let mut bytes = Vec::new();
        bytes.push(SyncMessage::HELLO);
        bytes.extend(enc.finish());

        assert_eq!(decode_sync_message(&bytes), Err(MnemeError::SchemaDrift));
    }

    #[test]
    fn crdt_wire_diff_depth_width_overflow_fails_closed() {
        let mut enc = Encoder::new();
        encode_text_map(
            &mut enc,
            vec![
                ("depth_hint", CborValue::Unsigned(u64::from(u32::MAX) + 1)),
                ("mst_root_local", CborValue::Bytes(vec![0x44; 32])),
            ],
        )
        .expect("encode canonical diff request map");

        let mut bytes = Vec::new();
        bytes.push(SyncMessage::DIFF_REQ);
        bytes.extend(enc.finish());

        assert_eq!(decode_sync_message(&bytes), Err(MnemeError::SchemaDrift));
    }
}
