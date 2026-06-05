//! §11 sync wire: 1-byte tag + MNEME-dCBOR payload.

use mneme_core::{
    CborValue, ConsistencyProof, Decoder, Encoder, MnemeError, NodeId, Root, SyncMessage,
};

const MAX_SYNC_PAYLOAD: usize = 4 * 1024 * 1024;

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
            Err(MnemeError::SchemaDrift)
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
        return Err(MnemeError::SchemaDrift);
    }
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(tag);
    out.extend(body);
    Ok(out)
}

/// Decode tagged sync frame.
pub fn decode_sync_message(bytes: &[u8]) -> Result<SyncMessage, MnemeError> {
    if bytes.is_empty() || bytes.len() > 1 + MAX_SYNC_PAYLOAD {
        return Err(MnemeError::SchemaDrift);
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
        _ => Err(MnemeError::SchemaDrift),
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
        match key.as_text().ok_or(MnemeError::SchemaDrift)? {
            "proto_ver" => proto_ver = parse_u16(&value)?,
            "node_id" => node_id = parse_fixed16(&value)?,
            "head_root" => head_root = parse_fixed32(&value)?,
            "head_sig" => head_sig = parse_bytes(&value)?,
            _ => return Err(MnemeError::SchemaDrift),
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
        match key.as_text().ok_or(MnemeError::SchemaDrift)? {
            "root" => root = Some(decode_root_value(&value)?),
            "consistency_proof" => {
                consistency_proof = if is_null(&value) {
                    None
                } else {
                    Some(decode_consistency_proof_value(&value)?)
                };
            }
            _ => return Err(MnemeError::SchemaDrift),
        }
    }
    dec.ensure_consumed()?;
    Ok(SyncMessage::RootProof {
        root: root.ok_or(MnemeError::SchemaDrift)?,
        consistency_proof,
    })
}

fn decode_diff_req(payload: &[u8]) -> Result<SyncMessage, MnemeError> {
    let mut dec = Decoder::new(payload);
    let map = dec.decode_map()?;
    let mut mst_root_local = [0u8; 32];
    let mut depth_hint = 0u32;
    for (key, value) in map {
        match key.as_text().ok_or(MnemeError::SchemaDrift)? {
            "mst_root_local" => mst_root_local = parse_fixed32(&value)?,
            "depth_hint" => depth_hint = parse_u32(&value)?,
            _ => return Err(MnemeError::SchemaDrift),
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
            return Err(MnemeError::SchemaDrift);
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
            return Err(MnemeError::SchemaDrift);
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
            return Err(MnemeError::SchemaDrift);
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
    let map = value.as_map().ok_or(MnemeError::SchemaDrift)?;
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
        match k.as_text().ok_or(MnemeError::SchemaDrift)? {
            "version" => version = parse_u16(v)?,
            "sequence" => sequence = parse_u64(v)?,
            "prev_root" => prev_root = parse_fixed32(v)?,
            "key_index_root" => key_index_root = parse_fixed32(v)?,
            "dag_head_root" => dag_head_root = parse_fixed32(v)?,
            "semantic_commit" => semantic_commit = parse_fixed32(v)?,
            "hlc_max" => {
                let b = parse_bytes(v)?;
                if b.len() != 14 {
                    return Err(MnemeError::SchemaDrift);
                }
                hlc_max.copy_from_slice(&b);
            }
            "preimage_hash" => preimage_hash = parse_fixed32(v)?,
            "signature" => signature = parse_bytes(v)?,
            _ => return Err(MnemeError::SchemaDrift),
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
    let map = value.as_map().ok_or(MnemeError::SchemaDrift)?;
    let mut from_sequence = 0u64;
    let mut to_sequence = 0u64;
    let mut path = Vec::new();
    for (k, v) in map {
        match k.as_text().ok_or(MnemeError::SchemaDrift)? {
            "from_sequence" => from_sequence = parse_u64(v)?,
            "to_sequence" => to_sequence = parse_u64(v)?,
            "path" => path = parse_vec_fixed32(v)?,
            _ => return Err(MnemeError::SchemaDrift),
        }
    }
    Ok(ConsistencyProof {
        from_sequence,
        to_sequence,
        path,
    })
}

fn parse_u16(v: &CborValue) -> Result<u16, MnemeError> {
    Ok(parse_u64(v)? as u16)
}

fn parse_u32(v: &CborValue) -> Result<u32, MnemeError> {
    Ok(parse_u64(v)? as u32)
}

fn parse_u64(v: &CborValue) -> Result<u64, MnemeError> {
    v.as_u64().ok_or(MnemeError::SchemaDrift)
}

fn parse_bytes(v: &CborValue) -> Result<Vec<u8>, MnemeError> {
    v.as_bytes()
        .map(|b| b.to_vec())
        .ok_or(MnemeError::SchemaDrift)
}

fn parse_fixed16(v: &CborValue) -> Result<[u8; 16], MnemeError> {
    let b = parse_bytes(v)?;
    if b.len() != 16 {
        return Err(MnemeError::SchemaDrift);
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&b);
    Ok(out)
}

fn parse_fixed32(v: &CborValue) -> Result<[u8; 32], MnemeError> {
    let b = parse_bytes(v)?;
    if b.len() != 32 {
        return Err(MnemeError::SchemaDrift);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    Ok(out)
}

fn parse_vec_fixed32(v: &CborValue) -> Result<Vec<[u8; 32]>, MnemeError> {
    let arr = v.as_array().ok_or(MnemeError::SchemaDrift)?;
    arr.iter().map(parse_fixed32).collect()
}

fn parse_vec_bytes(v: &CborValue) -> Result<Vec<Vec<u8>>, MnemeError> {
    let arr = v.as_array().ok_or(MnemeError::SchemaDrift)?;
    arr.iter().map(parse_bytes).collect()
}

fn is_null(v: &CborValue) -> bool {
    matches!(v, CborValue::Null)
}
