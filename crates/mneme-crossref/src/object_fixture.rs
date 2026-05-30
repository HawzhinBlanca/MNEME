//! Deterministic object CBOR encodings for Appendix B fixtures (reference path).

use crate::dcbor::{DcborEncode, Encoder, encode_canonical};
use crate::domain::hash_obj;
use crate::error::CrossrefError;

const F_VERSION: u64 = 0;
const F_KIND: u64 = 1;
const F_PARENT_IDS: u64 = 2;
const F_WRITER: u64 = 3;
const F_SESSION: u64 = 4;
const F_HLC: u64 = 5;
const F_TRUST_TIER: u64 = 6;
const F_PAYLOAD_ENC: u64 = 7;

const OBJECT_VERSION: u16 = 1;

pub fn writer_hash(pubkey: &[u8; 32]) -> [u8; 32] {
    *blake3::hash(pubkey).as_bytes()
}

/// MST convergence fixture object (matches mneme-crdt `sample_record`).
pub fn mst_agent_object_bytes(agent_seed: u8) -> Result<Vec<u8>, CrossrefError> {
    let keypair_seed = [agent_seed; 32];
    let pubkey = ed25519_seed_pubkey(&keypair_seed);
    encode_object(
        0, // Episodic
        writer_hash(&pubkey),
        u64::from(agent_seed),
        b"payload",
        2, // Trusted
    )
}

/// Appendix B receipt fixture object (matches mneme-verify `fixture_record`).
pub fn receipt_fixture_object_bytes() -> Result<Vec<u8>, CrossrefError> {
    let agent_seed = [0x02; 32];
    let pubkey = ed25519_seed_pubkey(&agent_seed);
    encode_receipt_object(
        writer_hash(&pubkey),
        [0x42; 16],
        [0x03; 16],
        b"appendix-b-receipt",
    )
}

fn ed25519_seed_pubkey(seed: &[u8; 32]) -> [u8; 32] {
    use ed25519_dalek::SigningKey;
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

fn encode_object(
    kind: u8,
    writer: [u8; 32],
    wall_ms: u64,
    body: &[u8],
    trust_tier: u8,
) -> Result<Vec<u8>, CrossrefError> {
    encode_record(FixtureObject {
        kind,
        writer,
        session: [0u8; 16],
        wall_ms,
        node_id: [0x02; 16],
        body: body.to_vec(),
        trust_tier,
    })
}

fn encode_receipt_object(
    writer: [u8; 32],
    session: [u8; 16],
    node_id: [u8; 16],
    body: &[u8],
) -> Result<Vec<u8>, CrossrefError> {
    encode_record(FixtureObject {
        kind: 1,
        writer,
        session,
        wall_ms: 1,
        node_id,
        body: body.to_vec(),
        trust_tier: 1,
    })
}

fn encode_record(record: FixtureObject) -> Result<Vec<u8>, CrossrefError> {
    encode_canonical(&record)
}

struct FixtureObject {
    kind: u8,
    writer: [u8; 32],
    session: [u8; 16],
    wall_ms: u64,
    node_id: [u8; 16],
    body: Vec<u8>,
    trust_tier: u8,
}

impl DcborEncode for FixtureObject {
    fn dcbor_encode(&self, enc: &mut Encoder) -> Result<(), CrossrefError> {
        enc.begin_map(8)?;
        enc.encode_unsigned(F_VERSION)?;
        enc.encode_unsigned(u64::from(OBJECT_VERSION))?;
        enc.encode_unsigned(F_KIND)?;
        enc.encode_unsigned(u64::from(self.kind))?;
        enc.encode_unsigned(F_PARENT_IDS)?;
        enc.begin_array(0)?;
        enc.encode_unsigned(F_WRITER)?;
        enc.encode_bytes(&self.writer)?;
        enc.encode_unsigned(F_SESSION)?;
        enc.encode_bytes(&self.session)?;
        enc.encode_unsigned(F_HLC)?;
        enc.begin_array(3)?;
        enc.encode_unsigned(self.wall_ms)?;
        enc.encode_unsigned(0)?;
        enc.encode_bytes(&self.node_id)?;
        enc.encode_unsigned(F_TRUST_TIER)?;
        enc.encode_unsigned(u64::from(self.trust_tier))?;
        enc.encode_unsigned(F_PAYLOAD_ENC)?;
        enc.begin_map(2)?;
        enc.encode_text("alg")?;
        enc.encode_unsigned(0)?;
        enc.encode_text("body")?;
        enc.encode_bytes(&self.body)?;
        Ok(())
    }
}

pub fn object_id(bytes: &[u8]) -> [u8; 32] {
    hash_obj(bytes)
}
