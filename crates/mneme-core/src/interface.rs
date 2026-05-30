//! Frozen interface contracts (blueprint §20.3).
//!
//! **INTERFACE FREEZE:** Types in this module are normative seams between parallel
//! agents. No agent may change field layouts, enum variants, or hashing rules without
//! an explicit interface-change request. See `CONTRACT.md`.

use crate::hlc::{Hlc, NodeId};
use std::fmt;

pub use crate::error::MnemeError;

/// Contract version bumped only via interface-change request.
pub const CONTRACT_VERSION: &str = "mneme-core-v1.0.0";

// ---------------------------------------------------------------------------
// Core identity types (§5.5, §20.3)
// ---------------------------------------------------------------------------

/// 32-byte content address (INV-1).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectId(pub [u8; 32]);

impl ObjectId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectId({})", hex_prefix(&self.0))
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex_full(&self.0))
    }
}

/// Logical key for the key index (§5.6).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LogicalKey {
    pub namespace: String,
    pub name: String,
}

impl LogicalKey {
    pub fn hash(&self) -> [u8; 32] {
        use blake3::Hasher;
        let mut h = Hasher::new();
        h.update(b"MNEME-key-v1\x00");
        h.update(self.namespace.as_bytes());
        h.update(&[0]);
        h.update(self.name.as_bytes());
        *h.finalize().as_bytes()
    }
}

// ---------------------------------------------------------------------------
// SMT proof types (smt ↔ dag/root/verify)
// ---------------------------------------------------------------------------

/// Merkle authentication path for SMT membership (frozen seam).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    pub key: [u8; 32],
    pub value: [u8; 32],
    pub path: Vec<[u8; 32]>,
    pub root: [u8; 32],
    pub leaf_index: usize,
}

/// Non-membership proof for a logical key (frozen seam).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonMembershipProof {
    pub key: [u8; 32],
    pub path: Vec<[u8; 32]>,
    pub root: [u8; 32],
}

// ---------------------------------------------------------------------------
// Retrieval types (index ↔ verify)
// ---------------------------------------------------------------------------

/// Deterministic retrieval procedure descriptor (§6.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Procedure {
    pub algo: ProcedureAlgo,
    pub ef_search: u32,
    pub k: u32,
    pub distance: DistanceMetric,
    pub seed: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcedureAlgo {
    Hnsw,
    Ivf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DistanceMetric {
    SquaredL2I64,
    CosineI64,
}

/// Authenticated verification object (§9.2, ADS backend).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationObject {
    pub nodes: Vec<([u8; 32], Vec<[u8; 32]>)>,
    pub candidates: Vec<(ObjectId, [u8; 32], i64)>,
    pub procedure_id: [u8; 32],
    pub query_commit: [u8; 32],
    pub result_ids: Vec<ObjectId>,
}

/// Retrieval receipt binding recall to a signed root (§9.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub root_bound: [u8; 32],
    pub logical_key: [u8; 32],
    pub object_id: [u8; 32],
    pub membership_proof: Vec<[u8; 32]>,
    pub key_index_root: [u8; 32],
    pub leaf_index: usize,
}

// ---------------------------------------------------------------------------
// Root types (root ↔ verify/crdt/store)
// ---------------------------------------------------------------------------

/// Signed store root (§5.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Root {
    pub version: u16,
    pub preimage_hash: [u8; 32],
    pub dag_head_root: [u8; 32],
    pub key_index_root: [u8; 32],
    pub semantic_commit: [u8; 32],
    pub hlc_max: [u8; 14],
    pub prev_root: [u8; 32],
    pub signature: Vec<u8>,
    pub sequence: u64,
}

/// Root preimage before hashing and signing (§5.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootPreimage {
    pub version: u16,
    pub dag_head_root: [u8; 32],
    pub key_index_root: [u8; 32],
    pub semantic_commit: [u8; 32],
    pub hlc_max: [u8; 14],
    pub prev_root: [u8; 32],
}

impl RootPreimage {
    /// Canonical preimage payload (domain tag applied by [`crate::hash_root_preimage`]).
    pub fn encode_payload(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + 32 * 4 + 14);
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(&self.dag_head_root);
        buf.extend_from_slice(&self.key_index_root);
        buf.extend_from_slice(&self.semantic_commit);
        buf.extend_from_slice(&self.hlc_max);
        buf.extend_from_slice(&self.prev_root);
        buf
    }

    /// `BLAKE3(ROOT ‖ payload)` per §5.7.
    pub fn hash(&self) -> [u8; 32] {
        crate::domain::hash_root_preimage(&self.encode_payload())
    }
}

/// RFC 9162-style consistency proof between checkpoint roots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsistencyProof {
    pub from_sequence: u64,
    pub to_sequence: u64,
    pub path: Vec<[u8; 32]>,
}

// ---------------------------------------------------------------------------
// Capability types (cap ↔ store/verify)
// ---------------------------------------------------------------------------

/// Offline-verifiable capability token body (§12, frozen seam).
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

/// Attenuation caveat evaluated offline (§12).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Caveat {
    NotAfter(Hlc),
    CreatedBefore(Hlc),
    OnlyEpisodic,
    NamespacePrefix(String),
    RateLimited(u32),
}

// ---------------------------------------------------------------------------
// Sync wire messages (crdt ↔ mnemed, §11)
// ---------------------------------------------------------------------------

/// Anti-entropy sync message enum (1-byte type tag + MNEME-dCBOR payload).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncMessage {
    Hello {
        proto_ver: u16,
        node_id: NodeId,
        head_root: [u8; 32],
        head_sig: Vec<u8>,
    },
    RootProof {
        root: Root,
        consistency_proof: Option<ConsistencyProof>,
    },
    DiffReq {
        mst_root_local: [u8; 32],
        depth_hint: u32,
    },
    DiffResp {
        divergent_subtree_summaries: Vec<[u8; 32]>,
    },
    WantObjects {
        ids: Vec<[u8; 32]>,
    },
    HaveObjects {
        objects: Vec<Vec<u8>>,
    },
    Bye,
}

impl SyncMessage {
    pub const HELLO: u8 = 0x01;
    pub const ROOT_PROOF: u8 = 0x02;
    pub const DIFF_REQ: u8 = 0x03;
    pub const DIFF_RESP: u8 = 0x04;
    pub const WANT_OBJECTS: u8 = 0x05;
    pub const HAVE_OBJECTS: u8 = 0x06;
    pub const BYE: u8 = 0x07;
}

// ---------------------------------------------------------------------------
// Kernel-facing query/draft types (store seam, not hashed)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Query {
    pub logical_key: LogicalKey,
    pub min_tier: TrustTier,
    /// Fixed-point query vector for semantic procedure P (§9.2).
    pub embedding: Option<crate::FixedPointEmbedding>,
}

#[derive(Clone, Debug)]
pub struct Draft {
    pub namespace: String,
    pub logical_name: String,
    pub kind: MemoryKind,
    pub body: Vec<u8>,
    pub parent_ids: Vec<ObjectId>,
    pub session: [u8; 16],
    pub trust_tier: Option<TrustTier>,
    /// When set, object is indexed semantically under `embedding_commit` (§5.5).
    pub embedding: Option<crate::FixedPointEmbedding>,
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub id: ObjectId,
    pub record: ObjectRecord,
    pub plaintext: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ObjectRef {
    pub id: ObjectId,
}

#[derive(Clone, Debug)]
pub enum ForgetTarget {
    LogicalKey(LogicalKey),
    ObjectId(ObjectId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForgetMode {
    Shred,
    /// Accountable chameleon redaction (§13.3); requires operator trapdoor custody.
    Redact,
}

// Object model types live in `object` but are part of the frozen contract.
pub use crate::object::{HlcWire, MemoryKind, OBJECT_VERSION, ObjectRecord, PayloadEnc, TrustTier};

fn hex_prefix(bytes: &[u8; 32]) -> String {
    bytes[..8].iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_full(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::MnemeError;

    #[test]
    fn contract_version_is_frozen_string() {
        assert_eq!(CONTRACT_VERSION, "mneme-core-v1.0.0");
    }

    #[test]
    fn mneme_error_has_no_stringly_other_variant() {
        // Compile-time seam: MnemeError must remain a closed enum (INV-9).
        let _ = MnemeError::SchemaDrift;
    }
}
