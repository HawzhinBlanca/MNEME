//! Frozen interface contracts (blueprint §20.3).
//!
//! **INTERFACE FREEZE:** Types in this module are normative seams between parallel
//! agents. No agent may change field layouts, enum variants, or hashing rules without
//! an explicit interface-change request. See `CONTRACT.md`.

use crate::hlc::{Hlc, NodeId};
use std::fmt;

pub use crate::error::MnemeError;

/// Contract version bumped only via interface-change request.
pub const CONTRACT_VERSION: &str = "mneme-core-v2.0.0-draft";

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
// Context assembly (Phase II gate)
// ---------------------------------------------------------------------------

/// Frozen assembly profile id for deterministic prompt layouts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssemblyProfile {
    pub id: [u8; 32],
}

/// Attestation that the assembled context matched the certified memory set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContextConsumptionAttestation {
    pub assembly_profile: AssemblyProfile,
    pub context_hash: [u8; 32],
    pub certified_memory_set_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputBinding {
    pub context_hash: [u8; 32],
    pub output_hash: [u8; 32],
    pub model_identity: [u8; 32],
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

/// Phase I: level of retrieval proof bundled in a Cognition Certificate (§5 honesty).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetrievalProofLevel {
    /// Procedure-faithful top-k: membership/completeness for the complete authenticated member set
    /// plus top-k over prover-asserted distances; true top-k ranking is not proven and this is
    /// not top-k by true query-to-embedding distance until verifiers recompute candidate distances.
    /// (Renamed from `ExactDominance` — the old name implied exact nearest-neighbor dominance,
    /// which this level does not prove.)
    ProcedureFaithfulTopK = 0,
    /// Dominance over a prover-asserted set of authenticated members (`visited_order`); not graph replay.
    HnswAuditOnDemand = 1,
    /// Provably-complete top-k via authenticated ball-tree pruning frontier (CR-6). Proves no closer
    /// neighbor was hidden in committed geometry — not semantic truth, not exact-NN-by-relevance.
    CompleteTopK = 2,
}

impl RetrievalProofLevel {
    /// Deprecated alias for backward compatibility. Use `ProcedureFaithfulTopK` instead.
    #[deprecated(
        note = "renamed to ProcedureFaithfulTopK — ExactDominance implied exact-NN which this level does not prove"
    )]
    pub const EXACT_DOMINANCE: Self = Self::ProcedureFaithfulTopK;
}

/// Phase I bi-temporal anchor (transaction-time via signed root; valid-time in P1-2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AsOf {
    RootSeq(u64),
    /// Valid-time upper bound (wall ms): only objects with `valid_time_ms <= t` are eligible.
    ValidTime(u64),
}

/// Phase I provenance filter for poison-evidence recall (P1-3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenanceFilter {
    /// Expected `ObjectRecord.writer` (BLAKE3 of cap subject).
    pub written_by: Option<[u8; 32]>,
    /// HLC lower bound (inclusive): `record.hlc >= since`.
    pub since: Option<[u8; 14]>,
    pub min_tier: TrustTier,
}

/// Per-candidate provenance bound into a scoped recall receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateProvenance {
    pub object_id: ObjectId,
    pub writer: [u8; 32],
    pub trust_tier: u8,
    pub hlc: [u8; 14],
    pub valid_time_ms: Option<u64>,
}

/// Cognition Certificate schema version (Phase I v1 wire).
pub const COGNITION_CERT_VERSION: u16 = 1;
pub const COGNITION_CERT_VERSION_V2_DRAFT: u16 = 2;

/// Authenticated verification object (§9.2, ADS backend).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationObject {
    pub nodes: Vec<([u8; 32], Vec<[u8; 32]>)>,
    pub candidates: Vec<(ObjectId, [u8; 32], i64)>,
    /// True leaf indices in the **full** semantic Merkle tree (not the subset), parallel to
    /// `candidates` / `nodes`. Required for HNSW audit-on-demand so membership paths verify
    /// against the committed tree rather than a prover-supplied subset.
    pub leaf_indices: Vec<usize>,
    pub procedure_id: [u8; 32],
    pub query_commit: [u8; 32],
    pub result_ids: Vec<ObjectId>,
    pub candidates_embeddings: Option<Vec<crate::FixedPointEmbedding>>,
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
    /// Optional valid-time (world time), distinct from transaction-time (`hlc` at ingest).
    pub valid_time_ms: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub id: ObjectId,
    pub record: ObjectRecord,
    /// Decrypted payload **only after** the store layer (`Store::recall_verified`
    /// → `decrypt_entries`) AEAD-opens it against the per-key AAD. As returned by
    /// the verifier TCB (`mneme_verify::verify_recall` / `verify_semantic_recall`)
    /// this still holds the AEAD **ciphertext** (`record.payload_enc.body`): the
    /// key vault is deliberately outside the budgeted TCB (§17.6), so the verifier
    /// proves integrity / provenance / authorization but never decrypts (F-6). A
    /// direct consumer of the public TCB entry points therefore receives ciphertext
    /// here and must not treat it as readable plaintext. The field name is frozen
    /// by the §20.3 interface freeze; the trust boundary is documented rather than
    /// renamed. (`Store::recall_verified` is the only agent-facing read — INV-5.)
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
        assert_eq!(CONTRACT_VERSION, "mneme-core-v2.0.0-draft");
    }

    #[test]
    fn mneme_error_has_no_stringly_other_variant() {
        // Compile-time seam: MnemeError must remain a closed enum (INV-9).
        let _ = MnemeError::SchemaDrift;
    }

    #[test]
    fn retrieval_proof_level_docs_preserve_distance_honesty() {
        let source = include_str!("interface.rs")
            .split_once("#[cfg(test)]")
            .map(|(production, _tests)| production)
            .expect("interface tests should follow production code");

        assert!(
            !source.contains("True top-k"),
            "ProcedureFaithfulTopK docs must not claim true top-k until candidate distances are verifier-recomputed"
        );
        assert!(
            source.contains("prover-asserted distances"),
            "ProcedureFaithfulTopK docs must state that top-k is over prover-asserted distances"
        );
        assert!(
            source.contains("membership/completeness"),
            "ProcedureFaithfulTopK docs must state that current proof is membership/completeness scoped"
        );
        assert!(
            source.contains("top-k ranking is not proven"),
            "ProcedureFaithfulTopK docs must say top-k ranking is not proven"
        );
        assert!(
            source.contains("not top-k by true query-to-embedding distance"),
            "ProcedureFaithfulTopK docs must keep the distance-binding caveat explicit"
        );
        // Guard: the old over-claiming name must only appear in the deprecated alias context
        assert!(
            !source.contains("ExactDominance = 0"),
            "ExactDominance variant was renamed to ProcedureFaithfulTopK — the old name must not appear as a primary enum variant"
        );
    }

    #[test]
    fn verification_object_v2_shape_stays_frozen_until_contract_bump() {
        let source = include_str!("interface.rs")
            .split_once("#[cfg(test)]")
            .map(|(production, _tests)| production)
            .expect("interface tests should follow production code");
        let (_, after_struct) = source
            .split_once("pub struct VerificationObject {")
            .expect("VerificationObject remains a frozen interface type");
        let (verification_object, _) = after_struct
            .split_once("/// Retrieval receipt binding recall")
            .expect("VerificationObject remains before key-index Receipt");

        assert_eq!(CONTRACT_VERSION, "mneme-core-v2.0.0-draft");
        assert!(
            verification_object.contains("pub candidates: Vec<(ObjectId, [u8; 32], i64)>"),
            "v1 VerificationObject candidate rows stay `(ObjectId, embedding_commit, distance)` until a formal interface-change request bumps CONTRACT_VERSION"
        );
        assert!(
            verification_object
                .contains("pub candidates_embeddings: Option<Vec<crate::FixedPointEmbedding>>"),
            "embedding-carrying semantic VO support must carry candidates_embeddings"
        );
    }

    /// KEY-HASH-1: LogicalKey::hash is deterministic.
    #[test]
    fn logical_key_hash_is_deterministic() {
        let k = LogicalKey {
            namespace: "test".to_string(),
            name: "obj".to_string(),
        };
        assert_eq!(k.hash(), k.hash(), "LogicalKey::hash must be deterministic");
    }

    /// KEY-HASH-2: The null-byte separator in LogicalKey::hash is NOT sufficient
    /// when namespace/name strings contain embedded null bytes. This test documents
    /// the known limitation: inputs with embedded null bytes CAN collide.
    ///
    /// Mitigation: namespace/name values must not contain null bytes — this is
    /// enforced at the API level (MCP/CLI inputs, CBOR decode validation).
    /// The hash function itself does not re-validate its inputs.
    #[test]
    fn logical_key_hash_null_byte_in_input_can_collide_known_limitation() {
        // ("a\x00b", "c") and ("a", "b\x00c") produce identical BLAKE3 streams.
        // This is a known limitation when null bytes appear in inputs.
        let k1 = LogicalKey {
            namespace: "a\x00b".to_string(),
            name: "c".to_string(),
        };
        let k2 = LogicalKey {
            namespace: "a".to_string(),
            name: "b\x00c".to_string(),
        };
        // These DO collide — document this property explicitly.
        assert_eq!(
            k1.hash(),
            k2.hash(),
            "KNOWN LIMITATION: null bytes in namespace/name can cause LogicalKey hash collisions; \
             prevent via input validation at API boundaries"
        );
    }

    /// KEY-HASH-3: different namespace produces different hash (cross-namespace separation).
    #[test]
    fn logical_key_hash_cross_namespace_separation() {
        let k1 = LogicalKey {
            namespace: "ns1".to_string(),
            name: "key".to_string(),
        };
        let k2 = LogicalKey {
            namespace: "ns2".to_string(),
            name: "key".to_string(),
        };
        assert_ne!(
            k1.hash(),
            k2.hash(),
            "keys in different namespaces must produce different hashes"
        );
    }

    /// KEY-HASH-4: well-formed keys (no null bytes) are always domain-separated.
    #[test]
    fn logical_key_hash_well_formed_keys_are_distinct() {
        let keys = [
            LogicalKey {
                namespace: "ns".to_string(),
                name: "a".to_string(),
            },
            LogicalKey {
                namespace: "ns".to_string(),
                name: "b".to_string(),
            },
            LogicalKey {
                namespace: "ns2".to_string(),
                name: "a".to_string(),
            },
            LogicalKey {
                namespace: "".to_string(),
                name: "key".to_string(),
            },
            LogicalKey {
                namespace: "key".to_string(),
                name: "".to_string(),
            },
        ];
        let hashes: Vec<[u8; 32]> = keys.iter().map(|k| k.hash()).collect();
        for i in 0..hashes.len() {
            for j in (i + 1)..hashes.len() {
                assert_ne!(
                    hashes[i], hashes[j],
                    "well-formed keys[{}] and keys[{}] must hash differently",
                    i, j
                );
            }
        }
    }
}
