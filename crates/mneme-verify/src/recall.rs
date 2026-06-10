//! `verify_recall` fail-closed gate (§9.3).

use crate::proof::verify_membership_proof;
use crate::root::verify_root;
use mneme_core::{
    Entry, MnemeError, ObjectId, ObjectRecord, Query, Receipt, Root, TrustTier, from_bytes_strict,
    hash_obj, object::OBJECT_VERSION,
};
use mneme_crypto::TrustConfig;
use mneme_dag::DagIndex;
use mneme_smt::{MembershipProof, SparseMerkleTree, TOMBSTONE};
use std::collections::BTreeMap;

pub struct RecallInput {
    pub receipt: Receipt,
    pub object_bytes: Vec<u8>,
    pub root: Root,
}

pub struct RecallContext<'a> {
    pub key_index: &'a SparseMerkleTree,
    pub dag: &'a DagIndex,
    pub objects: &'a BTreeMap<[u8; 32], Vec<u8>>,
    pub previous_root: Option<&'a Root>,
}

pub fn verify_recall(
    recall: &RecallInput,
    query: &Query,
    trust: &TrustConfig,
    ctx: &RecallContext<'_>,
) -> Result<Vec<Entry>, MnemeError> {
    verify_root(&recall.root, trust, ctx.previous_root)?;
    // INVARIANT: Receipt binding matches the query logical key and current signed root.
    verify_receipt_binding(&recall.receipt, &recall.root, query)?;
    verify_key_index_membership(&recall.receipt, &recall.root)?;

    // INVARIANT: Recomputed object hash matches the receipt object_id to prevent content tampering.
    let computed_id = hash_obj(&recall.object_bytes);
    if computed_id != recall.receipt.object_id {
        return Err(MnemeError::ObjectTampered);
    }

    let record: ObjectRecord = from_bytes_strict(&recall.object_bytes)?;
    if record.version != OBJECT_VERSION {
        return Err(unsupported_object_version_error(record.version));
    }

    // PROOF-OBLIGATION: Verify Merkle DAG parent/head integrity (provenance chain check).
    verify_provenance(&record, ctx)?;
    verify_writer_and_tier(&record, trust, query)?;
    // INVARIANT: Tombstone/forgotten check (anti-replay and shredded memory rejection).
    verify_not_forgotten(&recall.receipt.logical_key, ctx.key_index)?;

    // F-6 layering contract: the TCB returns the integrity/provenance/authorization-
    // verified `ObjectRecord`. `Entry.plaintext` here is the AEAD *ciphertext* body
    // (`payload_enc.body`); AEAD-open against the per-key AAD is performed by the
    // store layer, which alone holds the key vault. Keeping decryption out preserves
    // the minimal TCB (§17.6). A wholly-missing key (vs the tombstone gate above)
    // likewise fails closed one layer out: no receipt → `ReceiptRootMismatch`,
    // never plaintext.
    Ok(vec![Entry {
        id: ObjectId(computed_id),
        record: record.clone(),
        plaintext: record.payload_enc.body.clone(),
    }])
}

fn verify_receipt_binding(receipt: &Receipt, root: &Root, query: &Query) -> Result<(), MnemeError> {
    let key_hash = query.logical_key.hash();
    if receipt.root_bound != root.preimage_hash {
        return Err(MnemeError::ReceiptRootMismatch);
    }
    if receipt.key_index_root != root.key_index_root {
        return Err(MnemeError::ReceiptRootMismatch);
    }
    if receipt.logical_key != key_hash {
        return Err(MnemeError::ReceiptRootMismatch);
    }
    Ok(())
}

pub(crate) fn unsupported_object_version_error(version: u16) -> MnemeError {
    MnemeError::UnsupportedVersion { got: version }
}

fn verify_key_index_membership(receipt: &Receipt, root: &Root) -> Result<(), MnemeError> {
    if receipt.key_index_root != root.key_index_root {
        return Err(MnemeError::ReceiptRootMismatch);
    }
    let proof = MembershipProof {
        key: receipt.logical_key,
        value: receipt.object_id,
        path: receipt.membership_proof.clone(),
        root: receipt.key_index_root,
        leaf_index: receipt.leaf_index,
    };
    verify_membership_proof(&proof)
}

pub(crate) fn verify_provenance(
    record: &ObjectRecord,
    ctx: &RecallContext<'_>,
) -> Result<(), MnemeError> {
    for parent in &record.parent_ids {
        let bytes = ctx
            .objects
            .get(parent)
            .ok_or(MnemeError::ProvenanceBroken)?;
        if hash_obj(bytes) != *parent {
            return Err(MnemeError::ProvenanceBroken);
        }
    }
    Ok(())
}

pub(crate) fn verify_writer_and_tier(
    record: &ObjectRecord,
    trust: &TrustConfig,
    query: &Query,
) -> Result<(), MnemeError> {
    if !trust.trusts_writer(&record.writer) {
        return Err(MnemeError::UnauthorizedWriter);
    }
    let obj_tier = TrustTier::from_u8(record.trust_tier)?;
    if obj_tier < query.min_tier {
        return Err(MnemeError::BelowTierPolicy {
            required: query.min_tier.as_u8(),
            got: obj_tier.as_u8(),
        });
    }
    Ok(())
}

fn verify_not_forgotten(
    key_hash: &[u8; 32],
    key_index: &SparseMerkleTree,
) -> Result<(), MnemeError> {
    if key_index.is_tombstoned(key_hash) || key_index.get(key_hash) == Some(TOMBSTONE) {
        return Err(MnemeError::Forgotten);
    }
    Ok(())
}
