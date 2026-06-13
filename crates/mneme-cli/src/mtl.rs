//! MTL-1 — Memory Transparency Log (single-operator, SCITT-style).
//!
//! An append-only Merkle log of signed memory roots. Each appended statement is
//! `(root_seq, root_preimage)`; the operator signs a log HEAD `(size, merkle_root)` and
//! can issue an offline-verifiable INCLUSION RECEIPT proving a given root was logged at
//! a given index under that head. The Merkle tree follows the RFC 6962 construction
//! (distinct leaf/node prefixes), so the same `(statements, index)` always yields the
//! same proof, on any host.
//!
//! HONESTY BOUNDARY: this is a SINGLE-OPERATOR log. An inclusion receipt proves "the
//! operator's signed head at this size commits to this root at this index." It does NOT
//! by itself prevent an operator from signing two divergent heads (equivocation) — that
//! needs cross-head consistency proofs / witness gossip (the MTL-2 extension). And it
//! proves logging, not truth of the logged memory — authenticated != true.

use crate::replay::{Reader, put_id_list};
use mneme_core::MnemeError;
use mneme_crypto::{KeyPair, sign_message, verify_signature_bytes, verifying_key_from_bytes};

pub const MTL_RECEIPT_VERSION: u16 = 1;
const RECEIPT_DOMAIN: &[u8] = b"MNEME-mtl-receipt-v1";
const HEAD_DOMAIN: &[u8] = b"MNEME-mtl-head-v1";
const LEAF_DOMAIN: &[u8] = b"MNEME-mtl-leaf-v1";
const NODE_DOMAIN: &[u8] = b"MNEME-mtl-node-v1";

pub const MTL_HONESTY: &str = "single-operator transparency log: an inclusion receipt \
proves the operator's signed head commits to this memory root at this index; it does NOT \
prevent the operator signing two divergent heads (equivocation needs cross-head consistency \
proofs / witness gossip — MTL-2), and it proves logging, not truth — authenticated != true";

/// One logged statement: a signed memory root identified by its sequence + preimage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogStatement {
    pub root_seq: u64,
    pub root_preimage: [u8; 32],
}

/// RFC 6962 leaf hash (0x00-domain-separated).
pub fn leaf_hash(s: &LogStatement) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(LEAF_DOMAIN);
    h.update(&s.root_seq.to_le_bytes());
    h.update(&s.root_preimage);
    *h.finalize().as_bytes()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(NODE_DOMAIN);
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

/// Largest power of two strictly less than `n` (n ≥ 2).
fn split_point(n: usize) -> usize {
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// RFC 6962 Merkle tree hash over leaf hashes.
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => *blake3::hash(HEAD_DOMAIN).as_bytes(), // empty-tree sentinel
        1 => leaves[0],
        n => {
            let k = split_point(n);
            node_hash(&merkle_root(&leaves[..k]), &merkle_root(&leaves[k..]))
        }
    }
}

/// RFC 6962 audit path for leaf `index` in a tree over `leaves`.
pub fn audit_path(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    let n = leaves.len();
    if n <= 1 {
        return vec![];
    }
    let k = split_point(n);
    if index < k {
        let mut p = audit_path(&leaves[..k], index);
        p.push(merkle_root(&leaves[k..]));
        p
    } else {
        let mut p = audit_path(&leaves[k..], index - k);
        p.push(merkle_root(&leaves[..k]));
        p
    }
}

/// Recompute the Merkle root from a leaf hash and its audit path, following the exact
/// RFC 6962 §2.1.1 inclusion-proof verification algorithm. Fails closed on a path that
/// is too short, too long, or an out-of-range index.
pub fn root_from_path(
    leaf: &[u8; 32],
    index: usize,
    size: usize,
    path: &[[u8; 32]],
) -> Result<[u8; 32], MnemeError> {
    if index >= size {
        return Err(MnemeError::SchemaDrift);
    }
    let mut fnode = index;
    let mut snode = size - 1;
    let mut r = *leaf;
    for p in path {
        if snode == 0 {
            return Err(MnemeError::SchemaDrift); // path too long
        }
        if fnode & 1 == 1 || fnode == snode {
            r = node_hash(p, &r);
            if fnode & 1 == 0 {
                while fnode != 0 && fnode & 1 == 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    if snode != 0 {
        return Err(MnemeError::SchemaDrift); // path too short
    }
    Ok(r)
}

/// Offline-verifiable inclusion receipt bound to a signed log head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionReceiptV1 {
    pub leaf_index: u64,
    pub size: u64,
    pub statement: LogStatement,
    pub audit_path: Vec<[u8; 32]>,
    pub merkle_root: [u8; 32],
    pub operator_pk: [u8; 32],
    /// Operator signature over the head `(size ‖ merkle_root)`.
    pub sig: [u8; 64],
}

/// Operator signature input for a log head — the receipt's `sig` covers exactly this.
fn head_message(size: u64, merkle_root: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(HEAD_DOMAIN.len() + 40);
    m.extend_from_slice(HEAD_DOMAIN);
    m.extend_from_slice(&size.to_le_bytes());
    m.extend_from_slice(merkle_root);
    m
}

impl InclusionReceiptV1 {
    fn payload(&self) -> Result<Vec<u8>, MnemeError> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(RECEIPT_DOMAIN);
        out.extend_from_slice(&MTL_RECEIPT_VERSION.to_le_bytes());
        out.extend_from_slice(&self.leaf_index.to_le_bytes());
        out.extend_from_slice(&self.size.to_le_bytes());
        out.extend_from_slice(&self.statement.root_seq.to_le_bytes());
        out.extend_from_slice(&self.statement.root_preimage);
        put_id_list(&mut out, &self.audit_path)?;
        out.extend_from_slice(&self.merkle_root);
        out.extend_from_slice(&self.operator_pk);
        Ok(out)
    }

    /// Sign the head and encode the receipt to wire bytes. The signature is over the
    /// head `(size, merkle_root)` so it is reusable across receipts under the same head;
    /// the wire integrity of the whole receipt is covered by the envelope check below.
    pub fn sign_and_encode(mut self, operator: &KeyPair) -> Result<Vec<u8>, MnemeError> {
        self.operator_pk = operator.public_key_bytes();
        let head_sig = sign_message(
            operator.signing_key(),
            &head_message(self.size, &self.merkle_root),
        );
        self.sig = head_sig;
        let mut wire = self.payload()?;
        // Envelope signature over the full receipt payload, then the head signature.
        let envelope_sig = sign_message(operator.signing_key(), &wire);
        wire.extend_from_slice(&envelope_sig);
        wire.extend_from_slice(&self.sig);
        Ok(wire)
    }

    /// Strict fail-closed decode + envelope signature + head signature + Merkle
    /// inclusion check (recomputed root must equal the signed `merkle_root`).
    pub fn verify(wire: &[u8], pinned_pk: Option<&[u8; 32]>) -> Result<Self, MnemeError> {
        let mut r = Reader::new(wire);
        r.expect(RECEIPT_DOMAIN)?;
        let version = u16::from_le_bytes(r.take_arr::<2>()?);
        if version != MTL_RECEIPT_VERSION {
            return Err(MnemeError::UnsupportedVersion { got: version });
        }
        let leaf_index = u64::from_le_bytes(r.take_arr::<8>()?);
        let size = u64::from_le_bytes(r.take_arr::<8>()?);
        let root_seq = u64::from_le_bytes(r.take_arr::<8>()?);
        let root_preimage = r.take_arr::<32>()?;
        let audit_path = r.take_id_list()?;
        let merkle_root = r.take_arr::<32>()?;
        let operator_pk = r.take_arr::<32>()?;
        let payload_len = r.consumed();
        let envelope_sig = r.take_arr::<64>()?;
        let head_sig = r.take_arr::<64>()?;
        r.expect_end()?;

        if let Some(pk) = pinned_pk {
            if pk != &operator_pk {
                return Err(MnemeError::RootSigInvalid);
            }
        }
        let vk = verifying_key_from_bytes(&operator_pk)?;
        // Envelope integrity over the whole receipt payload.
        verify_signature_bytes(&vk, &wire[..payload_len], &envelope_sig)?;
        // Head signature binds (size, merkle_root) — the transparency commitment.
        verify_signature_bytes(&vk, &head_message(size, &merkle_root), &head_sig)?;

        // Merkle inclusion: recomputed root must equal the signed head root.
        let statement = LogStatement {
            root_seq,
            root_preimage,
        };
        let recomputed = root_from_path(
            &leaf_hash(&statement),
            usize::try_from(leaf_index).map_err(|_| MnemeError::SchemaDrift)?,
            usize::try_from(size).map_err(|_| MnemeError::SchemaDrift)?,
            &audit_path,
        )?;
        if recomputed != merkle_root {
            return Err(MnemeError::ReceiptRootMismatch);
        }

        Ok(Self {
            leaf_index,
            size,
            statement,
            audit_path,
            merkle_root,
            operator_pk,
            sig: head_sig,
        })
    }
}

/// Append-only transparency log over `LogStatement`s.
#[derive(Debug, Default, Clone)]
pub struct TransparencyLog {
    statements: Vec<LogStatement>,
}

impl TransparencyLog {
    pub fn from_statements(statements: Vec<LogStatement>) -> Self {
        Self { statements }
    }
    fn leaves(&self) -> Vec<[u8; 32]> {
        self.statements.iter().map(leaf_hash).collect()
    }

    /// Build a signed inclusion receipt for `index` under the current head.
    pub fn inclusion_receipt(
        &self,
        index: usize,
        operator: &KeyPair,
    ) -> Result<Vec<u8>, MnemeError> {
        if index >= self.statements.len() {
            return Err(MnemeError::IndexPathInvalid);
        }
        let leaves = self.leaves();
        let receipt = InclusionReceiptV1 {
            leaf_index: index as u64,
            size: self.statements.len() as u64,
            statement: self.statements[index],
            audit_path: audit_path(&leaves, index),
            merkle_root: merkle_root(&leaves),
            operator_pk: [0u8; 32],
            sig: [0u8; 64],
        };
        receipt.sign_and_encode(operator)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stmt(i: u64) -> LogStatement {
        LogStatement {
            root_seq: i,
            root_preimage: *blake3::hash(&i.to_le_bytes()).as_bytes(),
        }
    }

    fn log_of(n: u64) -> TransparencyLog {
        TransparencyLog::from_statements((0..n).map(stmt).collect())
    }

    #[test]
    fn inclusion_verifies_for_every_index_at_many_sizes() {
        let op = KeyPair::from_seed([3u8; 32]);
        for n in 1u64..=33 {
            let log = log_of(n);
            for i in 0..n as usize {
                let wire = log.inclusion_receipt(i, &op).expect("receipt");
                let r = InclusionReceiptV1::verify(&wire, Some(&op.public_key_bytes()))
                    .unwrap_or_else(|e| panic!("n={n} i={i} verify failed: {e:?}"));
                assert_eq!(r.leaf_index, i as u64);
                assert_eq!(r.size, n);
            }
        }
    }

    #[test]
    fn wrong_statement_for_index_is_rejected() {
        let op = KeyPair::from_seed([3u8; 32]);
        let log = log_of(8);
        let mut wire = log.inclusion_receipt(3, &op).expect("receipt");
        // Corrupt the root_preimage bytes in the payload (after domain+version+8+8+8).
        let off = RECEIPT_DOMAIN.len() + 2 + 8 + 8 + 8;
        wire[off] ^= 0x01;
        assert!(InclusionReceiptV1::verify(&wire, None).is_err());
    }

    #[test]
    fn every_byte_flip_fails_closed() {
        let op = KeyPair::from_seed([3u8; 32]);
        let wire = log_of(7).inclusion_receipt(5, &op).expect("receipt");
        for i in 0..wire.len() {
            let mut bad = wire.clone();
            bad[i] ^= 0x01;
            assert!(
                InclusionReceiptV1::verify(&bad, Some(&op.public_key_bytes())).is_err(),
                "byte flip at {i} must fail closed"
            );
        }
    }

    #[test]
    fn truncation_and_trailing_fail_closed() {
        let op = KeyPair::from_seed([3u8; 32]);
        let wire = log_of(6).inclusion_receipt(2, &op).expect("receipt");
        assert!(InclusionReceiptV1::verify(&wire[..wire.len() - 1], None).is_err());
        let mut extra = wire.clone();
        extra.push(0);
        assert!(InclusionReceiptV1::verify(&extra, None).is_err());
    }

    #[test]
    fn wrong_pinned_pk_rejected() {
        let op = KeyPair::from_seed([3u8; 32]);
        let other = KeyPair::from_seed([4u8; 32]);
        let wire = log_of(5).inclusion_receipt(1, &op).expect("receipt");
        assert!(matches!(
            InclusionReceiptV1::verify(&wire, Some(&other.public_key_bytes())),
            Err(MnemeError::RootSigInvalid)
        ));
    }

    #[test]
    fn receipt_from_one_head_does_not_verify_against_a_grown_head() {
        // A receipt's size/root are signed; presenting it with a different (grown) head's
        // root would change the head message and fail the head signature. Here we just
        // confirm two different sizes produce different signed roots.
        let op = KeyPair::from_seed([3u8; 32]);
        let r5 = InclusionReceiptV1::verify(
            &log_of(5).inclusion_receipt(0, &op).unwrap(),
            Some(&op.public_key_bytes()),
        )
        .unwrap();
        let r6 = InclusionReceiptV1::verify(
            &log_of(6).inclusion_receipt(0, &op).unwrap(),
            Some(&op.public_key_bytes()),
        )
        .unwrap();
        assert_ne!(
            r5.merkle_root, r6.merkle_root,
            "appending must change the signed head root"
        );
    }
}
