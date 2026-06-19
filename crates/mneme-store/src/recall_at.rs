//! Bi-temporal verified recall (`recall_verified_at`, Phase I P1-2).

use crate::Store;
use crate::layout;
use mneme_cap::Capability;
use mneme_core::{
    AsOf, Entry, HlcWire, MnemeError, ObjectId, ObjectRecord, Procedure, Query, Root,
    from_bytes_strict, valid_time_from_ext,
};
use mneme_crypto::TrustConfig;
use mneme_index::SemanticIndex;
use mneme_root::CheckpointLog;
use mneme_verify::{RecallContext, SemanticRecallInput, verify_recall, verify_semantic_recall};

impl Store {
    /// Verified recall bound to a historical signed root or valid-time filter (Phase I).
    pub fn recall_verified_at(
        &self,
        query: &Query,
        proc: &Procedure,
        cap: &Capability,
        as_of: AsOf,
    ) -> Result<Vec<Entry>, MnemeError> {
        self.authorize_read(query, cap)?;
        match as_of {
            AsOf::RootSeq(seq) => self.recall_verified_at_root_seq(query, proc, cap, seq),
            AsOf::ValidTime(t) => self.recall_verified_at_valid_time(query, proc, cap, t),
        }
    }

    fn recall_verified_at_root_seq(
        &self,
        query: &Query,
        proc: &Procedure,
        cap: &Capability,
        seq: u64,
    ) -> Result<Vec<Entry>, MnemeError> {
        let head = layout::read_head(&self.path)?;
        let stored = CheckpointLog::read_checkpoint(&self.path, seq).map_err(|e| {
            if matches!(e, MnemeError::IoFailed { .. }) {
                MnemeError::HistoricalRecallInvalid
            } else {
                e
            }
        })?;
        stored.verify_signature(&self.operator.verifying_key())?;
        if seq > head.sequence {
            return Err(MnemeError::HistoricalRecallInvalid);
        }
        let trust = TrustConfig::new(self.operator.public_key_bytes());
        mneme_root::verify_checkpoint_chain(&self.path, &trust.operator_keys, &head)?;
        let historical = stored.to_root();
        let previous = self.previous_root_at_seq(seq)?;
        if seq == head.sequence {
            return self.recall_verified_bound_to_root(
                query,
                proc,
                cap,
                &historical,
                previous.as_ref(),
            );
        }
        let snap_index = layout::load_key_index_at_seq(&self.path, seq)?;
        if snap_index.root() != historical.key_index_root {
            return Err(MnemeError::HistoricalRecallInvalid);
        }
        if mneme_index::is_key_index_procedure(proc) {
            return self.recall_key_at_index(
                query,
                proc,
                cap,
                &historical,
                &snap_index,
                previous.as_ref(),
            );
        }
        let semantic = self.semantic_as_of(&historical)?;
        self.recall_semantic_at_index(query, proc, cap, &historical, &semantic, previous.as_ref())
    }

    fn recall_verified_at_valid_time(
        &self,
        query: &Query,
        proc: &Procedure,
        cap: &Capability,
        bound_ms: u64,
    ) -> Result<Vec<Entry>, MnemeError> {
        let root = self.current_root()?;
        if mneme_index::is_key_index_procedure(proc) {
            let entries = self.recall_verified(query, proc, cap)?;
            return Ok(filter_entries_valid_time(entries, bound_ms));
        }
        // Valid-time is a *content attribute*, not a signed checkpoint — there is no
        // "signed root at valid-time t". So this is a fully VERIFIED semantic recall over
        // the current signed root (the receipt binds to `root.semantic_commit`), followed
        // by a post-filter on the verified entries by valid_time. The previous approach
        // rebuilt a valid-time-filtered sub-index whose commit never matched the signed
        // root, so `verify_semantic_receipt` always failed closed — non-functional. This
        // version is both sound (entries are receipt-verified) and functional.
        let previous = self.session_previous_root();
        let entries = self.recall_semantic_at_index(
            query,
            proc,
            cap,
            &root,
            &self.semantic,
            previous.as_ref(),
        )?;
        Ok(filter_entries_valid_time(entries, bound_ms))
    }

    fn recall_verified_bound_to_root(
        &self,
        query: &Query,
        proc: &Procedure,
        cap: &Capability,
        root: &Root,
        previous: Option<&Root>,
    ) -> Result<Vec<Entry>, MnemeError> {
        if mneme_index::is_key_index_procedure(proc) {
            return self.recall_key_at_index(query, proc, cap, root, &self.key_index, previous);
        }
        self.recall_semantic_at_index(query, proc, cap, root, &self.semantic, previous)
    }

    fn recall_key_at_index(
        &self,
        query: &Query,
        _proc: &Procedure,
        _cap: &Capability,
        root: &Root,
        key_index: &mneme_index::KeyIndex,
        previous: Option<&Root>,
    ) -> Result<Vec<Entry>, MnemeError> {
        let proof = key_index.prove_membership(&query.logical_key)?;
        let receipt = mneme_core::Receipt {
            root_bound: root.preimage_hash,
            logical_key: query.logical_key.hash(),
            object_id: proof.value,
            membership_proof: proof.path,
            key_index_root: root.key_index_root,
            leaf_index: proof.leaf_index,
        };
        let id = ObjectId(proof.value);
        let bytes = self
            .objects
            .get(id.as_bytes())
            .ok_or(MnemeError::ObjectTampered)?;
        from_bytes_strict::<ObjectRecord>(bytes).map_err(|_| MnemeError::ObjectTampered)?;
        self.enforce_min_tier(query, &id)?;
        let input = mneme_verify::RecallInput {
            receipt,
            root: root.clone(),
            object_bytes: bytes.clone(),
        };
        let objects =
            crate::provenance_objects_for_ids(&self.objects, std::slice::from_ref(id.as_bytes()))?;
        let ctx = RecallContext {
            key_index: self.key_index.tree(),
            dag: &self.dag,
            objects: &objects,
            previous_root: previous,
        };
        let mut entries = verify_recall(&input, query, &self.trust, &ctx)?;
        self.decrypt_entries(&mut entries)?;
        Ok(entries)
    }

    fn recall_semantic_at_index(
        &self,
        query: &Query,
        proc: &Procedure,
        _cap: &Capability,
        root: &Root,
        semantic: &SemanticIndex,
        previous: Option<&Root>,
    ) -> Result<Vec<Entry>, MnemeError> {
        let embedding = query
            .embedding
            .as_ref()
            .ok_or(MnemeError::ProcedureMismatch)?;
        let receipt = semantic
            .recall_receipt_zkann(
                proc,
                embedding,
                root.preimage_hash,
                mneme_core::RetrievalProofLevel::ProcedureFaithfulTopK,
            )
            .map_err(crate::index_err)?;
        let mut seed_ids: Vec<[u8; 32]> = receipt
            .verification_object
            .candidates
            .iter()
            .map(|(id, _, _)| *id.as_bytes())
            .collect();
        seed_ids.sort();
        seed_ids.dedup();
        let objects = crate::provenance_objects_for_ids(&self.objects, &seed_ids)?;
        let input = SemanticRecallInput {
            receipt,
            root: root.clone(),
        };
        let ctx = RecallContext {
            key_index: self.key_index.tree(),
            dag: &self.dag,
            objects: &objects,
            previous_root: previous,
        };
        let mut entries = verify_semantic_recall(&input, proc, query, &self.trust, &ctx)?;
        self.decrypt_entries(&mut entries)?;
        Ok(entries)
    }

    fn previous_root_at_seq(&self, seq: u64) -> Result<Option<Root>, MnemeError> {
        if seq <= 1 {
            return Ok(None);
        }
        let stored = CheckpointLog::read_checkpoint(&self.path, seq - 1)?;
        stored.verify_signature(&self.operator.verifying_key())?;
        Ok(Some(stored.to_root()))
    }

    fn session_previous_root(&self) -> Option<Root> {
        if self.roots.len() > 1 {
            Some(self.roots[self.roots.len() - 2].clone())
        } else {
            None
        }
    }

    fn semantic_as_of(&self, root: &Root) -> Result<SemanticIndex, MnemeError> {
        let mut index = SemanticIndex::new();
        for (id, bytes) in &self.objects {
            let record: ObjectRecord =
                from_bytes_strict(bytes).map_err(|_| MnemeError::ObjectTampered)?;
            if hlc_wire_bytes(&record.hlc) > root.hlc_max {
                continue;
            }
            if let Some(emb) = self.embeddings.get(id) {
                index
                    .insert(ObjectId(*id), emb.clone())
                    .map_err(crate::index_err)?;
            }
        }
        if index.semantic_commit() != root.semantic_commit {
            return Err(MnemeError::HistoricalRecallInvalid);
        }
        Ok(index)
    }
}

fn hlc_wire_bytes(h: &HlcWire) -> [u8; 14] {
    mneme_core::Hlc {
        wall_ms: h.wall_ms,
        counter: h.counter,
        node_id: mneme_core::NodeId::from_bytes(h.node_id),
    }
    .to_bytes()
}

fn filter_entries_valid_time(entries: Vec<Entry>, bound_ms: u64) -> Vec<Entry> {
    entries
        .into_iter()
        .filter(|e| valid_time_from_ext(&e.record.ext).is_none_or(|t| t <= bound_ms))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mneme_core::{
        EXT_VALID_TIME_MS, HlcWire, ObjectId, ObjectRecord, PayloadEnc, ext_map_with_valid_time,
        valid_time_from_ext,
    };

    fn make_entry(valid_time_ms: Option<u64>) -> Entry {
        let ext = valid_time_ms.map(ext_map_with_valid_time);
        let record = ObjectRecord {
            version: 1,
            kind: 1,
            parent_ids: vec![],
            writer: [0u8; 32],
            session: [0u8; 16],
            hlc: HlcWire {
                wall_ms: 0,
                counter: 0,
                node_id: [0u8; 16],
            },
            trust_tier: 1,
            payload_enc: PayloadEnc {
                alg: 0,
                key_id: None,
                nonce: None,
                body: vec![],
            },
            embedding_commit: None,
            redaction_slot: None,
            ext,
        };
        Entry {
            id: ObjectId([0u8; 32]),
            record,
            plaintext: vec![],
        }
    }

    /// All entries without a valid_time pass through regardless of bound.
    #[test]
    fn filter_valid_time_no_ext_always_passes() {
        let entries = vec![make_entry(None), make_entry(None)];
        let result = filter_entries_valid_time(entries, 0);
        assert_eq!(
            result.len(),
            2,
            "entries without valid_time must always pass"
        );
    }

    /// Entries at exactly the bound must pass (boundary inclusive).
    #[test]
    fn filter_valid_time_boundary_inclusive() {
        let entries = vec![make_entry(Some(100))];
        let at_bound = filter_entries_valid_time(entries, 100);
        assert_eq!(at_bound.len(), 1, "entry at exactly bound must pass (<=)");
    }

    /// Entries after the bound must be filtered out.
    #[test]
    fn filter_valid_time_after_bound_excluded() {
        let entries = vec![make_entry(Some(101))];
        let before = filter_entries_valid_time(entries, 100);
        assert!(before.is_empty(), "entry after bound must be excluded");
    }

    /// Mixed: some pass, some are filtered.
    #[test]
    fn filter_valid_time_mixed_boundary() {
        let entries = vec![
            make_entry(None),       // no valid_time: always passes
            make_entry(Some(50)),   // before bound: passes
            make_entry(Some(100)),  // at bound: passes (<=)
            make_entry(Some(101)),  // after bound: filtered
            make_entry(Some(9999)), // far future: filtered
        ];
        let result = filter_entries_valid_time(entries, 100);
        assert_eq!(
            result.len(),
            3,
            "should have 3 passing entries: None, 50, 100"
        );
    }

    /// ext_map_with_valid_time must encode and valid_time_from_ext must decode correctly.
    #[test]
    fn ext_map_round_trips_valid_time() {
        for ms in [0u64, 1, 100, u64::MAX / 2, u64::MAX - 1] {
            let map = ext_map_with_valid_time(ms);
            assert!(map.contains_key(&EXT_VALID_TIME_MS));
            let decoded = valid_time_from_ext(&Some(map));
            assert_eq!(decoded, Some(ms), "round-trip failed for ms={ms}");
        }
        assert_eq!(valid_time_from_ext(&None), None);
    }

    /// hlc_wire_bytes must produce a 14-byte array with correct LE fields.
    #[test]
    fn hlc_wire_bytes_round_trips_wall_ms() {
        let wire = HlcWire {
            wall_ms: 0xDEAD_BEEF_CAFE_0001,
            counter: 42,
            node_id: [0xAB; 16],
        };
        let bytes = hlc_wire_bytes(&wire);
        let wall = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        assert_eq!(wall, wire.wall_ms);
        let counter = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        assert_eq!(counter, wire.counter);
    }
}
