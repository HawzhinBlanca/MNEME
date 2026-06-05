//! Bi-temporal verified recall (`recall_verified_at`, Phase I P1-2).

use crate::Store;
use crate::layout;
use mneme_cap::Capability;
#[cfg(feature = "experimental_semantic")]
use mneme_core::HlcWire;
use mneme_core::{
    AsOf, Entry, MnemeError, ObjectId, ObjectRecord, Procedure, Query, Root, from_bytes_strict,
    valid_time_from_ext,
};
use mneme_crypto::TrustConfig;
#[cfg(feature = "experimental_semantic")]
use mneme_index::SemanticIndex;
use mneme_root::CheckpointLog;
use mneme_verify::{RecallContext, verify_recall};
#[cfg(feature = "experimental_semantic")]
use mneme_verify::{SemanticRecallInput, verify_semantic_recall};

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
        #[cfg(feature = "experimental_semantic")]
        {
            let semantic = self.semantic_as_of(&historical)?;
            self.recall_semantic_at_index(
                query,
                proc,
                cap,
                &historical,
                &semantic,
                previous.as_ref(),
            )
        }
        #[cfg(not(feature = "experimental_semantic"))]
        {
            Err(MnemeError::ProcedureMismatch)
        }
    }

    fn recall_verified_at_valid_time(
        &self,
        query: &Query,
        proc: &Procedure,
        cap: &Capability,
        bound_ms: u64,
    ) -> Result<Vec<Entry>, MnemeError> {
        if mneme_index::is_key_index_procedure(proc) {
            let entries = self.recall_verified(query, proc, cap)?;
            return Ok(filter_entries_valid_time(entries, bound_ms));
        }
        #[cfg(feature = "experimental_semantic")]
        {
            let root = self.current_root()?;
            // Valid-time is a *content attribute*, not a signed checkpoint — there is no
            // "signed root at valid-time t". So this is a fully VERIFIED semantic recall over
            // the current signed root (the receipt binds to `root.semantic_commit`), followed
            // by a post-filter on the verified entries by valid_time.
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
        #[cfg(not(feature = "experimental_semantic"))]
        {
            Err(MnemeError::ProcedureMismatch)
        }
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
        #[cfg(feature = "experimental_semantic")]
        {
            self.recall_semantic_at_index(query, proc, cap, root, &self.semantic, previous)
        }
        #[cfg(not(feature = "experimental_semantic"))]
        {
            Err(MnemeError::ProcedureMismatch)
        }
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

    #[cfg(feature = "experimental_semantic")]
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
                mneme_core::RetrievalProofLevel::ExactDominance,
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

    #[cfg(feature = "experimental_semantic")]
    fn session_previous_root(&self) -> Option<Root> {
        if self.roots.len() > 1 {
            Some(self.roots[self.roots.len() - 2].clone())
        } else {
            None
        }
    }

    #[cfg(feature = "experimental_semantic")]
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

#[cfg(feature = "experimental_semantic")]
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
