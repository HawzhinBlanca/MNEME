//! Default-off benchmark support for isolating verified-recall overhead.
//!
//! This module is included only by `mneme-store/bench_support`. It deliberately
//! exposes the unverified assembly path for a local performance harness and must
//! not be enabled in the product API.

use crate::{Store, layout};
use mneme_cap::Capability;
use mneme_core::{Draft, FixedPointEmbedding, MnemeError, Query};

impl Store {
    /// Benchmark-only batch seed for key-index recall perf.
    #[doc(hidden)]
    pub fn bench_populate_semantic_entries(
        &mut self,
        namespace: &str,
        count: usize,
        cap: &Capability,
    ) -> Result<(), MnemeError> {
        self.verify_cap(cap)?;
        if !cap.permits_write(namespace, mneme_core::MemoryKind::Semantic) {
            return Err(MnemeError::CapDenied);
        }
        let tier = cap.default_tier();
        layout::begin_transaction(&self.path)?;
        let result = (|| -> Result<(), MnemeError> {
            self.vault.begin_batch()?;
            let mut ids = Vec::with_capacity(count);
            for i in 0..count {
                let draft = Draft {
                    namespace: namespace.into(),
                    logical_name: format!("key-{i:05}"),
                    kind: mneme_core::MemoryKind::Semantic,
                    body: b"x".to_vec(),
                    parent_ids: vec![],
                    session: [0x42; 16],
                    trust_tier: None,
                    embedding: None,
                    valid_time_ms: None,
                };
                let (id, _) = self.apply_remember_draft(&draft, cap, tier, false, false)?;
                ids.push(id);
            }
            self.vault.flush_batch()?;
            self.dag.seed_independent_heads(&ids)?;
            self.key_index.tree_mut().rebuild_root_cache();
            layout::persist_key_index(&self.path, self)?;
            layout::persist_object_keys(&self.path, self)?;
            layout::persist_embeddings(&self.path, self)?;
            self.commit_root_inner()?;
            Ok(())
        })();
        match result {
            Ok(()) => layout::commit_transaction(&self.path),
            Err(MnemeError::IncompleteTransaction) => {
                self.vault.cancel_batch();
                Err(MnemeError::IncompleteTransaction)
            }
            Err(e) => {
                self.vault.cancel_batch();
                let _ = layout::abort_transaction(&self.path);
                Err(e)
            }
        }
    }

    /// Benchmark-only batch seed for semantic-recall perf.
    #[doc(hidden)]
    pub fn bench_populate_embedded_entries(
        &mut self,
        namespace: &str,
        count: usize,
        dim: u32,
        cap: &Capability,
    ) -> Result<(), MnemeError> {
        self.verify_cap(cap)?;
        if !cap.permits_write(namespace, mneme_core::MemoryKind::Semantic) {
            return Err(MnemeError::CapDenied);
        }
        let tier = cap.default_tier();
        layout::begin_transaction(&self.path)?;
        let result = (|| -> Result<(), MnemeError> {
            let mut ids = Vec::with_capacity(count);
            for i in 0..count {
                let draft = Draft {
                    namespace: namespace.into(),
                    logical_name: format!("key-{i:05}"),
                    kind: mneme_core::MemoryKind::Semantic,
                    body: b"x".to_vec(),
                    parent_ids: vec![],
                    session: [0x42; 16],
                    trust_tier: None,
                    embedding: Some(bench_embedding(i, dim)?),
                    valid_time_ms: None,
                };
                let (id, _) = self.apply_remember_draft(&draft, cap, tier, false, false)?;
                ids.push(id);
            }
            self.dag.seed_independent_heads(&ids)?;
            self.key_index.tree_mut().rebuild_root_cache();
            layout::persist_key_index(&self.path, self)?;
            layout::persist_object_keys(&self.path, self)?;
            layout::persist_embeddings(&self.path, self)?;
            self.commit_root_inner()?;
            Ok(())
        })();
        match result {
            Ok(()) => layout::commit_transaction(&self.path),
            Err(MnemeError::IncompleteTransaction) => Err(MnemeError::IncompleteTransaction),
            Err(e) => {
                let _ = layout::abort_transaction(&self.path);
                Err(e)
            }
        }
    }

    /// Benchmark-only: run untrusted recall assembly without `verify_recall`.
    #[doc(hidden)]
    pub fn bench_recall_raw(&self, query: &Query, cap: &Capability) -> Result<(), MnemeError> {
        self.authorize_read(query, cap)?;
        let proc = mneme_index::default_key_procedure();
        let recall = self.recall(query, &proc, cap)?;
        std::hint::black_box(&recall);
        Ok(())
    }
}

/// Deterministic, well-spread embedding for the semantic benchmark.
#[doc(hidden)]
pub fn bench_embedding(i: usize, dim: u32) -> Result<FixedPointEmbedding, MnemeError> {
    if dim == 0 {
        return Err(MnemeError::SchemaDrift);
    }
    let mut components = vec![0i16; dim as usize];
    for (d, slot) in components.iter_mut().enumerate() {
        let mixed = (i as u64)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add((d as u64).wrapping_mul(0x632B_E593_7F4A_1C97));
        *slot = ((mixed >> 17) % 2048) as i16 - 1024;
    }
    FixedPointEmbedding::new(dim, 0, components)
}
