//! `verify-forget-absence` — Trick #3 offline non-use scan.

use mneme_core::{DistanceMetric, MnemeError, Procedure, ProcedureAlgo};
use mneme_crypto::TrustConfig;
use mneme_index::{
    FORGET_ABSENCE_HONESTY, ForgetAbsenceRequest, PostForgetCert, PreForgetAnchorCert,
    verify_forget_absence,
};
use std::fs;
use std::path::{Path, PathBuf};

pub fn run_verify_forget_absence(
    forget_sequence: u64,
    target_commit: [u8; 32],
    cognition_cert_commit: Option<[u8; 32]>,
    post_certs: &[PathBuf],
    anchor_cert: Option<&Path>,
    trust: &TrustConfig,
    proc: &Procedure,
) -> Result<(), MnemeError> {
    let mut cert_bytes_storage = Vec::with_capacity(post_certs.len());
    for path in post_certs {
        cert_bytes_storage.push(fs::read(path).map_err(|e| MnemeError::IoFailed {
            path: path.display().to_string(),
            kind: e.to_string(),
        })?);
    }
    let post_entries: Vec<PostForgetCert<'_>> = cert_bytes_storage.iter().map(|b| PostForgetCert { cert_bytes: b }).collect();
    let anchor_storage;
    let pre_anchor = if let Some(path) = anchor_cert {
        anchor_storage = fs::read(path).map_err(|e| MnemeError::IoFailed {
            path: path.display().to_string(),
            kind: e.to_string(),
        })?;
        Some(PreForgetAnchorCert { cert_bytes: &anchor_storage })
    } else { None };
    verify_forget_absence(
        &ForgetAbsenceRequest {
            forget_sequence,
            target_commit,
            cognition_cert_commit,
            post_forget_certs: &post_entries,
            pre_forget_anchor: pre_anchor,
        },
        trust,
        proc,
    )
}

pub fn verify_forget_absence_honesty_footer() -> &'static str { FORGET_ABSENCE_HONESTY }

pub fn default_procedure(ef_search: u32, k: u32) -> Procedure {
    Procedure {
        algo: ProcedureAlgo::Hnsw,
        ef_search,
        k,
        distance: DistanceMetric::SquaredL2I64,
        seed: 0,
    }
}
