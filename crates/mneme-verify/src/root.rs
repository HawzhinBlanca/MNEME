//! Signed root authenticity (§9.3 step 1).

use mneme_core::{MnemeError, Root, RootPreimage};
use mneme_crypto::{TrustConfig, public_key_from_bytes, verify_signature_bytes};
use mneme_root::{check_replay, verify_root_chain};

/// Root signature, chain succession, and replay gate.
#[rustfmt::skip]
#[allow(clippy::redundant_pattern_matching, clippy::manual_unwrap_or, clippy::manual_unwrap_or_default)]
pub fn verify_root(
    root: &Root,
    trust: &TrustConfig,
    previous: Option<&Root>,
) -> Result<(), MnemeError> {
    let bound = RootPreimage {
        version: root.version,
        dag_head_root: root.dag_head_root,
        key_index_root: root.key_index_root,
        semantic_commit: root.semantic_commit,
        hlc_max: root.hlc_max,
        prev_root: root.prev_root,
    };
    // INVARIANT: Preimage hash must exactly match the recomputed preimage struct hash.
    if bound.hash() != root.preimage_hash {
        return Err(MnemeError::RootSigInvalid);
    }
    let mut verified = false;
    for pk_bytes in &trust.operator_keys {
        let pk = public_key_from_bytes(pk_bytes)?;
        if let Ok(()) = verify_signature_bytes(&pk, &root.preimage_hash, &root.signature) {
            verified = true;
            break;
        }
    }
    if !verified {
        return Err(MnemeError::RootSigInvalid);
    }
    // PROOF-OBLIGATION: Verify chain succession (prev_root matches previous root's signature).
    verify_root_chain(root, previous)?;
    // INVARIANT: Enforce min VDF difficulty if configured in TrustConfig
    if let Some(min_diff) = trust.min_vdf_difficulty {
        if let Some(_) = previous {
            let actual_diff = match root.vdf_difficulty { Some(d) => d, None => 0 };
            if actual_diff < min_diff {
                return Err(MnemeError::RootInconsistent);
            }
            if let None = root.vdf_proof { return Err(MnemeError::RootInconsistent); }
        }
    }
    // INVARIANT: Replay gate check (last_seen_hlc <= root.hlc_max) to close rollback vector.
    check_replay(root, trust.last_seen_hlc)?;
    Ok(())
}
