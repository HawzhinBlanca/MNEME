//! Signed root authenticity (§9.3 step 1).

use mneme_core::{MnemeError, Root, RootPreimage};
use mneme_crypto::{TrustConfig, public_key_from_bytes, verify_signature_bytes};
use mneme_root::{check_replay, verify_root_chain};

/// Root signature, chain succession, and replay gate.
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
    if bound.hash() != root.preimage_hash {
        return Err(MnemeError::RootSigInvalid);
    }
    let mut verified = false;
    for pk_bytes in &trust.operator_keys {
        let pk = public_key_from_bytes(pk_bytes)?;
        if verify_signature_bytes(&pk, &root.preimage_hash, &root.signature).is_ok() {
            verified = true;
            break;
        }
    }
    if !verified {
        return Err(MnemeError::RootSigInvalid);
    }
    verify_root_chain(root, previous)?;
    check_replay(root, trust.last_seen_hlc)?;
    Ok(())
}
