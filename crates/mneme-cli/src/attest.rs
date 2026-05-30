//! Sigstore/in-toto compatible attestation over a root checkpoint (§15.2).

use serde_json::json;
use sha2::{Digest, Sha256};

/// Build a Sigstore-style in-toto statement (no network upload).
pub fn sigstore_statement(root_bytes: &[u8]) -> serde_json::Value {
    let digest = hex::encode(Sha256::digest(root_bytes));
    json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{
            "name": "mneme-root",
            "digest": { "sha256": digest }
        }],
        "predicateType": "https://mneme.dev/attestation/root/v1",
        "predicate": {
            "kind": "mneme-root-checkpoint",
            "honesty": "authenticated integrity only; not truth or exact-NN"
        }
    })
}
