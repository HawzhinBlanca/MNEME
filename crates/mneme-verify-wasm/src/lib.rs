//! `mneme-verify-wasm` — the **browser auditor**. Compiles MNEME's offline
//! receipt-verification path to WebAssembly so a third party can verify a receipt
//! **in the browser, zero-install, without trusting the operator's server**.
//!
//! This is the moat made portable: the same fail-closed checks the CLI runs
//! (`verify-robr`, `verify-mtl`, `verify-shapley`) run client-side over wire bytes
//! the user pastes in, pinned to an operator public key they supply out-of-band.
//!
//! Each `verify_*` function takes the receipt as base64 wire bytes plus the
//! operator public key as 64 hex chars, and returns a small JSON summary on
//! success or throws the typed rejection message on failure (fail-closed).
//!
//! ## Honesty boundary (load-bearing — never weaken)
//! Verifying a receipt proves integrity / provenance / authorization (and, for the
//! transparency log, *logging*) — **not** semantic truth, **not** true
//! nearest-neighbors, **not** that a model produced a bound output, **not** model
//! learning. `authenticated != true`. Every result carries the artifact's own
//! honesty caveat.
//!
//! The crate is `crate-type = ["cdylib", "rlib"]`: the `cdylib` is the wasm
//! artifact; the `rlib` lets the verification logic be unit-tested natively.

use wasm_bindgen::prelude::*;

use base64::Engine as _;
use mneme_account::robr::{ROBR_HONESTY, RobrReceiptV1};
use mneme_receipts::mtl::{ConsistencyReceiptV1, InclusionReceiptV1};
use mneme_receipts::shapley::ShapleyCertV1;
use mneme_receipts::{MTL_HONESTY, SHAPLEY_HONESTY};

/// Decode the standard-base64 wire form a daemon/Desk/CLI emits.
fn decode_b64(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| format!("base64 decode failed: {e}"))
}

/// Parse a pinned operator public key (32 bytes / 64 hex chars).
fn parse_pk(pk_hex: &str) -> Result<[u8; 32], String> {
    let bytes =
        hex::decode(pk_hex.trim()).map_err(|e| format!("operator pk hex decode failed: {e}"))?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| "operator pk must be 32 bytes (64 hex chars)".to_string())
}

/// Verify a Recall-to-Output Binding Receipt (ROBR) offline under a pinned key.
#[wasm_bindgen]
pub fn verify_robr(receipt_b64: &str, operator_pk_hex: &str) -> Result<String, String> {
    let wire = decode_b64(receipt_b64)?;
    let pk = parse_pk(operator_pk_hex)?;
    let r = RobrReceiptV1::verify(&wire, Some(&pk)).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "ok": true,
        "kind": "robr",
        "root_seq": r.root_seq,
        "root_preimage": hex::encode(r.root_preimage),
        "prompt_hash": hex::encode(r.prompt_hash),
        "context_count": r.context_ids.len(),
        "output_token_commit": hex::encode(r.output_token_commit),
        "honesty": ROBR_HONESTY,
    })
    .to_string())
}

/// Verify an MTL transparency-log INCLUSION receipt (this root was logged at this index).
#[wasm_bindgen]
pub fn verify_mtl_inclusion(receipt_b64: &str, operator_pk_hex: &str) -> Result<String, String> {
    let wire = decode_b64(receipt_b64)?;
    let pk = parse_pk(operator_pk_hex)?;
    let r = InclusionReceiptV1::verify(&wire, Some(&pk)).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "ok": true,
        "kind": "mtl_inclusion",
        "leaf_index": r.leaf_index,
        "size": r.size,
        "merkle_root": hex::encode(r.merkle_root),
        "root_seq": r.statement.root_seq,
        "honesty": MTL_HONESTY,
    })
    .to_string())
}

/// Verify an MTL CONSISTENCY receipt (the log between two heads is append-only).
#[wasm_bindgen]
pub fn verify_mtl_consistency(receipt_b64: &str, operator_pk_hex: &str) -> Result<String, String> {
    let wire = decode_b64(receipt_b64)?;
    let pk = parse_pk(operator_pk_hex)?;
    let r = ConsistencyReceiptV1::verify(&wire, Some(&pk)).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "ok": true,
        "kind": "mtl_consistency",
        "first_size": r.first_size,
        "second_size": r.second_size,
        "first_root": hex::encode(r.first_root),
        "second_root": hex::encode(r.second_root),
        "honesty": MTL_HONESTY,
    })
    .to_string())
}

/// Verify a CCR-Shapley contribution certificate (signature + count consistency).
#[wasm_bindgen]
pub fn verify_shapley(cert_b64: &str, operator_pk_hex: &str) -> Result<String, String> {
    let wire = decode_b64(cert_b64)?;
    let pk = parse_pk(operator_pk_hex)?;
    let r = ShapleyCertV1::verify(&wire, Some(&pk)).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "ok": true,
        "kind": "shapley",
        "root_seq": r.root_seq,
        "namespace": r.namespace,
        "key_count": r.keys.len(),
        "samples": r.samples,
        "honesty": SHAPLEY_HONESTY,
    })
    .to_string())
}

/// The combined honesty boundary for everything this auditor proves.
#[wasm_bindgen]
pub fn honesty() -> String {
    format!(
        "mneme-verify-wasm proves integrity/provenance/authorization (and, for MTL, logging) \
         offline under a PINNED operator key — NOT semantic truth, NOT true nearest-neighbors, \
         NOT that a model produced a bound output, NOT model learning. authenticated != true.\n\
         - ROBR: {ROBR_HONESTY}\n- MTL: {MTL_HONESTY}\n- Shapley: {SHAPLEY_HONESTY}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_inputs_fail_closed() {
        // Not base64.
        assert!(verify_robr("@@@not-base64@@@", &"11".repeat(32)).is_err());
        // Bad pk length.
        assert!(verify_robr("AAAA", "00").is_err());
        // Wrong-length pk hex.
        assert!(parse_pk("abcd").is_err());
        assert!(parse_pk(&"11".repeat(32)).is_ok());
    }

    #[test]
    fn honesty_carries_the_boundary() {
        let h = honesty();
        assert!(h.contains("authenticated != true"));
        assert!(h.contains("NOT semantic truth"));
    }
}
