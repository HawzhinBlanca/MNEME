//! Blueprint §3 honesty boundary — surfaced in MCP tool descriptions (not footnotes).

/// Shared footer for all memory tools (authenticated ≠ true; receipts ≠ exact-NN).
pub const HONESTY_FOOTER: &str = "Honesty boundary: the memory-and-record layer is cryptographically airtight; \
model-side parametric residue is STATISTICAL attestation only, never claimed as cryptographic deletion. \
Authenticated memory is not truth; receipts prove procedure-faithfulness over committed data, not exact nearest-neighbor optimality.";

/// A-INJ structural mitigation (§2.4, §13.4) — quarantine tier, not anti-poisoning.
pub const AINJ_MITIGATION: &str = "A-INJ mitigation: tool-channel writes land in quarantine tier; \
they are attributable and non-actionable at higher min_tier until promoted by a separate Promote capability.";

pub const RECORD_DESCRIPTION: &str = "Record with provenance: write memory via the MCP tool channel \
(always quarantine tier), return object/root evidence, and store signed, attributable content. ";

pub const RECALL_DESCRIPTION: &str = "Recall with signed chain: runs recall_verified only — no unverified bytes enter agent context. \
Returns entries only after receipt verifies against the signed root and returns root evidence. ";

pub const ERASE_DESCRIPTION: &str = "Erase with receipt and proof of absence: cryptographic shred forget, \
tombstone the logical key, return the post-erase signed root, ForgetProof receipt, and SMT absence proof. ";

pub const VERIFY_DESCRIPTION: &str = "Verify the record store fail-closed: validate HEAD, signed checkpoint chain, \
object hashes, key-index sidecars, replay floor, and return verified root evidence. ";

/// Append §3 honesty boundary to tool-call error messages (not footnotes).
pub fn tool_error_message(err: mneme_core::MnemeError) -> String {
    let base = format!("{err:?}");
    let hint = match &err {
        mneme_core::MnemeError::CapDenied => {
            " Tool-channel writes require a tools/ namespace prefix; recall min_tier must be within capability bounds."
        }
        mneme_core::MnemeError::BelowTierPolicy { .. } => {
            " A-INJ mitigation: low-trust entries are structurally non-actionable at higher min_tier — not truth detection."
        }
        mneme_core::MnemeError::Forgotten => " Entry was cryptographically forgotten (tombstone).",
        _ => "",
    };
    format!("{base}{hint} {HONESTY_FOOTER}")
}
