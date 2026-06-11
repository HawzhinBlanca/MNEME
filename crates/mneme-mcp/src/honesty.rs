//! Blueprint §3 honesty boundary — surfaced in MCP tool descriptions (not footnotes).

/// Shared footer for all memory tools (authenticated ≠ true; receipts ≠ exact-NN).
pub const HONESTY_FOOTER: &str = "Honesty: authenticated≠true (integrity/provenance only, not truth). \
Receipts prove procedure-faithfulness over committed data, not exact nearest-neighbor optimality. \
Phase I ExactDominance proves membership/completeness plus top-k over prover-asserted distances; \
true top-k ranking is not proven and it is not top-k by true query-to-embedding distance until \
verifiers recompute candidate distances.";

/// A-INJ structural mitigation (§2.4, §13.4) — quarantine tier, not anti-poisoning.
pub const AINJ_MITIGATION: &str = "A-INJ mitigation: tool-channel writes land in quarantine tier; \
they are attributable and non-actionable at higher min_tier until promoted by a separate Promote capability.";

pub const REMEMBER_DESCRIPTION: &str = "Write memory via the MCP tool channel (always quarantine tier). \
Does not detect falsehood; stores signed, attributable content. ";

pub const RECALL_DESCRIPTION: &str = "Fail-closed exact logical-key recall (not semantic/vector search): runs recall_verified only — no unverified bytes enter agent context. \
The `key` argument must match the remembered logical key name exactly; natural-language queries are not supported. \
Returns entries only after receipt verifies against the signed root. ";

pub const FORGET_DESCRIPTION: &str =
    "Cryptographic forget (shred) with tombstone; root remains verifiable. ";

pub const FORGET_PROOF_DESCRIPTION: &str = "Cryptographic forget (shred) with tombstone plus canonical ForgetProof CBOR and signed-root metadata for offline deletion-certificate verification. ";

/// Append §3 honesty boundary to protocol-level tool errors (missing args, size caps, etc.).
pub fn protocol_error_message(message: impl AsRef<str>) -> String {
    format!("{} {HONESTY_FOOTER}", message.as_ref())
}

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
