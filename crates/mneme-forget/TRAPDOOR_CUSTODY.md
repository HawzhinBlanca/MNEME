# Trapdoor custody (chameleon redaction)

Accountable redaction (§13.3) preserves the committed `object_id` by adjusting the
`redaction_slot` witness with operator-held trapdoor material derived from the
operator signing key.

## Weak point (honest)

Anyone who holds the operator trapdoor seed material can:

- Forge redaction witnesses for arbitrary payload replacements that keep the same `object_id`.
- Undetectably replace redacted content if they also control stored blobs and signatures.

This is **operational custody**, not a cryptographic proof of erasure. Shred mode (§13.2)
remains the default; redact is opt-in and requires explicit operator capability.

## Required controls

- Trapdoor seed stored in HSM/KMS or offline ceremony; never in git or CI logs.
- Separate break-glass policy for `--mode redact` with audit log of `RedactionRecord.reason`.
- Periodic review that redaction records match operator pubkey allowlist.
