# mneme-cap — module contract (§20.2)

## Responsibility

Offline-verifiable capability tokens: issue, attenuate, MNEME-dCBOR encode/decode, sig-chain verification, and trust-tier policy (§12, §13.4).

## Public API

```rust
pub struct Permissions; // bitflags: READ | WRITE | FORGET | MERGE | PROMOTE
pub use mneme_core::interface::Capability;
pub use mneme_core::Caveat;

impl Capability {
    fn issue(...) -> Result<Self, MnemeError>;
    fn attenuate(&self, subject: &KeyPair, extra: Vec<Caveat>) -> Result<Self, MnemeError>;
    fn verify(&self, issuer: &KeyPair, now: &Hlc) -> Result<(), MnemeError>;
    fn verify_issuer_chain(&self, issuer: &KeyPair) -> Result<(), MnemeError>;
    fn cap_id(&self) -> Result<[u8; 32], MnemeError>;
    fn sig_chain(&self) -> Result<Vec<[u8; 64]>, MnemeError>;
    fn permits_write / permits_read / permits_forget / permits_promote;
    fn require_promote(&self) -> Result<(), MnemeError>; // → PromoteDenied
    fn default_tier / writer_hash / from_bytes / to_bytes;
}

pub fn tool_channel_cap(...) -> Result<Capability, MnemeError>; // Quarantine, no Promote
pub fn agent_cap(...) -> Result<Capability, MnemeError>;
pub fn default_cap_expiry() -> Hlc;
```

## Invariants owned

- **§12** offline cap verification (`cap_id = BLAKE3(CAP ‖ dCBOR(preimage))`)
- **§13.4** tool-channel `tier_default = Quarantine`, no `Promote`
- **INV-9** typed errors: `CapDenied`, `CapExpired`, `CapMalformed`, `PromoteDenied`

## Proof obligations

| Test | Closes |
|------|--------|
| `cap_issue_verify_roundtrip` | dCBOR + sig-chain issue/verify |
| `tool_channel_quarantine_no_promote` | §9.1 tool channel / §13.4 |
| `not_after_expired_returns_cap_expired` | NotAfter HLC caveat |
| `sig_chain_tamper_returns_cap_denied` | Sig-chain integrity |
| `dcbor_sig_chain_byte_tamper_rejected` | In-memory sig tamper fail-closed |
| `cap_dcbor_wire_byte_tamper_rejected` | dCBOR wire byte tamper fail-closed |
| `attenuation_appends_subject_sig` | Narrow-only attenuation |
| `sig_chain_malformed_length_is_cap_malformed` | Malformed chain |
| `e2e_promote_requires_promote_capability` | PromoteDenied at store |
| `e2e_quarantine_entry_blocked_from_trusted_recall` | MINJA tier gate |

## Dependencies

- `mneme-core` (frozen `Capability`, `Caveat`, dCBOR, HLC)
- `mneme-crypto` (Ed25519 sign/verify)

## May start when

- Wave 0 (`mneme-core`) + Wave 1 (`mneme-crypto`) complete.

## Forbidden

- No changes to `mneme-core/src/interface.rs` fields without INTERFACE-CHANGE doc.
- No store / verify TCB logic in this crate.
- No `unsafe`.

## Handoff (§20.4)

See parent agent handoff report.
