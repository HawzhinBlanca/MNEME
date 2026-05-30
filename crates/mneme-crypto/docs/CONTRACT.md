# mneme-crypto — module contract (§20.2)

## Responsibility

Ed25519 signing/verification, XChaCha20-Poly1305 payload sealing, per-object key vault, and operator `TrustConfig` — no store or receipt logic.

## Public API

```rust
// keys: KeyPair, TrustConfig, public_key_from_bytes
// sign: sign_message, verify_signature, verify_signature_bytes
// payload: seal_payload, open_payload, shred_payload_key (as implemented)
```

## Invariants owned

- Supports **INV-4** (signatures) and **INV-5** (trust config inputs to verify)
- Payload crypto supports **§13.2** crypto-shredding (key vault)

## Proof obligations

| Test | Closes |
|------|--------|
| `fault_injection_ed25519_rejects_tampered_message` | §18 crypto fault hook |
| `ed25519_*` | Signature soundness |
| `payload_*` / `vault_*` | AEAD + shredder paths |

## Dependencies

- `mneme-core` only.

## May start when

- Wave 0 (`mneme-core`) types and `MnemeError` are frozen.

## Forbidden

- No store, SMT, or verifier logic.
- No `unsafe`.
- Secrets must not be logged or committed.

## Handoff (§20.4)

Report: crypto tests + `validation-lane crypto`; fault-injection matrix coverage; key-vault custody assumptions documented.
