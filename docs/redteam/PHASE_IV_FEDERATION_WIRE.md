# Finding — federated cognition certificate wire forgery (P4-2)

**Severity: PARSE + GATE (research sketch).** Date 2026-06-04.

## What

Phase IV P4-2 ships a **decode-only** federated certificate wire in
`mneme-index/federation_cert.rs`. `PHASE_IV_FEDERATION_GATE_OPEN` is `false`; honest
verify returns `UnsupportedVersion` after parse checks. No CRDT merge proof or cross-org
trust surface exists yet.

## Attack surface

| Forgery | Vector | Expected rejection |
|---|---|---|
| Replay | Resubmit identical wire bytes | Still `UnsupportedVersion` (no accept on replay) |
| Bad merge head | Tamper `merge_head_digest` on wire | `UnsupportedVersion` or `CertificateInvalid` |
| Wire tamper | Truncate CBOR, flip cognition cert payload | `CertificateInvalid` |
| Elevated status | `status = "verified"` instead of draft label | `CertificateInvalid` |
| Empty embed | `cognition_cert_bytes` empty | `CertificateInvalid` |
| Unknown field | Extra map key | `UnknownField` / `CertificateInvalid` on decode |

## Why it matters

Federation introduces cross-org trust boundaries. Parse must not panic on hostile input;
verify must not accept elevated claims while the gate is closed. Replay acceptance before
merge-head binding would let stale federated certs re-enter context.

## Required tests (landed)

- `crates/mneme-index/src/federation_cert.rs` — `forgery_*` unit tests
- `fuzz/fuzz_targets/federation_cert_parse.rs` — decode-only fuzz (no panic)

Run:

```bash
cargo test -p mneme-index federation forgery -- --nocapture
# optional fuzz smoke:
cargo fuzz run federation_cert_parse -- -runs=16
```

## Honesty boundary

Decode success does **not** imply cross-org verification. Draft status
`unverified_until_phase_iv_federation_gate` must remain on wire until P4-2 merge binding
and trust-surface work lands.

## Status

**Mitigated (wire sketch):** hostile wires fail closed; gate closed rejects all verify;
fuzz entry decodes without panic.
