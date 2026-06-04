# Finding — ActionReceipt forgery surface (P3-1)

**Severity: NON-REPUDIATION (feature-gated).** Date 2026-06-04.

## What

Phase III P3-1 adds Ed25519 signing over `ActionReceipt::signable_preimage` behind the
`phase_iii_verify` Cargo feature (default **off**). When the feature is off,
`mneme-account` rejects with `UnsupportedVersion` — no fabricated receipt enters the store path.

When the feature is on (CI / opt-in builds), offline verify covers:

- detached signature over the provisional preimage (no domain tag yet)
- optional `cognition_cert_commit` presence byte in the preimage
- bound verify: action, capability, root must match after sig check

## Attack surface

| Forgery | Vector | Expected rejection |
|---|---|---|
| Wrong signer | Signature from key K₂, `sanctioner` field claims K₁ | `MnemeError::RootSigInvalid` |
| Tampered signature | Flip byte in detached sig | `RootSigInvalid` |
| Tampered preimage | Mutate `action_commit` / `root_bound` after mint | `RootSigInvalid` |
| Spliced cert commit | Copy `cognition_cert_commit` from another receipt | `RootSigInvalid` |
| Empty signature | Clear sig vector | `RootSigInvalid` |
| Bound mismatch | Valid sig but wrong action/root/cap at bound gate | `ProvenanceBroken` / `ReceiptRootMismatch` / `CapMalformed` |
| Gate-off bypass | Present forged wire when `phase_iii_verify` disabled | `UnsupportedVersion` (never Ok) |

## Why it matters

Without these checks, an external action could be attributed to a human sanctioner or
capability that did not authorize it. The gate-off path must never accept even a
well-formed, signature-bearing wire.

## Required tests (landed)

- `crates/mneme-account/src/verify.rs` — `redteam::forgery_*` (feature `phase_iii_verify`)
- `crates/mneme-account/tests/fail_closed.rs` — `gate_off_*` bypass pins (default build)
- `crates/mneme-account/tests/verify_crypto.rs` — mint/verify integration

Run:

```bash
cargo test -p mneme-account --features phase_iii_verify redteam -- --nocapture
cargo test -p mneme-account fail_closed gate_off -- --nocapture
```

## Honesty boundary

A valid `ActionReceipt` proves **authorization + non-repudiation** — not that the action
was wise or its premises true (CLAUDE.md §honesty).

## Status

**Mitigated (verify slice):** crypto forgeries fail closed; default build gate-off bypass
tests pin `UnsupportedVersion`. Store-path `bind_action` signer integration remains open.
