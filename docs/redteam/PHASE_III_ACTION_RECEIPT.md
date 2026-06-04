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
cargo test -p mneme-account --features phase_iii_bind_action --test bind_action -- --nocapture
cargo test -p mneme-account --test fail_closed gate_off -- --nocapture
cargo test -p mneme-store --test phase_iii_bind bind_external_action_fail_closed -- --nocapture
cargo test -p mneme-store --features phase_iii_bind --test phase_iii_bind -- --nocapture
```

## Honesty boundary

A valid `ActionReceipt` proves **authorization + non-repudiation** — not that the action
was wise or its premises true (CLAUDE.md §honesty).

## Status

**Mitigated (P3-1 software slice):** crypto forgeries fail closed; default build gate-off
bypass tests pin `UnsupportedVersion`. Store-path `bind_external_action` → `bind_action`
mints signed receipts only with `phase_iii_bind_action` / `phase_iii_verify` (or store
`phase_iii_bind` feature); production default remains closed.

## Store path

| Surface | Gate | Default |
|---|---|---|
| `Store::bind_external_action` | `mneme-store/phase_iii_bind` → `mneme-account/phase_iii_bind_action` | `UnsupportedVersion` |
| `mneme_account::bind_action` | `PHASE_III_BIND_ACTION_OPEN` | `false` |
| Wire verify | `phase_iii_verify` / `PHASE_III_GATE_OPEN` | `false` |

Tests: `crates/mneme-store/tests/phase_iii_bind.rs`, `crates/mneme-account/tests/bind_action.rs`,
`crates/mneme-account/src/sign.rs` (`redteam_bind`).
