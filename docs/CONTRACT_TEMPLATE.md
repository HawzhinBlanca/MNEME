# MNEME module contract (blueprint §20.2)

Copy this template into `docs/CONTRACT.md` for each crate. Do not change **Public API** without an interface-change request.

## Responsibility

<!-- One sentence: what this crate owns. -->

## Public API

<!-- Frozen function signatures / types (blueprint §7, §20.3). -->

```rust
// paste normative API surface here
```

## Invariants owned

<!-- Which of INV-1..INV-10 this crate enforces. -->

- INV-…:

## Proof obligations

<!-- Exact test names that must pass (red → green) before the slice is done. -->

| Test | Closes |
|------|--------|
| `…` | … |

## Dependencies

<!-- Workspace crates this module may call. -->

- `mneme-…`

## May start when

<!-- Completed waves / crates. -->

- Wave … complete: …

## Forbidden

<!-- e.g. mneme-verify: no unsafe, unwrap, panic, anyhow, as casts; TCB line budget. -->

- …

## Handoff (§20.4)

Every finished slice reports: files changed; invariant/gap closed; focused tests; validation-ladder status; determinism-gate status; tamper-case delta; **what remains unsafe or unproven**.
