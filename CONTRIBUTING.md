# Contributing to MNEME

Thank you for your interest in contributing to MNEME! As a verifiable memory substrate for AI agents, we maintain exceptionally high standards for security, correctness, and reviewability.

Please take a moment to review these guidelines before submitting a pull request.

## Code of Conduct

By participating in this project, you agree to uphold a professional, respectful, and cooperative environment.

## Canonical Tooling & Gates

Before any change can be merged, it must pass all verification checks. We use a validation ladder to gate releases:

```bash
# Check formatting
cargo fmt --all -- --check

# Check clippy warnings
cargo clippy --workspace --all-targets -- -D warnings

# Run all workspace tests
cargo test --workspace -- --nocapture

# Run the validation lane (quick gate)
scripts/ci/validation-lane.sh quick
```

## Architectural Invariants (Non-Negotiable)

MNEME is designed to fail closed. Every contributor must respect and preserve the following invariants:

1. **TCB Line Budget (Tier-1):** The `mneme-verify` crate holds our fail-closed verifier TCB. It **must stay under 500 lines of Rust code** (enforced by `cargo test -p mneme-verify --test tcb_budget`). If you need to add logic there, you must provide explicit invariant justification.
2. **No Unsafe Code:** The verifier TCB has `#![forbid(unsafe_code)]` enabled. Do not use `unsafe` blocks to resolve compiler/borrow-checker complaints. The fix is to restructure code safely.
3. **No Indexing Panics:** Slice/array indexing (e.g. `data[0]`) can panic. The verifier TCB must use `.get(..)` and handle the `None` case gracefully (failing closed). Line-local overrides are allowed using the `// tcb-index-ok` comment marker only if bounds are statically guaranteed.
4. **No Numeric `as` Casts:** Numeric casts (`as u8`, `as usize`, etc.) can silently truncate or wrap. Use checked conversions (`try_into()`, `TryFrom`) or explicit enum mappers instead.
5. **No Panics or Unwraps in Production TCB:** The production verifier must never call `.unwrap()`, `.expect()`, `panic!`, `unreachable!`, or use libraries that swallow errors (e.g., `anyhow::Error`). Errors must be explicitly typed using `MnemeError` variants.
6. **Interface Freeze:** Types defined in `mneme-core/src/interface.rs` are normative seams. Field layouts, enum variants, and hashing rules must not change without a formal interface-change review.
7. **Single-Writer Lock:** Store opening (`Store::open`/`Store::create`) must acquire an advisory `flock` on `.mneme.lock` to prevent concurrent writer processes.

## Honesty Boundary

MNEME enforces a strict Honesty Boundary:
* **Authenticated ≠ True:** A signed root verifies if it has a valid signature, regardless of whether the contents of the memory are semantically true. MNEME proves integrity, provenance, and authorization, not truth.
* **Procedure-Faithfulness ≠ Optimal Retrieval:** The verification objects prove that the HNSW/retrieval procedure was executed faithfully over the committed memory set; they do not prove that the retrieved entries are the absolute nearest neighbors or semantically perfect.
* Never weaken or remove these boundaries from documentation, comments, error messages, or MCP descriptions.

## Pull Request Checklist

When submitting a PR, make sure you have:
1. Checked that all tests and `validation-lane.sh quick` are green.
2. Verified that the `mneme-verify` crate remains within its 500-line budget.
3. Ensured no forbidden patterns (unsafe, panic, unwrap, numeric as-casts) are added to the TCB.
4. Added or updated tests in `tests/` or `crates/*/tests/` to verify your changes.
5. Preserved all existing comments and docstrings.
