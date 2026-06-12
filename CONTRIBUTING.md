# Contributing to MNEME

Thank you for contributing. MNEME is a fail-closed verifiable memory substrate; changes
must preserve security invariants and the §3 honesty boundary.

## Before you open a PR

Run the validation ladder (see `CLAUDE.md`):

```bash
cargo fmt --all -- --check

cargo clippy -p mneme-core -p mneme-crypto -p mneme-smt -p mneme-dag \
  -p mneme-root -p mneme-cap -p mneme-verify -p mneme-store \
  --lib --tests -- -D warnings

cargo test --workspace -- --nocapture

scripts/ci/validation-lane.sh quick
```

For semantic or tamper-sensitive changes, also run:

```bash
scripts/ci/validation-lane.sh tamper
scripts/ci/validation-lane.sh determinism
```

## Architectural invariants (non-negotiable)

1. **Agent reads** — Agent-facing recall uses only `Store::recall_verified` /
   `recall_verified_default`. The untrusted index path stays `pub(crate)`.
2. **TCB budget** — `mneme-verify` orchestration TCB must stay ≤500 lines
   (`TCB_LINE_BUDGET`; enforced by `cargo test -p mneme-verify tcb_budget`).
3. **No unsafe in verifier TCB** — `#![forbid(unsafe_code)]` in `mneme-verify`.
   Reshape safe code instead of adding `unsafe`.
4. **Fail-closed** — Every error path rejects; use typed `MnemeError` variants.
5. **Interface freeze** — `mneme-core/src/interface.rs` layout and hashing rules require
   explicit interface-change review.
6. **Single-writer store** — `Store::open` / `Store::create` hold advisory `flock` on
   `.mneme.lock` for the process lifetime.

TCB guard details: `scripts/ci/verify-tcb-guard.sh` and `docs/TCB_MANIFEST.md`.

## Honesty boundary (§3)

Preserve these limits in code, docs, errors, and MCP tool text:

1. **Authenticated ≠ true.** MNEME proves integrity, provenance, and authorization — not
   semantic truth.
2. **Verifiable retrieval proves procedure-faithfulness under the committed quantized metric, not real-valued nearest-neighbor optimality.**
   Phase I `ExactDominance` proves membership/completeness plus top-k over prover-asserted
   distances; true top-k ranking is not proven, and returned items are not proven to be the
   exact top-k under the committed quantized metric (quantized top-k may differ from real-valued top-k) by query-to-embedding distance until verifiers recompute candidate
   distances from carried embeddings. Under Candidate (b), MNEME can prove
   exact top-k nearest neighbors under the committed quantized integer metric
   (with deterministic index-order tie-breaking), but the quantization caveat
   remains: top-k under the quantized metric may differ from the true real-valued
   top-k due to quantization precision.

Do not weaken or remove these strings from standing docs or exports.

## Pull request checklist

- [ ] `validation-lane.sh quick` green (or broader lanes if your change warrants it)
- [ ] Verifier TCB line budget unchanged or explicitly justified with manifest update
- [ ] No new forbidden patterns in TCB (`unwrap`, `expect`, `panic!`, numeric `as` casts)
- [ ] Tests added or updated for behavior you changed
- [ ] Honesty boundary preserved in user-facing text

## Scope discipline

One task, one merge: keep PRs focused on a single work-order item or bugfix. Do not mix
unrelated refactors, speculative features, or human-gated P3 proof claims.
