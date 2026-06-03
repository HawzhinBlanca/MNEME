# 🔴 CRITICAL — TCB fail-OPEN: provenance receipts skip ALL VO verification

**Severity: CRITICAL (TCB soundness / fail-open).** Introduced by `d433999`
("fix(phase-i): close red-team findings #3 and #5"), **live on `master`**, CI green. Date 2026-06-04.

**Status: FIXED** on `master` — merge `a494fe0` (fix `7d21c0b`). `verify_semantic_receipt_tcb_gate`
always runs Merkle membership; provenance receipts use `verify_provenance_attestation` instead of
skipping VO. Regression: `forgery_provenance_bearing_non_topk_result_rejected`.

**Tag:** `phase-i-software` → `be2b536` predates this fix; do not move unless release policy allows a
post-Phase-I security patch tag. See also [`PHASE_I_TCB_PROVENANCE_SKIP.md`](PHASE_I_TCB_PROVENANCE_SKIP.md).

## What

`crates/mneme-verify/src/semantic.rs::verify_semantic_receipt` — a function in the **fail-closed
verifier TCB** — was changed to:

```rust
if receipt.provenance.is_none() {
    verify_semantic_receipt_vo(receipt, proc)   // Merkle membership + dominance + procedure replay
} else {
    Ok(())                                        // <-- skips ALL VO verification
}
```

`verify_semantic_receipt_vo` is the **only** thing that proves the receipt's candidates are
authenticated members of the committed semantic index (Merkle paths bound to `semantic_commit`),
that the results are dominant (top-k), and that they equal the procedure replay. Skipping it when
`receipt.provenance.is_some()` — a **prover-controlled field** — means a provenance-bearing receipt
gets **none** of those checks.

## Why it's a fail-open (the attack)

`verify_semantic_recall`'s per-result loop (after the skipped VO) only checks, for each
`result_id`: the object exists in `ctx.objects`, re-hashes to its id (A-NET), version is current,
its `embedding_commit` equals the **prover-supplied** candidate row's, plus DAG-provenance and
writer/tier. **None of that proves the result is in the committed index or is a nearest neighbor.**

A malicious prover therefore: attaches any `provenance` attachment; sets `result_ids = [X]` where
`X` is any object the verifier can fetch (e.g. a low-ranked or unrelated entry); adds a matching
candidate row `(X, X.embedding_commit, any_dist)`; sets `query_commit` to the query's. The TCB
returns `Ok` and yields `X` as a "verified semantic recall result" — with **no membership proof and
no dominance**. This is the exact forgery class the VO check exists to stop, now reachable by
flipping one prover-controlled `Option` to `Some`.

The honest store's scoped path (`scoped_recall.rs:47`) pre-runs the full VO via
`verify_semantic_receipt_vo_zkann` *before* the final `verify_semantic_recall`, so the store call
isn't immediately exploitable. **But the TCB must self-verify** — its contract is "I verify the
receipt," not "I trust the caller pre-checked." Any other caller (the Cognition-Certificate
verifier, the bi-temporal `recall_at` path, `mnemed`, future callers) that passes a
provenance-bearing receipt through this gate is exposed, and the fail-closed prime directive is
violated.

## Root cause

This was meant to fix finding #3 (scoped recall fail-closing because the final
`verify_semantic_recall` re-replayed the **unfiltered** candidates against the post-filter
`result_ids`). The intent was right; the implementation threw the baby out — it removed *all* VO
verification instead of only relaxing the *unfiltered-replay equality*.

## Correct fix (restore soundness AND keep #3 fixed)

For a provenance receipt, the TCB must still prove **membership** and must prove the results are
the **provenance-filtered** top-k — it must not skip verification:

1. **Always** verify candidate membership against `semantic_commit` (the Merkle/`leaf_indices`
   portion of `verify_ads_vo`) — never skip this.
2. If `provenance.is_none()`: also require `result_ids == replay(candidates)` (unfiltered dominance),
   as today.
3. If `provenance.is_some()`: verify the provenance attestation — i.e. `result_ids == replay(filter(candidates))`
   and every result satisfies the filter predicate against its real object record
   (`verify_provenance_attestation` already does exactly this in `mneme-index`). Wire it into the
   TCB gate (it needs `ctx.objects`, which `verify_semantic_recall` already has).

Net: membership is proven for *all* receipts; dominance is checked over the *unfiltered* set when
there's no filter and over the *filtered* set when there is. #3 stays fixed (no spurious
unfiltered-replay mismatch) and the fail-open is closed.

Mind the **TCB ≤ 500-line budget** — prefer calling the existing `mneme-index`
`verify_provenance_attestation` + a membership-only helper rather than inlining logic.

## Required tests (must fail-closed before this is "fixed")

- **Adversarial:** a provenance-bearing receipt whose `result_ids` contain a NON-member / non-top-k
  object must be **rejected** (today it is accepted). This is the regression test that proves the
  fail-open is closed.
- **Parity:** the same forged receipt must be rejected by `mneme-crossref` too (keep the two
  verifiers in agreement).
- Keep the legitimate scoped-recall e2e (`e2e_provenance_scoped_returns_trusted_when_poison_outranks`)
  green.

## Recommendation

**Fix before anything else and before tagging Phase I.** A fail-open in the verifier TCB is the
single worst defect class for this project — it converts "fail-closed, verify everything" into
"trust any receipt that sets a flag." Consider a brief pause of concurrent edits to `mneme-verify`
while this lands, given the TCB budget and the need for an adversarial test.
