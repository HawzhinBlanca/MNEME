# Finding — provenance-scoped recall fail-closes (non-functional) when poison outranks the trusted entry

**Severity: FUNCTIONAL (safe but broken for the core anti-MINJA case).** Date 2026-06-03.
Found while adding the P1-3 exclusion test the integration suite omitted.

## Symptom

`Store::recall_verified_scoped` returns `Err(MnemeError::ProcedureMismatch)` whenever the
provenance filter excludes a candidate that ranks **above** a surviving trusted entry — i.e.
exactly the anti-MINJA scenario (an injected, foreign-writer memory embedded close to the
query). The poison never leaks (fail-closed, so the **security** invariant holds), but the
trusted entry can't be recalled either — so the feature is non-functional for its headline use.

The existing test (`e2e_provenance_scoped_recall_honors_filter`) only covered the case where the
filter excludes **nothing**, so it never hit this.

## Root cause

In `crates/mneme-store/src/scoped_recall.rs`:

1. `verify_semantic_receipt_vo_zkann(&receipt, …)` verifies the **unfiltered** top-k (result_ids
   = unfiltered top-k). OK.
2. `align_scoped_receipt_results(&mut receipt, …)` **mutates `result_ids` to the FILTERED top-k**.
3. `verify_provenance_attestation(…)` proves the filtered results honor the filter. OK.
4. `verify_semantic_recall(&input, …)` (the final TCB gate) calls `verify_semantic_receipt` →
   `verify_semantic_receipt_vo`, which **re-replays the UNFILTERED candidates** and requires
   `replayed == result_ids`. But `result_ids` is now the *filtered* set → mismatch →
   `ProcedureMismatch`.

So step 4 re-checks an invariant (result_ids = unfiltered top-k) that step 2 deliberately broke.

## Fix options (for the owning team — touches verification composition, do NOT hot-patch)

- **A (preferred):** the final gate for the scoped path must verify against the *filtered*
  candidate set, not the unfiltered one. E.g. a `verify_semantic_recall_scoped` that takes the
  provenance attestation and replays over the filter-passing candidates (the provenance
  attestation already does this in `verify_provenance_attestation`; the final entry-extraction
  should reuse that filtered result rather than re-running the unfiltered VO).
- **B:** keep `result_ids` = unfiltered top-k in the receipt; carry the filtered selection
  separately; extract returned entries from the filtered selection while the VO check stays
  consistent with the unfiltered receipt.

Either way, keep the per-entry checks (re-hash, version, writer/tier, provenance) inside the TCB;
do not duplicate them in the store. Mind the TCB ≤ 500-line budget.

## Tests

- `e2e_provenance_scoped_recall_excludes_foreign_writer_poison` — **green**: asserts the SAFETY
  invariant (poison never leaks, whether filtered or fail-closed).
- `e2e_provenance_scoped_returns_trusted_when_poison_outranks` — **`#[ignore]`d**: asserts the
  FUNCTIONAL behavior (trusted entry returned, poison dropped). Un-ignore once A/B lands.

## Honesty note

This is **safe today** (poison cannot leak — fail-closed). The gap is *availability* of the
legitimate result under the real attack, not a soundness/leak bug.
