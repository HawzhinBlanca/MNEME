# Polish finding — Certificate v1 silently drops provenance (P1-4 spec/code mismatch)

**Severity: LOW (polish / honesty; safe, not a soundness or leak bug).** Date 2026-06-04.

## What

`assemble_cognition_certificate_v1` accepts a `SemanticRecallReceipt`, but
`encode_semantic_receipt` (`crates/mneme-index/src/cognition_cert.rs`) serializes only
`root_bound, semantic_commit, procedure_id, query_commit, result_ids, vo_body, [zkann]`
(map_len 6 or 7) — **it does not encode `receipt.provenance`** — and decode sets
`provenance: None`. So a provenance-bearing (scoped) recall, when certified, is **silently
downgraded** to a non-provenance certificate.

Two consequences:
1. **Spec/code mismatch.** P1-4 says Cognition Certificate v1 binds "…+ provenance-filter
   attestation." It does not — the un-poisoned property is **not** in the portable cert; it is
   only enforced in the live `recall_verified_scoped` path.
2. **Footgun (silent drop).** Certifying a scoped recall yields a cert that verifies under the
   *non-provenance* path (unfiltered `result_ids == replay(candidates)`). Because a scoped recall's
   `result_ids` are the *filtered* top-k, that cert typically **fails closed** on verify
   (`ProcedureMismatch`) — safe, but the caller gets no signal that the provenance guarantee was
   dropped at assembly time. If the filter happened to exclude nothing, it "succeeds" but proves
   nothing about provenance.

## Why it's not urgent

No soundness/leak risk: the cert is either verified honestly as a non-provenance retrieval cert,
or it fails closed. Nothing forged is accepted.

## Recommended polish (pick one)

- **A (cheap, honest, do now):** make `assemble_cognition_certificate_v1` **reject** a
  provenance-bearing receipt with a typed error (e.g. `MnemeError::UnsupportedCertExtension` /
  "provenance attestation not carried by Certificate v1"). Fail-closed + explicit instead of
  silent-drop. Update P1-4 to state v1 does **not** bind provenance (defer to v2).
- **B (feature, later):** encode the provenance attestation in the cert wire **and** teach both
  the main verifier and `mneme-crossref` to verify it offline — then P1-4's "un-poisoned" claim is
  truthfully met in the portable artifact. Requires crossref parity + a committed cert vector.

## Status of the broader red-team (2026-06-04)

All soundness items are resolved on `master` and CI is green across all workflows:
- #1 main exact-dominance forgeable → fixed (PR #5).
- #2 valid-time semantic non-functional → fixed.
- #3 provenance-scoped fail-closes when poison outranks → fixed.
- #4 crossref forgeable + divergent → fixed (PR #6).
- #5 HNSW audit overclaim → label downgraded.
- #6 (introduced by the #3 fix) **TCB fail-open on provenance receipts** → fixed (`7d21c0b`):
  `verify_semantic_receipt_tcb_gate` always runs membership; provenance → `verify_provenance_attestation`;
  provenance-without-objects fails closed; regression tests `forgery_provenance_*` are real.

This (cert provenance drop) is the only remaining item and it is LOW/polish.
