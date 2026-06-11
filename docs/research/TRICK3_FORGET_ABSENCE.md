# Trick #3 — Proof of Non-Use After Forgetting (Forget-Absence Prototype)

**Status:** Prototype in `mneme-index` (`forget_absence`). **Not** constant-size Jewel C (C2 parked). **Date:** 2026-06-11.

**Related:** [`VERIFIABLE_ABSENCE_AND_COMPLETE_RETRIEVAL.md`](VERIFIABLE_ABSENCE_AND_COMPLETE_RETRIEVAL.md), [`PHASE_III_FORGET_PROOF.md`](../redteam/PHASE_III_FORGET_PROOF.md), [`BEACON_SPOT_CHECK_RETRIEVAL.md`](BEACON_SPOT_CHECK_RETRIEVAL.md) §7.

## Software-feasible (shipped)

| Item | Location |
|---|---|
| Ω(N) post-forget cert scan | `verify_forget_absence` |
| Used-set extraction | `certified_used_commits` |
| Cert commit domain tag | `MNEME-COGNITION-CERT-COMMIT/v1` |
| Connection 5 anchor splice | optional `cognition_cert_commit` + `--anchor-cert` |
| CLI | `mneme verify-forget-absence` |
| Crossref sketch | `wire_forget_absence` |

## Parked

- C2 class-group universal accumulator
- Accumulator in signed Root (frozen seam)
- VDF temporal sandwich
- Full LogicalKey non-use without ObjectId mapping

Certified cognition only; operator can withhold certificates. Authenticated ≠ true.
