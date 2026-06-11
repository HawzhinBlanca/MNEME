# Phase IV — Cross-Implementation Notes (P4-3)

**Audience:** `mneme-crossref` maintainers and external verifier authors.

**Honesty:** `mneme-crossref` must not depend on any `mneme-*` workspace crate. Federation
and PIOP surfaces are **not** mirrored here yet; this doc records the gap and the planned
shape only.

---

## 1. What crossref proves today

- Cognition Certificate v1: `crates/mneme-crossref/src/wire_cert.rs` — decode, Ed25519 root
  check, receipt binding, ADS / zkANN dominance replay.
- Enforced by `scripts/ci/cross-implementation-vectors.sh` against Appendix B fixtures.

---

## 2. Phase IV gaps (intentional)

| Surface | In `mneme-index` | In `mneme-crossref` |
|---|---|---|
| Federation cert wire | `federation_cert.rs` | **Not started** |
| PIOP exact-NN | `piop_research.rs` (`UnsupportedVersion`) | **N/A** — no prover |
| Global exact-NN level | Research only | Same honesty strings as index |

---

## 3. Planned federation mirror

When P4-2 wire stabilizes:

1. Add `src/wire_federation.rs` with identical field keys (`1`–`5`) and draft status string.
2. `verify_federation_wire(bytes) -> Err(UnsupportedVersion)` while gate closed (match index).
3. Extend `tests/appendix_b_crossref.rs` or a sibling fixture file — **no** `mneme-index` import.
4. Register target in `cross-implementation-vectors.sh` once vectors exist.

---

## 4. Honesty strings to copy verbatim

External SDKs should not paraphrase retrieval limits:

- `mneme_verify::HONESTY_PROCEDURE` and `mneme_crossref::HONESTY_PROCEDURE`.
- `PIOP_RESEARCH_HONESTY` / `PIOP_RESEARCH_STATUS` (`piop_research.rs`) if exposing research APIs.
- `FEDERATION_CERT_DRAFT_STATUS` — wire must carry draft label until gate opens.

---

## 5. References

- `docs/phase-program/INTEROP_SDK_STUB.md`
- `docs/redteam/PHASE_IV_FEDERATION_WIRE.md`
- `docs/research/PHASE_IV_A_PIOP_SPIKE.md`

---

## 6. Trick #1 — beacon spot-check (prototype extension)

**Status:** Wire + CLI + pinned Appendix B fixture landed; crossref runs stub after cert verify.

| Surface | In `mneme-index` | In `mneme-crossref` |
|---|---|---|
| `audit_beacon` cert field (key `7`) | prototype branch | `wire_beacon.rs` decode + lottery selector |
| Full exact-NN replay on selected audits | `verify-cert --audit` (store-backed) | **Not started** — returns `UnsupportedVersion` when selected |
| drand / NIST BLS offline verify | documented in research memo | **Deferred** — zero new deps in crossref v0 |

Integration mirror (landed):

1. `wire_cert::decode_cert` accepts optional field `7` without breaking v1-only certs.
2. `wire_beacon::verify_beacon_spot_check_stub` runs after standard cert verify.
3. `crossref_beacon_spot_check_fixture` reads `beacon_spot_check.cbor` (`fixture_status: pass`).

Honesty string: `mneme_crossref::BEACON_SPOT_CHECK_HONESTY` (copy verbatim in external SDKs).

Design reference: `docs/research/BEACON_SPOT_CHECK_RETRIEVAL.md`.

Cognition Transparency Log vision: `docs/VISION_PROOF_CARRYING_COGNITION.md`.
