# MNEME Interop SDK — Draft Surface (Phase IV P4-3)

**Status:** Documentation stub only. No SDK packages ship in this slice.

**Honesty:** External verifiers must remain independent of the MNEME workspace
(`mneme-crossref` is the in-repo proof point for Certificate v1). Phase IV
interop targets multi-language verifier SDKs aligned to the same wire schemas
as `mneme-core` / `mneme-index`, not wrappers around the store kernel.

---

## 1. Normative artifacts (read first)

| Artifact | Role |
|---|---|
| `docs/PHASE_IV_TASK_SPEC.md` | Phase IV exit criteria |
| `docs/phase-program/manifest.yaml` | Phase program evidence paths |
| `crates/mneme-core/src/interface.rs` | Frozen types (interface freeze) |
| `crates/mneme-index/src/cognition_cert.rs` | Cognition Certificate v1 wire + offline verify |
| `crates/mneme-index/src/federation_cert.rs` | Federated cert wire sketch (decode + fail-closed verify) |
| `crates/mneme-crossref/src/wire_cert.rs` | Independent v1 reimplementation (zero `mneme-*` deps) |
| `docs/research/PHASE_IV_A_PIOP_SPIKE.md` | PIOP research-only; no SDK claims |

---

## 2. Planned SDK surfaces (not implemented)

### 2.1 Rust (`mneme-interop` — future crate)

- `verify_cognition_certificate_v1(bytes, trust, procedure) -> Result<Root, MnemeError>`
  — thin re-export or copy of `mneme-index` offline verifier; **no store access**.
- `decode_federation_cognition_cert_wire(bytes)` — parse-only.
- `verify_federation_cognition_cert_wire(bytes)` — returns `UnsupportedVersion` while
  `PHASE_IV_FEDERATION_GATE_OPEN == false` (fail-closed sketch).
- `verify_federation_cognition_cert_wire_with_merge_head(bytes, sketch)` — merge-head binding; gate still closed.

### 2.2 TypeScript / Go / Python (external repos)

- CBOR/dCBOR decode helpers generated from the same field-number maps as Rust.
- Fail-closed default: `UnsupportedVersion` when wire version > supported.
- Honesty strings re-exported verbatim (`HONESTY_PROCEDURE`, `PIOP_RESEARCH_HONESTY`,
  `FEDERATION_CERT_DRAFT_STATUS`).

### 2.3 Federation wire (draft)

| Field key | Type | Semantics |
|---|---|---|
| `1` | `u16` | `FEDERATION_COGNITION_CERT_VERSION` (= 1) |
| `2` | `text` | Must equal `unverified_until_phase_iv_federation_gate` |
| `3` | `bytes[32]` | `issuer_org_id` (non-zero when verify sketch runs) |
| `4` | `bytes` | Embedded cognition cert v1 bytes (opaque here) |
| `5` | `bytes[32]` | `merge_head_digest` (non-zero sketch; CRDT binding TBD) |

Decode success **does not** imply cross-org trust. See `docs/redteam/PHASE_IV_FEDERATION_WIRE.md`.

---

## 3. Verification contract (all languages)

1. **Authenticated ≠ true** — signatures prove integrity, not semantic truth.
2. **Procedure-faithfulness ≠ exact-NN** — Phase I `ExactDominance` is
   top-k over prover-asserted distances, not top-k by true query-to-embedding distance,
   unless a future `retrieval_proof_level` upgrade is present *and* verified by
   an out-of-TCB PIOP verifier (not shipped).
3. **Missing or invalid optional proofs fail closed** — never degrade into context.
4. **Federation gate closed** — federated verify must reject with `UnsupportedVersion`
   until P4-2 merge binding and trust-surface work ships.

---

## 4. Cross-implementation proof points

| Proof point | Location | Scope today |
|---|---|---|
| Certificate v1 | `crates/mneme-crossref` + `scripts/ci/cross-implementation-vectors.sh` | Independent decode/verify vs `mneme-index` |
| Federation wire | `mneme-index` only | Decode + verify sketch; **no** crossref crate yet |
| PIOP / exact-NN | `piop_research` seam | `UnsupportedVersion` only; not in crossref |

**Crossref extension (planned):** add `wire_federation.rs` in `mneme-crossref` mirroring
`federation_cert.rs` field map, with the same fail-closed gate constant — only after federation
wire stabilizes. Until then, interop consumers should copy the field table in §2.3.

---

## 5. Versioning policy (draft)

- Cognition cert: v1 normative; v2 draft fields documented in `cognition_cert.rs`.
- Federation cert: bump `FEDERATION_COGNITION_CERT_VERSION` only with a red-team doc update
  and new fuzz corpora (`federation_cert_parse`, `federation_cert_verify`).
- PIOP research: `PIOP_RESEARCH_VERSION = 0` — not a wire version; entry point always
  `UnsupportedVersion`.

---

## 6. Next steps before any SDK publish

- [ ] Draft standard text (certificate schema + trust config) in a public doc repo.
- [ ] External verifier proof point (separate from `mneme-crossref`).
- [ ] `mneme-crossref` federation wire mirror + appendix vectors.
- [ ] Versioning policy ratified for federation wire.

*This file is a stub; it records intent only and promises no benchmarks or SDK releases.*
