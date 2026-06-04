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
| `crates/mneme-core/src/interface.rs` | Frozen types (interface freeze) |
| `crates/mneme-index/src/cognition_cert.rs` | Cognition Certificate v1 wire + offline verify |
| `crates/mneme-index/src/federation_cert.rs` | Federated cert wire sketch (decode-only) |
| `crates/mneme-crossref/src/wire_cert.rs` | Independent v1 reimplementation |

---

## 2. Planned SDK surfaces (not implemented)

### 2.1 Rust (`mneme-interop` — future crate)

- `verify_cognition_certificate_v1(bytes, trust, procedure) -> Result<Root, MnemeError>`
  — thin re-export or copy of `mneme-index` offline verifier; **no store access**.
- `decode_federation_cognition_cert_wire(bytes)` — parse-only until P4-2 gate opens.

### 2.2 TypeScript / Go / Python (external repos)

- CBOR/dCBOR decode helpers generated from the same field-number maps as Rust.
- Fail-closed default: `UnsupportedVersion` when wire version > supported.
- Honesty strings re-exported verbatim (`HONESTY_NOT_EXACT_NN`, `PIOP_RESEARCH_HONESTY`).

---

## 3. Verification contract (all languages)

1. **Authenticated ≠ true** — signatures prove integrity, not semantic truth.
2. **Procedure-faithfulness ≠ exact-NN** — unless a future `retrieval_proof_level`
   upgrade is present *and* verified by an out-of-TCB PIOP verifier (not shipped).
3. **Missing or invalid optional proofs fail closed** — never degrade into context.

---

## 4. Next steps before any SDK publish

- [ ] Draft standard text (certificate schema + trust config) in a public doc repo.
- [ ] External verifier proof point (separate from `mneme-crossref`).
- [ ] Versioning policy for federation wire (`FEDERATION_COGNITION_CERT_VERSION`).

*This file is a stub; it records intent only and promises no benchmarks or SDK releases.*
