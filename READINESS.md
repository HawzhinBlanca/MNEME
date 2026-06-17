# MNEME Integration Readiness Report

**Assessor:** Adversarial Readiness Auditor (Antigravity)  
**Date:** 2026-06-17 (revised from 2026-06-09 original)  
**Workspace:** `/Users/hawzhin/MNEME`  
**Verdict:** **READY (single-host v0 key-recall kernel)**

---

## 1. Executive Verdict

The MNEME v0 **key-recall kernel** — content-addressed storage, signed roots, SMT
membership proofs, capability-scoped authorization, crypto-shred erasure, and the
474-line verifier TCB — is ready for single-host deployment. All validation lanes
pass on the committed tree. The system proves integrity, provenance, and
authorization; it does **not** prove semantic truth or exact nearest-neighbor
optimality (§3 honesty boundary).

### What "ready" means (proven)

| Guarantee | Evidence |
|---|---|
| Key-index `recall_verified` + signed root | e2e; `recall_verified` **197.7 µs** @ 10k |
| Tamper rejection at read time (A-DB) | 606 generative tamper cases, all fail-closed |
| Quarantine tier gate (A-INJ / MINJA) | `BelowTierPolicy` enforced; killer-demo green |
| Kill/resume fail-closed (INV-8) | chaos suite; `.incomplete` sentinel |
| Replay/rollback rejection (A-REPLAY) | Cold-open checkpoint scan; `RootReplayed` |
| GDPR crypto-shred + prove-absent | e2e; `ForgetProof` minted and self-verified |
| Determinism gate (single-host) | Foundation-gate ×2 byte-identical |
| Cross-architecture determinism | macOS/arm64 ↔ ubuntu/x86_64 CI runner |
| Verifier TCB: panic-free, `forbid(unsafe)` | 474/500 lines; guard-tested |
| Cross-implementation vectors | `mneme-crossref` (0 `mneme-*` deps), 7/7 PASS |

### What "ready" does NOT mean (not proven)

| Claim | Status | Honest disposition |
|---|---|---|
| Semantic (vector) recall end-to-end verified | **NOT PROVEN** | Semantic verification delegates ~1,420 lines in `mneme-index` outside the budgeted TCB; the verification object does not carry embeddings for verifier distance recompute (§3 caveat) |
| §11 network sync with object transfer | **STUB** | `mnemed` implements root gossip (`Hello`/`RootProof`/`Bye`) only; no `DiffReq`/`WantObjects`/`HaveObjects`; multi-agent convergence is single-host `merge_from_path` |
| Two-machine cross-host determinism | **PARTIAL** | Same-host dual-workspace passes; SSH cross-host requires `MNEME_SECOND_HOST` (operator-gated) |
| ZK retrieval proof | **DEFERRED** | `pedersen_schnorr_zk` feature is 12-month milestone; v0 default is ADS + optional BLAKE3 `commitment_binding` (not zero-knowledge) |
| Differential oracle / formal verification | **NOT STARTED** | Correctness of `verify_recall` rests on code review, not on a checker or machine-checked proof |
| Global exact-NN (no hidden closer point) | **PHASE IV RESEARCH** | Unbuilt; no PIOP prover shipped |

---

## 2. Crate-Level Status

| Crate | Core/Defer | Key metric |
|---|---|---|
| `mneme-core` | CORE | Frozen interface contracts (§20.3) |
| `mneme-crypto` | CORE | AEAD, Ed25519, key vault, zeroize-on-drop |
| `mneme-smt` | CORE | Membership + non-membership proofs |
| `mneme-dag` | CORE | Provenance head-set, acyclicity |
| `mneme-index` | CORE (key) / DEFER (semantic) | Key-index: proven. Semantic verify: 1,420 lines outside TCB budget |
| `mneme-root` | CORE | Signed roots, checkpoint log, A-REPLAY |
| `mneme-cap` | CORE | Offline-verifiable capabilities |
| `mneme-forget` | CORE | Crypto-shred + tombstone + absence proof |
| `mneme-verify` | CORE (**TCB**) | **474 / 500 lines**, `forbid(unsafe)`, panic-free |
| `mneme-store` | CORE | Atomic transactions, `.incomplete` guard |
| `mneme-mcp` | CORE | 4-tool MCP surface (key recall only in v0) |
| `mneme-cli` | OPERATOR | `verify`, `recall`, `remember`, `forget` |
| `mneme-crdt` | DEFER | MST merge; single-host only |
| `mnemed` | DEFER | Root gossip only; no object sync |
| `mneme-crossref` | DEFER | Assurance/conformance, not runtime TCB |

---

## 3. Test & Verification Statistics

* **`#[test]` count**: ~1,827 across workspace
* **Tamper suite**: 606 store generative cases + verify tamper cases (counted from source)
* **Fuzz targets**: 7 (dcbor, smt, cap, receipt, index_wire, sync, cognition_cert)
* **Key-recall latency**: **197.7 µs** @ 10k (§19 SLA: <1 ms) ✅
* **Dual-workspace determinism**: Byte-identical ✅
* **Independent audit**: `AUDIT_INDEPENDENT_VERDICT.md` — F-2 (High) closed; F-1 closed; F-4/F-5 restated as honest deferrals

---

## 4. Honest residuals (not claimed fixed)

- **F-3, F-6, F-7** (Low) from independent audit — documented, defense-in-depth
- Ingest is fsync-per-key; `merge` is O(merged-set)
- `mneme-verify` semantic path (`semantic.rs`, 91 lines) delegates to `mneme-index` (1,420 lines) which is **not** under the 500-line TCB budget
- No differential oracle or formal verification of the verifier
- `Entry` struct is constructible outside the verifier (frozen interface; requires interface-change request to seal)

---

*This report replaces the previous READINESS.md which over-certified the system as "fully ready, secure, and resilient" and claimed 100% across all crates including deferred components. The honest disposition above matches the §19 exit matrix in README.md and the independent audit verdict in AUDIT_INDEPENDENT_VERDICT.md.*
