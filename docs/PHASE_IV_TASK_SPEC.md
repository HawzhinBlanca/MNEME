# MNEME ∞ — Phase IV Task Specification

**Scale & standard** — global exact-NN, federated cognition certificates, and open interop. This is a **research-only** slice on `master`; no PIOP prover or new verifier code ships here.

**Status:** Deferred research. **Baseline:** `master` green; Phase I–III software slices present. **Prime directives unchanged:** fail-closed; verifier TCB ≤ 500 lines (`mneme-verify`); authenticated ≠ true; stable toolchain (Rust 1.86.0); **no SNARK/FRI/PIOP prover implemented.**

---

## 0. Scope and honesty (non-goals)

- No PIOP/FRI/Plonky2 prover or verifier lands in `mneme-verify` or the recall path.
- `piop_research` feature is **off by default**, wired to no recall/receipt path, and its entry point returns **`UnsupportedVersion`** (fail-closed) if ever called; it proves nothing.
- Honest level remains **dominance over the committed/visited set**; global exact-NN is a research target only.
- Hardware/TEE, federated deployments, and interop SDKs are **not** implemented in this slice.

---

## 1. Exit criteria (Phase IV closes when all green)

### P4-1 — Global exact-NN (zkRAG/PIOP path)
- [x] Research memo captured (`docs/research/PHASE_IV_A_PIOP_SPIKE.md`), explicitly author-reported numbers only.
- [x] Research seam scaffolded: `piop_research` flag off-by-default; `prove_exact_nn_piop` returns `UnsupportedVersion` (fail-closed `Err`, not panic) and is not on any recall/receipt/verify path.
- [x] Formal exact-NN statement + threat model sketch (`docs/research/PHASE_IV_A_PIOP_STATEMENT.md`, spike §6 Step 1).
- [x] Stable-toolchain survey of succinct-argument stacks (`docs/research/PHASE_IV_A_PIOP_TOOLCHAIN_MATRIX.md`, spike §6 Step 2; no nightly pin).
- [ ] Field-friendly commitment sidecar spike + determinism cost (BLAKE3 bridge) with measured overhead.
- [ ] Out-of-TCB prototype prover/verifier on a tiny flat index with honest prover/verify/size numbers (labeled hardware + |V| + dim).
- [x] Threat model + certificate integration design (fail-closed degradation rule in statement doc §4.4; `retrieval_proof_level` naming TBD until prototype).

### P4-2 — Federated cognition certificates
- [x] Cross-org wire sketch: `federation_cert.rs` types + fail-closed decode/verify (`UnsupportedVersion` while gate closed).
- [x] Verify-sketch fuzz + forgery unit tests (`federation_cert_parse`, `federation_cert_verify`; red-team doc).
- [ ] CRDT merge binding proof + honest trust-surface write-up (keys, revocation, replay protection).

### P4-3 — Open standardization + interop SDKs
- [x] Interop SDK surface stub (`docs/phase-program/INTEROP_SDK_STUB.md`); full standard text still open.
- [x] Crossref gap notes + federation field map (`docs/phase-program/PHASE_IV_CROSSREF_NOTES.md`).
- [ ] External verifier implementation proof point (independent of MNEME repo).

### P4-4 — Cost-to-default
- [ ] Performance/Cost model showing path to “verified by default” tier (prove/verify cost within ~10% target SLA).
- [x] Benchmark harness + reporting plan (`scripts/ci/phase-iv-cost-report.sh`; **no production numbers** header).

---

## 2. References

- `docs/research/PHASE_IV_A_PIOP_SPIKE.md` — zkRAG-style PIOP spike (research-only).
- `docs/research/PHASE_IV_A_PIOP_STATEMENT.md` — exact-NN statement + threat model (Step 1).
- `docs/research/PHASE_IV_A_PIOP_TOOLCHAIN_MATRIX.md` — stable toolchain survey (Step 2).
- `docs/phase-program/INTEROP_SDK_STUB.md` — interop SDK draft surface.
- `docs/phase-program/PHASE_IV_CROSSREF_NOTES.md` — crossref extension notes.
- `scripts/ci/phase-iv-cost-report.sh` — P4-4 planning report (no production numbers).
- `docs/ROADMAP.md` — Phase overview; Phase IV listed as research-only target.

---

*Phase IV is honest when it says “still research.” No prover exists, no new trust assumptions are added, and all receipts continue to prove procedure-faithfulness over the committed/visited set until the blockers are cleared and measured.* 
