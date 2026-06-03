# MNEME ∞ — Phase IV Task Specification

**Scale & standard** — global exact-NN, federated cognition certificates, and open interop. This is a **research-only** slice on `master`; no PIOP prover or new verifier code ships here.

**Status:** Deferred research. **Baseline:** `master` green; Phase I–III software slices present. **Prime directives unchanged:** fail-closed; verifier TCB ≤ 500 lines (`mneme-verify`); authenticated ≠ true; stable toolchain (Rust 1.86.0); **no SNARK/FRI/PIOP prover implemented.**

---

## 0. Scope and honesty (non-goals)

- No PIOP/FRI/Plonky2 prover or verifier lands in `mneme-verify` or the recall path.
- `piop_research` feature is **off by default**, wired to no recall/receipt path, and its entry point **panics** (fail-closed) if ever called; it proves nothing.
- Honest level remains **dominance over the committed/visited set**; global exact-NN is a research target only.
- Hardware/TEE, federated deployments, and interop SDKs are **not** implemented in this slice.

---

## 1. Exit criteria (Phase IV closes when all green)

### P4-1 — Global exact-NN (zkRAG/PIOP path)
- [x] Research memo captured (`docs/research/PHASE_IV_A_PIOP_SPIKE.md`), explicitly author-reported numbers only.
- [x] Research seam scaffolded: `piop_research` flag off-by-default; `prove_exact_nn_piop` panics and is not on any recall/receipt/verify path.
- [ ] Stable-toolchain survey of succinct-argument stacks (no nightly pin; transparency + dependency weight recorded).
- [ ] Field-friendly commitment sidecar spike + determinism cost (BLAKE3 bridge) with measured overhead.
- [ ] Out-of-TCB prototype prover/verifier on a tiny flat index with honest prover/verify/size numbers (labeled hardware + |V| + dim).
- [ ] Threat model + certificate integration design: `retrieval_proof_level` upgrade path; fail-closed degradation rule (PIOP absent/invalid → current honest level).

### P4-2 — Federated cognition certificates
- [ ] Cross-org / multi-agent certificate format draft; binding to existing CRDT merge.
- [ ] Honest trust-surface write-up (keys, revocation, replay protection) — no code yet.

### P4-3 — Open standardization + interop SDKs
- [ ] Draft standard text + verifier SDK surface sketches (multi-language) aligned to the certificate schema.
- [ ] External verifier implementation proof point (independent of MNEME repo).

### P4-4 — Cost-to-default
- [ ] Performance/Cost model showing path to “verified by default” tier (prove/verify cost within ~10% target SLA).
- [ ] Benchmark harness + reporting plan (no figures promised until implemented).

---

## 2. References

- `docs/research/PHASE_IV_A_PIOP_SPIKE.md` — zkRAG-style PIOP spike (research-only).
- `docs/ROADMAP.md` — Phase overview; Phase IV listed as research-only target.

---

*Phase IV is honest when it says “still research.” No prover exists, no new trust assumptions are added, and all receipts continue to prove procedure-faithfulness over the committed/visited set until the blockers are cleared and measured.* 
