# Appendix B — cross-implementation test vectors

Frozen fixtures for byte conformance (blueprint Appendix B, §17.8). Each directory has a `manifest.json` status marker; PASS means committed fixtures are byte-pinned and backed by existing repo tests/generators.

## Manifest

| Directory | Blueprint item | Status |
|-----------|----------------|--------|
| `objects/` | (1) object→id across all `MemoryKind` values | PASS |
| `dcbor/` | (2) MNEME-dCBOR canonical encodings (map-key ordering edge cases) | PASS |
| `smt/` | (3) SMT membership + non-membership roots and proofs | PASS |
| `roots/` | (4) signed `RootPreimage` + Ed25519 signature | PASS — byte-pinned by `mneme-root` `appendix_b_roots` test |
| `receipts/` | (5) passing + tampered retrieval receipt (ADS backend) | PASS — byte-pinned by `mneme-verify` `appendix_b_receipts` test |
| `receipts/zk/` | Commitment-binding + forgery corpus (not Appendix B item 5) | **PASS (v0)** — `privacy_fixture.json` + `forgery_expectations.json` pin BLAKE3 binding digests and typed `ZkProofInvalid` rejection; **NOT zero-knowledge, NOT SNARK, NOT Plonky2**. Plonky2/V3DB ZK retrieval is **12-month only** (`pedersen_schnorr_zk` feature ships a real Pedersen+Schnorr NIZK on Ristretto — not Plonky2; the previous `plonky2_prover` feature was renamed for honesty; B3 deferral closed) |
| `capabilities/` | (6) capability sig-chain + caveat evaluation | PASS — byte-pinned by `mneme-cap` `appendix_b_capabilities` test |
| `mst/` | (7) MST convergence triple (order-independence) | PASS — byte-pinned by `mneme-crdt` vector test |

**Scope honesty:** PASS means byte-pinned conformance — committed bytes are re-derived by primary crate tests and independently reproduced by the reference crate `mneme-crossref` (`cargo test -p mneme-crossref --test appendix_b_crossref`). CI gate: `scripts/ci/cross-implementation-vectors.sh`. External teams may still ship a third implementation; divergence is a release blocker.

## File conventions

- Payload: `*.cbor` (canonical bytes on disk).
- Expected digests: companion `*.expected` (hex BLAKE3) or `manifest.json` per directory.
- No absolute paths, wall-clock, or PID in hashed inputs (**INV-10**).

## CI

`scripts/ci/check-test-vectors.sh` (full validation lane) asserts this tree exists. Golden digests for nightly live under `proof/digests/`.
