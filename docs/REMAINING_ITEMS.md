# MNEME — Remaining Items (honest disposition)

Last updated: 2026-06-11 (`master` @ `28f3cf47`; doc sync after PR #37 P3 local scaffolds).
This tracks items beyond the certified single-host v0 core. Each entry states what is
in-repo, what is gated, and *why* it cannot be marked done without an external input.

> **Work order (2026-06-08):** [`docs/WORK_ORDER_DEEP_INSPECTION_2026-06-08.md`](WORK_ORDER_DEEP_INSPECTION_2026-06-08.md).
> **P0–P2 software scope: 100% complete** on `master` (merged via PR #8 @ `558af8e`;
> WO-1..WO-20 delivered; `validation-lane.sh quick` + `tamper` + `determinism` green on master).
> **P3 external proofs remain human/hardware-gated** (live KMS/HSM, distinct physical host
> convergence, TEE vendor quotes, machine-checked Lean). **P3 local scaffolds landed**
> on `master` via PR #37 @ `28f3cf47` (`validation-lane.sh p3-local`; see
> [`docs/P3_LOCAL_SCAFFOLDS.md`](P3_LOCAL_SCAFFOLDS.md)) — substitutes only, not external proof.
> **PR #8:** https://github.com/HawzhinBlanca/MNEME/pull/8 — **merged** 2026-06-09 @ `558af8e`
> (generative zkANN adversarial harness + distance-unbound finding; e2e fixes `3b44142`, `3556ed8`).

## P0–P2 closeout (2026-06-08, software-complete)

All prioritized honesty, correctness, deployment-hardening, MCP, and L3-delivery items
from the deep inspection are implemented and gated in-repo on `master`. P3 local scaffolds
landed (PR #37); external P3 proofs stay operator-gated. No further P0/P1/P2 code tasks block
the certified single-host v0 core.

## Delivered (code, tested, CI-verified)

- **B3** — durable group-commit: batched vault-key journal + snapshot key-index persist.
  Durable 10k ingest 105.9s → 1.17s (~90×). `feat 71c7ac3`.
- **B5** — concurrent-merge O(1) snapshot persist: 0.08 → 0.12 merges/s (~1.5×). `feat 2bf1fbb`.
- **B4** — AEAD-sealed vault-key transfer over §11 sync: same-trust-domain peers recall each
  other's **plaintext** after WebSocket sync; A-NET / foreign-operator / tampered-bundle all
  fail closed. `feat 19f8ca6`. See `docs/benchmarks/B4_SEALED_VAULT_KEY_SYNC.md`.
- **B6 (seam)** — `Store` is pluggable over `KeyVault`: `Box<dyn KeyVault + Send>`,
  `create_with_vault` / `open_with_vault`, batch ops (`begin_batch` / `flush_batch` /
  `cancel_batch`) on the trait with no-op defaults, `MemoryKeyVault` + parity test
  (`file_and_memory_vaults_have_identical_behaviour`), contract in
  [`docs/HSM_KMS_ADAPTER.md`](HSM_KMS_ADAPTER.md). TCB untouched; determinism foundation-gate
  byte-identical after refactor.
- **A1 — cross-physical-host determinism (§17.7) — PROVEN.** Foundation-gate `RunDigest`
  byte-identical across **macOS/arm64 ↔ Windows/x86_64** (two hosts, two OSes, two arches),
  commit `df5997a`, 5/5 fields. See [`docs/benchmarks/XHOST_DETERMINISM_PROOF.md`](benchmarks/XHOST_DETERMINISM_PROOF.md)
  + `scripts/ci/xhost-determinism-compare.sh`. Also fixed a real Windows durability bug
  (`atomic.rs::sync_parent_dir` now `#[cfg(unix)]`; Windows keeps file-level `sync_all`).
  The SSH-automated `MNEME_SECOND_HOST` CI leg remains for continuous re-verification.

## Turn-key (in-repo substitute passes; full proof unlocks with one input)

- **A2 — live-LLM MCP agent loop.** CI runs `scripts/ci/mcp-agent-sim.sh` and
  `e2e/mcp/sdk-client.test.mjs`. The live loop is `e2e/mcp/live-agent.test.mjs` (skips
  cleanly without `ANTHROPIC_API_KEY`). **To unlock:** `npm i @anthropic-ai/sdk`, set
  `ANTHROPIC_API_KEY` (+ `MNEME_MCP_BIN`).

## Delivered (2.0 waves C–E, 2026-06-02)

- **2.0-C** — Merge object batch writes (`write_objects_batch`: one parent-dir fsync per
  shard); incremental semantic index (`apply_merge_delta` on merge).
- **2.0-D** — `EnvelopeKeyVault` + `scripts/kms/dek-from-aws.sh` (AWS KMS DEK → env master).
  In-process `aws-sdk-kms` deferred until toolchain ≥1.91 (repo pins 1.86.0).
- **2.0-E** — `scripts/demo/sync-two-peer-demo.sh`; `.github/workflows/mneme-2-nightly.yml`
  (ZK semantic, envelope, optional live MCP when `ANTHROPIC_API_KEY` secret set).

## P3 local scaffolds (landed PR #37 @ `28f3cf47`, 2026-06-11)

Aggregate gate: `scripts/ci/validation-lane.sh p3-local`. Scripts:
`convergence-two-host.sh --local-smoke`, `kms/conformance-local.sh`,
`attestation-policy-local.sh`, `formal-obligations-local.sh`. Spec:
[`docs/P3_LOCAL_SCAFFOLDS.md`](P3_LOCAL_SCAFFOLDS.md). **Honesty:** local substitutes only;
does not replace live KMS/HSM, distinct-host SSH, TEE enclave, or Lean verification.

## Genuinely deferred (needs a real KMS/HSM endpoint for proof, not stubs)

- **B6 (cloud/HSM proof)** — Adapters + `conformance-local.sh` ship; **continuous proof**
  against a live `AWS_KMS_KEY_ID` remains operator-gated (nightly job compiles only).
  GCP/PKCS#11 still open.

## Honesty boundary (unchanged)

Single-host v0 remains certified per `READINESS.md` §0. Cross-host determinism is proven
as same-kernel dual-workspace + Docker linux/amd64 digest match + cross-runner CI — **not**
yet on a distinct physical host with `MNEME_SECOND_HOST` until that secret is configured.

## Complete k-NN / JL compression (CR-5..CR-7, 2026-06-11)

**Shipped:** exact complete k-NN (CR-1..CR-4) plus beacon-seeded JL **conservative** pruning
(prototype in `mneme-index::complete_knn::jl_projection`) with a proved no-wrong-prune ceiling
([`docs/research/JL_DISTORTION_BOUND.md`](research/JL_DISTORTION_BOUND.md)). Reproducible synthetic
compression gate: `cargo test -p mneme-index --test complete_knn_compression -- --nocapture`.

**Honest disposition:** in raw high `D` (test gate: `D=128`), exact pruning does not compress
(`|F|/n → 1`); JL conservative may help in moderate `D` on synthetic data but **does not**
close the open problem of sublinear **and** sound pruning on production embedding manifolds
(768–1536-d). Probabilistic JL mode is empirical-only (δ heuristic test, not a theorem on real
embeddings). `CompleteTopK` offline `verify-cert` and store `certify` issuance are **landed**
on `master` (PR #24 @ `31a54b0`); JL probabilistic mode and real 768–1536-d compression sweeps
remain open.

## Provably-complete retrieval (CR-5..CR-7, 2026-06-11)

Work order: [`docs/WORK_ORDER_COMPLETE_RETRIEVAL.md`](WORK_ORDER_COMPLETE_RETRIEVAL.md).
CR-1..CR-4 (exact ball-tree + tamper suite) ships on PR #15 (`cursor/complete-retrieval-cr1-4`).

**Delivered on `master` (CR-5..CR-7 + PR #24)**

| Item | Status | Notes |
|---|---|---|
| CR-5 JL conservative mode | **Landed** | Beacon-seeded `Φ`, `(1+ε)`-inflated pruning bound; proptest proves conservative search == brute-force on low/moderate `m`. |
| CR-5 JL probabilistic mode | **Scaffold** | Raw projected bound implemented; empirical `δ` gate **not** closed on 768–1536-dim embedding distributions — honest ceiling. |
| CR-6 `CompleteTopK` level | **Landed** | `RetrievalProofLevel::CompleteTopK` (tag 2); receipt field 8; `verify-cert` offline complete-kNN check; cert byte-identical ×2 test. |
| CR-6 store `certify` path | **Landed** | `SemanticIndex::recall_receipt_zkann(CompleteTopK)` + `Store::issue_cognition_certificate_v1` / `mneme certify --level complete-topk`. |
| CR-6 crossref vector | **Landed** | Appendix B `cognition_cert_complete_topk.cbor` (receipt field 8, level tag 2); `mneme-crossref::wire_complete_knn` verify path. |
| CR-7 compression curve | **Landed (honest)** | Reproducible `|F|/n` snapshot in [`docs/benchmarks/COMPLETE_KNN_COMPRESSION.md`](benchmarks/COMPLETE_KNN_COMPRESSION.md): exact pruning collapses to `|F|/n → 1` by D≥128 on uniform random points; JL conservative preserves exactness but does not beat the curse of dimensionality on this baseline. |

**Dimension ceiling (§3 honesty, unchanged):** complete-kNN proves *retrieval completeness over committed geometry*, not semantic truth. In raw high-D embedding space, reverse-triangle bounds rarely prune; certificates stay *correct* but not *succinct*. JL conservative mode trades compression for a sound never-wrongly-prune guarantee; finding `(m, ε)` that is both sublinear and sound on production embedding manifolds remains the open research prize — an acceptable honest outcome, not hidden.
