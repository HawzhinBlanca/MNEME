# MNEME — Remaining Items (honest disposition)

Last updated: 2026-06-01 (B6 seam refactor committed). This tracks items beyond the
certified single-host v0 core. Each entry states what is in-repo, what is gated, and
*why* it cannot be marked done without an external input.

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

## Genuinely deferred (needs a real KMS/HSM endpoint for proof, not stubs)

- **B6 (cloud/HSM proof)** — Adapters ship; **continuous proof** against a live
  `AWS_KMS_KEY_ID` remains operator-gated (nightly job compiles only). GCP/PKCS#11 still open.

## Honesty boundary (unchanged)

Single-host v0 remains certified per `READINESS.md` §0. Cross-host determinism is proven
as same-kernel dual-workspace + Docker linux/amd64 digest match + cross-runner CI — **not**
yet on a distinct physical host with `MNEME_SECOND_HOST` until that secret is configured.
