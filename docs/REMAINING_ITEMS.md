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

## Turn-key (in-repo substitute passes; full proof unlocks with one input)

- **A1 — cross-physical-host determinism (§17.7).** The `determinism-cross-runner.yml`
  workflow has a `detect-peer` job that reads `secrets.MNEME_SECOND_HOST`, runs the real SSH
  two-host proof when present, and otherwise runs a Docker same-kernel substitute +
  ubuntu-vs-macOS cross-runner comparison. **To unlock:** set `MNEME_SECOND_HOST`,
  `MNEME_DETERMINISM_SSH_KEY`, `MNEME_REMOTE_ROOT`. Nothing to build.

- **A2 — live-LLM MCP agent loop.** CI runs `scripts/ci/mcp-agent-sim.sh` and
  `e2e/mcp/sdk-client.test.mjs`. The live loop is `e2e/mcp/live-agent.test.mjs` (skips
  cleanly without `ANTHROPIC_API_KEY`). **To unlock:** `npm i @anthropic-ai/sdk`, set
  `ANTHROPIC_API_KEY` (+ `MNEME_MCP_BIN`).

## Genuinely deferred (needs a real KMS/HSM endpoint — NOT stubbed)

- **B6 (cloud/HSM adapter)** — The **kernel seam is delivered** (see above). What remains
  is a **concrete adapter** (AWS KMS, GCP KMS, PKCS#11/HSM) validated against a **real
  endpoint**. That cannot be proven without credentials and a target service. Stubbing a
  KMS client that never talks to hardware would be coverage theater.

## Honesty boundary (unchanged)

Single-host v0 remains certified per `READINESS.md` §0. Cross-host determinism is proven
as same-kernel dual-workspace + Docker linux/amd64 digest match + cross-runner CI — **not**
yet on a distinct physical host with `MNEME_SECOND_HOST` until that secret is configured.
