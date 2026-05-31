# MNEME — Remaining Items (honest disposition)

Last updated: 2026-06-01. This tracks the items beyond the certified single-host v0 core.
Each entry states exactly what is in-repo, what is gated, and *why* it cannot simply be
"marked done" without an external input.

## Delivered (code, tested, CI-verified)

- **B3** — durable group-commit: batched vault-key journal + snapshot key-index persist.
  Durable 10k ingest 105.9s → 1.17s (~90×). `feat 71c7ac3`.
- **B5** — concurrent-merge O(1) snapshot persist: 0.08 → 0.12 merges/s (~1.5×). `feat 2bf1fbb`.
- **B4** — AEAD-sealed vault-key transfer over §11 sync: same-trust-domain peers recall each
  other's **plaintext** after WebSocket sync; A-NET / foreign-operator / tampered-bundle all
  fail closed. `feat 19f8ca6`. See `docs/benchmarks/B4_SEALED_VAULT_KEY_SYNC.md`.

## Turn-key (in-repo substitute passes; full proof unlocks with one input)

- **A1 — cross-physical-host determinism (§17.7).** The `determinism-cross-runner.yml`
  workflow already has a `detect-peer` job that reads `secrets.MNEME_SECOND_HOST`, runs the
  real SSH two-host proof when present, and otherwise runs a Docker same-kernel substitute +
  the ubuntu-vs-macOS cross-runner comparison and skips the SSH leg with a clear message.
  **To unlock:** set `MNEME_SECOND_HOST`, `MNEME_DETERMINISM_SSH_KEY`, `MNEME_REMOTE_ROOT`.
  Nothing to build — the job lights up automatically.

- **A2 — live-LLM MCP agent loop.** The deterministic substitute (`scripts/ci/mcp-agent-sim.sh`,
  a 9-turn simulated agent over real `mneme-mcp` stdio) and the official-SDK-client interop
  test (`e2e/mcp/sdk-client.test.mjs`) both run in CI. The **live** loop is now wired in
  `e2e/mcp/live-agent.test.mjs`: it drives a real Anthropic model through the MCP tool-use
  loop (remember → recall, asserting both tools fire and content round-trips via
  `recall_verified`). It **skips cleanly** when `ANTHROPIC_API_KEY` is unset (the CI case),
  before touching any optional dependency, so the standard `node --test e2e/mcp/*.test.mjs`
  lane stays green. **To unlock:** `npm i @anthropic-ai/sdk`, set `ANTHROPIC_API_KEY` (+
  `MNEME_MCP_BIN`), run the test.

## Genuinely deferred (needs an external target + a scoped refactor — NOT faked)

- **B6 — HSM/KMS-backed vault.** Honest status of the seam:
  - `mneme_crypto::KeyVault` is a trait (`new_key`/`get`/`shred`/`contains`) with a
    `MemoryKeyVault` impl — so the *read/write* seam exists.
  - **But** `mneme_store::Store` holds a **concrete** `FileKeyVault`, and the durable
    group-commit path (B3) calls `begin_batch`/`flush_batch`/`cancel_batch`, which are
    **inherent to `FileKeyVault`, not on the trait**.
  - A real KMS adapter therefore requires: (1) extending `KeyVault` to cover batch
    semantics (or a separate batching seam), (2) making `Store` generic/`dyn` over the
    trait, and (3) a concrete adapter (AWS KMS, PKCS#11/HSM, GCP KMS) validated against a
    **real KMS endpoint**. Items (1)–(2) are a non-trivial kernel refactor; (3) cannot be
    proven without a target. This is intentionally left scoped rather than stubbed: a
    KMS adapter that is never exercised against a real endpoint would be coverage theater.

## Honesty boundary (unchanged)

Single-host v0 remains certified per `READINESS.md` §0. The cross-host determinism leg is
proven as same-kernel/dual-workspace + cross-runner, **not** yet on a distinct physical host
with `MNEME_SECOND_HOST` — that boundary stands until the secret is configured.
