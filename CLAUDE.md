# CLAUDE.md

This file is the **canonical, universal** agent guidance for this
repository. It is the single source of truth for build/test commands,
architecture invariants, the §3 honesty boundary, and workspace layout.
Every other agent guidance file (e.g. [`AGENTS.md`](AGENTS.md) for
Codex CLI) must defer to this file for load-bearing content and only
document tool-specific deltas.

If you change a build command, an architecture invariant, or a §3
honesty string: edit this file. Tool-specific deltas belong in the
other file.

## What is MNEME

Verifiable memory substrate for AI agents. Every recall must carry a receipt that verifies against a signed root under a declared retrieval procedure — if verification fails for any reason, the read **fails closed** and the memory never enters context. The system proves integrity, provenance, and authorization; it explicitly **does not** prove semantic truth or exact nearest-neighbor optimality.

## Build and test commands

```bash
# Format check
cargo fmt --all -- --check

# Lint (wave 0/1 + store kernel)
cargo clippy -p mneme-core -p mneme-crypto -p mneme-smt -p mneme-dag \
  -p mneme-root -p mneme-cap -p mneme-verify -p mneme-store \
  --lib --tests -- -D warnings

# Run a single crate's tests
cargo test -p mneme-store -- --nocapture
cargo test -p mneme-verify -- --nocapture
cargo test -p mneme-store -- recall_verified --nocapture   # single test by name

# Full workspace tests
cargo test --workspace -- --nocapture

# Validation ladder (preferred way to run gates)
scripts/ci/validation-lane.sh quick        # fmt + clippy + TCB guard + kill/resume smoke
scripts/ci/validation-lane.sh crypto       # crypto/smt fault injection
scripts/ci/validation-lane.sh tamper       # generative tamper suite (≥150 cases)
scripts/ci/validation-lane.sh determinism  # foundation-gate ×2
scripts/ci/validation-lane.sh full         # everything above + bench + fuzz + vectors

# §21 acceptance demo (offline, tests real adversarial scenarios)
scripts/demo/killer-demo.sh

# Fuzz (cargo-fuzz required; targets: dcbor_parse, smt_parse, cap_parse, receipt_parse, index_wire, sync_message_parse)
scripts/ci/fuzz-smoke.sh          # fast smoke (-runs=16)
scripts/ci/fuzz-meaningful.sh     # ≥30s per target

# Bench recall perf (§19 SLA: recall_verified <1 ms @ 10k)
scripts/ci/bench-recall-optional.sh
```

Toolchain: Rust **1.86.0** (see `rust-toolchain.toml`; `rustfmt` and `clippy` components required).

## Workspace layout

| Crate | Role |
|---|---|
| `mneme-core` | Frozen interface contracts (§20.3), `ObjectId`, `LogicalKey`, `Root`, `Receipt`, `TrustTier`, HLC, dCBOR codec |
| `mneme-crypto` | Ed25519 signing, ChaCha20-Poly1305 AEAD, key vault, chameleon redaction |
| `mneme-smt` | Sparse Merkle Tree: membership and non-membership proofs |
| `mneme-dag` | DAG index tracking parent/head pointers across objects |
| `mneme-index` | Key-index (SMT-backed) and semantic index (HNSW) with recall receipts |
| `mneme-root` | Signed root assembly, checkpoint log, A-REPLAY detection |
| `mneme-cap` | Offline-verifiable capability tokens (scoped write/promote/forget) |
| `mneme-forget` | GDPR shred, tombstone, prove-absent, chameleon redaction |
| `mneme-crdt` | CRDT merge / anti-entropy wire format (MST-style) |
| `mneme-verify` | **Fail-closed verifier TCB** — `verify_recall`, `verify_semantic_recall`, `verify_store`; `TCB_LINE_BUDGET = 500` |
| `mneme-store` | Store kernel: `remember` / `recall_verified` / `forget` / `promote`; atomic transactions with crash-safe `.incomplete` guard |
| `mneme-mcp` | MCP stdio server exposing store ops to AI agents |
| `mneme-cli` | `mneme` binary: `verify`, `recall`, `remember`, `forget`, `merge`, `attest`, `determinism` |
| `mnemed` | Local daemon with HTTP (`:7845`) + optional gRPC + Unix socket APIs, sync over WebSocket |
| `mneme-crossref` | Independent reference implementation of Appendix B vectors (zero `mneme-*` deps) |
| `fuzz/` | `cargo-fuzz` targets; excluded from workspace build |

## Architecture invariants (never violate)

- **INV-5**: Agent-facing reads use only `Store::recall_verified` / `recall_verified_default`. The untrusted index path (`Store::recall`) is `pub(crate)`.
- **INV-6**: Cold open rejects if any on-disk signed checkpoint has a higher sequence than `HEAD` (`RootReplayed` error). This closes the A-REPLAY rollback vector.
- **Fail-closed default**: every error path rejects rather than guesses. `MnemeError` variants are the typed rejection surface.
- **TCB budget**: `mneme-verify` must stay under 500 lines. Adding logic there requires explicit invariant justification.
- **Interface freeze**: types in `mneme-core/src/interface.rs` are normative seams. Field layout, enum variants, and hashing rules must not change without a formal interface-change request.

## Key data flow

```
Draft + Capability
    → Store::remember()          # atomic: .incomplete guard + object write + SMT upsert + signed root
    → signed Root (Ed25519)

Query + Procedure + Capability
    → Store::recall_verified()   # untrusted index fetch → receipt build → verify_recall() gate
    → Vec<Entry> or MnemeError   # fail-closed: no receipt → rejected
```

The `mneme-crossref` crate is an independent reimplementation of the Appendix B test vectors. It must not import any `mneme-*` workspace crate — this property is verified by `scripts/ci/cross-implementation-vectors.sh`.

## Honesty boundary (must be preserved in all code and docs)

1. **Authenticated ≠ true.** Signed entries verify even when content is false. MNEME proves integrity, provenance, authorization — not truth.
2. **Verifiable retrieval proves procedure-faithfulness, not exact nearest neighbors.**
3. The `commitment_binding` feature is a **tagged BLAKE3 envelope only** — not zero-knowledge, not a SNARK. (A legacy `zk = ["commitment_binding"]` Cargo feature alias was removed because it implied zero-knowledge, which the BLAKE3 envelope is not.) The `pedersen_schnorr_zk` feature (12-month milestone B3, off by default; previously mis-named `plonky2_prover` and renamed for honesty) is a **real transparent zero-knowledge proof**: Pedersen commitments + a Schnorr equality-of-openings NIZK over Ristretto (Fiat–Shamir, no trusted setup). It proves *faithful execution of a committed retrieval-match with witness privacy* — it is **not** Plonky2 and **not** a FRI/PLONK SNARK (Plonky2 1.x is nightly-only; the repo pins stable 1.86.0), and it still does **not** prove semantic truth or exact nearest neighbors. The `B3_DEFERRAL_STATUS` string in `pedersen_schnorr_zk.rs` records the Plonky2/FRI SNARK deferral.

These limits appear in `MnemeError` messages, MCP tool descriptions, and verifier exports. Never weaken or remove them.

## Scope notes

- No new vector-search engine (wrap existing ANN via `mneme-index`).
- No blockchain, no token, no on-chain dependency.
- No ZK proving system in v0/90-day scope.
- `mnemed` gRPC API is retained for tests only; the primary kernel API is Unix socket.
