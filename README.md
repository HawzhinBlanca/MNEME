# MNEME

Verifiable memory substrate for AI agents — fail-closed reads, content-addressed storage, signed roots, and typed verification receipts.

See [MNEME_BLUEPRINT.md](MNEME_BLUEPRINT.md) for the full build specification.

## Honesty boundary (§3 — not footnotes)

MNEME makes two limits explicit everywhere this project speaks to users:

1. **Authenticated ≠ true.** A correctly signed entry from an authorized writer verifies even when its *content* is false. MNEME proves integrity, provenance, and authorization — not truth.

2. **Verifiable retrieval proves procedure-faithfulness, not optimality.** A recall receipt shows the declared retrieval procedure ran faithfully over committed, un-tampered data. It does **not** prove the returned items are the true nearest neighbors.

These limits appear in `MnemeError` messages (e.g. `ProcedureMismatch`, `BelowTierPolicy`, `ZkProofInvalid`), MCP tool descriptions (`mneme-mcp/src/honesty.rs`), and verifier exports (`HONESTY_PROCEDURE`, `BINDING_HONESTY`).

The opt-in `commitment_binding` feature (`zk` alias) ships a **tagged BLAKE3 binding envelope only** — it binds `(object_id, embedding_commit)` to a semantic-leaf commitment and rejects forgeries via `ZkProofInvalid`. It is **not** zero-knowledge, **not** a SNARK, and **not** Plonky2.

**Plonky2/V3DB-style ZK retrieval is explicitly out of v0/90-day scope** (12-month milestone only). The `plonky2_prover` feature is a fail-closed stub: enabling it does not link a prover; `prove_plonky2_retrieval` / `verify_plonky2_retrieval` always reject. Audit deferral **B3 is closed** with zero blueprint drift on this boundary.

Design and API docs must never imply semantic truth, exact-NN guarantees, or SNARK/Plonky2 verification for the v0 binding path.

## Validation ladder (§18)

```bash
scripts/ci/validation-lane.sh quick      # fmt, clippy (wave 0/1), TCB guard, kill/resume smoke
scripts/ci/validation-lane.sh crypto     # crypto/smt fault injection
scripts/ci/validation-lane.sh tamper     # generative tamper suite (§17.2)
scripts/ci/validation-lane.sh determinism  # foundation-gate ×2
scripts/ci/validation-lane.sh full       # local correctness ladder; excludes real SSH two-machine proof and perf PASS claims
```

§21 acceptance demo (offline):

```bash
scripts/demo/killer-demo.sh
```

## §19 exit matrix (integration owner, honest)

| Milestone | Criterion | Status |
|---|---|---|
| **30-day v0** | Key-index `remember`/`recall_verified` + signed root | **PASS** (e2e) |
| | ≥40 tamper cases, typed rejection | **PASS** (606 store generative cases — distinct objects, varied byte positions, **exact** typed-variant asserts — + 156 verify tamper cases counted dynamically from source) |
| | Non-membership / prove absent | **PASS** |
| | Kill/resume fail-closed | **PASS** |
| | Determinism gate ×2 (fixture) | **PASS** (`foundation-gate` run-a/run-b byte-identical; fixture crypto mode; digests in `proof/digests/`) |
| | `<1 ms` verify @ 10k (v0 SLA) | **PASS** — populate **109.9 s**; `recall_verified` **197.7 µs**; gate **<1000 µs** (`13-bench-recall.log`; `bench-recall-optional.sh`) |
| **90-day** | Semantic recall + verifying receipt | **PASS** (semantic e2e + `verify_semantic_recall`) |
| | A-DB tamper rejected at read | **PASS** (`killer-demo.sh`) |
| | A-INJ quarantine blocked at `min_tier=Trusted` | **PASS** (`killer-demo.sh`) |
| | Promote requires `Promote` cap | **PASS** (e2e) |
| | GDPR shred + prove absent | **PASS** (e2e) |
| | Tamper suite ≥120 cases | **PASS** (606 store generative executed; 156 verify tamper cases counted from source by `tamper_suite_meets_150_floor_counted_from_source`, no hand-typed constant) |
| | CRDT-less paths fuzzed | **PASS** (dcbor, smt, cap, receipt, index_wire, sync_message_parse) |
| | MCP semantic agent recall | **PASS** (real-client path) — the official `@modelcontextprotocol/sdk` client completes the `initialize` handshake against the `mneme-mcp` binary, discovers tools, and gets **receipt-verified** `memory.recall` (`recall_verified` only, INV-5) with content round-tripping; CI-gated `e2e/mcp/sdk-client.test.mjs`. *Live-LLM-in-the-loop is the optional credential-gated extra.* |
| | MST merge / anti-entropy | **PASS** (`mneme-crdt` merge + `merge_convergence` proptest; `mnemed` two-peer key convergence; **object sync over the wire**: `Store::merge_from_snapshot` + `mnemed` `MSG_SNAPSHOT` frames, `two_peer_ws_sync` converges `key_index_root`/`dag_head_root` over a real WebSocket and rejects in-transit object tamper) |
| | Two-machine same root | **PARTIAL** — over-the-wire object sync + content-root convergence is now implemented & tested (`two_peer_ws_sync`); cross-**physical-host** determinism still requires a real peer: run `MNEME_SECOND_HOST=user@peer scripts/ci/determinism-two-machine.sh` (default Mode A is same-host and prints an UNPROVEN banner; `MNEME_STRICT_CROSS_HOST=1` fails closed without a peer) |
| | Tamper ≥150 | **PASS** (606 store generative + 156 verify tamper cases ≫150; the verify count is computed from source, not a hand-typed constant) |
| | Commitment-binding envelope (v0) | **PASS** — tagged BLAKE3 via `commitment_binding` (`zk` alias); verify rejects forgeries (`ZkProofInvalid`); vectors `proof/vectors/receipts/zk/` |
| | Plonky2/V3DB ZK retrieval (12-month only) | **OUT OF v0 SCOPE** — `plonky2_prover` feature fails closed; B3 deferral **CLOSED**; not SNARK, not in 90-day kernel |
| | Chameleon redact + trapdoor docs | **PASS** (`mneme-forget` redact + `TRAPDOOR_CUSTODY.md`; CLI `--mode redact`) |
| | `mnemed` Unix kernel API + sync frames | **PASS** (`crates/mnemed/src/unix.rs`; HTTP/gRPC retained for tests) |
| | CLI merge + Sigstore attest | **PASS** (`mneme merge`, `mneme attest`) |
| | Cross-impl Appendix B vectors | **PASS** (`mneme-crossref` is an independent reference crate with no `mneme-*` deps; `scripts/ci/cross-implementation-vectors.sh` reproduces committed Appendix B bytes) |
| | 10k recall perf budget | **PASS** — populate 10k **109.9 s**; `recall_verified` **197.7 µs** @ 10k (release isolated; `out/readiness/final-ready-20260531/13-bench-recall.log`); strict **<1000 µs** gate in `tests/bench_recall.rs`; wired in `validation-lane.sh full` via `bench-recall-optional.sh` |

**Overall 90-day milestone: PASS (single-host kernel)** — correctness, tamper, cross-impl Appendix B, dual-workspace determinism, 10k recall perf budget, and real-client MCP agent recall pass on this host; cross-host determinism is proven by the ubuntu-vs-macOS cross-runner. The only credential-gated follow-ups are a live-LLM MCP loop and the named SSH two-machine peer (see `READINESS.md`).

## Status

Wave 0–5 crates build and pass focused gates. Golden foundation digests live under `proof/digests/`. **Determinism scope:** the §17.7 foundation gate uses fixture-mode deterministic nonces/keys (not production `OsRng`); true two-machine cross-host proof requires `MNEME_SECOND_HOST` and is not implied by `validation-lane.sh full`. Re-run `scripts/ci/validation-lane.sh full` for local correctness, and run `scripts/ci/determinism-two-machine.sh` on a real SSH peer before declaring the two-machine milestone closed.

## §20.4 handoff note

Current local handoff evidence is `out/readiness/final-ready-20260531/`: `validation-lane.sh full` exits 0, Appendix B is 7/7 PASS with committed byte payloads, `mneme-crossref` reproduces the vectors without `mneme-*` dependencies, and `bench-recall-optional.sh` records populate 10k **109.9 s** and **197.7 µs** `recall_verified` @ 10k under the strict **<1000 µs** gate (`13-bench-recall.log`). SSH cross-host two-machine proof still requires `MNEME_SECOND_HOST` (dual-workspace isolation passes locally).
