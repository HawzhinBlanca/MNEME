# MNEME

Verifiable memory substrate for AI agents — fail-closed reads, content-addressed storage, signed roots, and typed verification receipts.

See [MNEME_BLUEPRINT.md](MNEME_BLUEPRINT.md) for the full build specification.

## Honesty boundary (§3 — not footnotes)

MNEME makes two limits explicit everywhere this project speaks to users:

1. **Authenticated ≠ true.** A correctly signed entry from an authorized writer verifies even when its *content* is false. MNEME proves integrity, provenance, and authorization — not truth.

2. **Verifiable retrieval proves procedure-faithfulness, not optimality.** A recall receipt shows the declared retrieval procedure ran faithfully over committed, un-tampered data. It does **not** prove the returned items are the true nearest neighbors.

These limits appear in `MnemeError` messages (e.g. `ProcedureMismatch`, `BelowTierPolicy`, `ZkProofInvalid`), MCP tool descriptions (`mneme-mcp/src/honesty.rs`), and verifier exports (`HONESTY_PROCEDURE`, `BINDING_HONESTY`).

The opt-in `commitment_binding` feature (`zk` alias) ships a **tagged BLAKE3 binding envelope only** — it binds `(object_id, embedding_commit)` to a semantic-leaf commitment and rejects forgeries. It is **not** zero-knowledge, **not** a SNARK, and **not** Plonky2. Full Plonky2/V3DB-style privacy receipts remain deferred.

Design and API docs must never imply semantic truth, exact-NN guarantees, or SNARK/Plonky2 verification for the binding path.

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
| | ≥40 tamper cases, typed rejection | **PASS** (830 store generative assertions + 147 verify tamper tests) |
| | Non-membership / prove absent | **PASS** |
| | Kill/resume fail-closed | **PASS** |
| | Determinism gate ×2 (fixture) | **PASS** (`foundation-gate` run-a/run-b byte-identical; fixture crypto mode; digests in `proof/digests/`) |
| **90-day** | Semantic recall + verifying receipt | **PASS** (semantic e2e + `verify_semantic_recall`) |
| | A-DB tamper rejected at read | **PASS** (`killer-demo.sh`) |
| | A-INJ quarantine blocked at `min_tier=Trusted` | **PASS** (`killer-demo.sh`) |
| | Promote requires `Promote` cap | **PASS** (e2e) |
| | GDPR shred + prove absent | **PASS** (e2e) |
| | Tamper suite ≥120 cases | **PASS** (store generative ≥120 executed; 147 verify tamper `#[test]`s across cap/checkpoint/semantic/suite/tombstone) |
| | CRDT-less paths fuzzed | **PASS** (dcbor, smt, cap, receipt, index_wire, sync_message_parse) |
| | MCP semantic agent recall | **NEEDS WORK** (MCP wrapper present; live Claude path not CI-gated) |
| **12-month** | MST merge / anti-entropy | **PASS** (`mneme-crdt` merge + `merge_convergence` proptest; `mnemed` two-peer key convergence) |
| | Two-machine same root | **NEEDS WORK** (`determinism-two-machine.sh` is SSH-only and fails closed without `MNEME_SECOND_HOST`; local proxy is labeled LOCAL-ONLY) |
| | Tamper ≥150 | **PASS** (830 store generative + 147 verify tamper tests ≫150 combined; verify inventory reconciled to 147 executed) |
| | Commitment-binding envelope (Plonky2 deferred) | **NEEDS WORK** — binding envelope only: tagged BLAKE3 via `commitment_binding` (`zk` alias); **NOT SNARK, NOT Plonky2**; roundtrip corpus at `proof/vectors/receipts/zk/privacy_fixture.json` |
| | Chameleon redact + trapdoor docs | **PASS** (`mneme-forget` redact + `TRAPDOOR_CUSTODY.md`; CLI `--mode redact`) |
| | `mnemed` Unix kernel API + sync frames | **PASS** (`crates/mnemed/src/unix.rs`; HTTP/gRPC retained for tests) |
| | CLI merge + Sigstore attest | **PASS** (`mneme merge`, `mneme attest`) |
| | Cross-impl Appendix B vectors | **PASS** (`mneme-crossref` is an independent reference crate with no `mneme-*` deps; `scripts/ci/cross-implementation-vectors.sh` reproduces committed Appendix B bytes) |
| | 10k recall perf budget | **PASS** — `recall_verified` **191–227 µs** @ 10k (release isolated; `out/readiness/final-ready-20260530/22-bench-recall.log`); strict blueprint `<1 ms` gate in `tests/bench_recall.rs`; wired in `validation-lane.sh full` via `bench-recall-optional.sh` |

**Overall 90-day milestone: PASS (single-host kernel)** — correctness, tamper, cross-impl Appendix B, dual-workspace determinism, and 10k recall perf budget pass on this host. Live MCP agent path and SSH two-machine determinism remain operational follow-ups (see `READINESS.md`).

## Status

Wave 0–5 crates build and pass focused gates. Golden foundation digests live under `proof/digests/`. **Determinism scope:** the §17.7 foundation gate uses fixture-mode deterministic nonces/keys (not production `OsRng`); true two-machine cross-host proof requires `MNEME_SECOND_HOST` and is not implied by `validation-lane.sh full`. Re-run `scripts/ci/validation-lane.sh full` for local correctness, and run `scripts/ci/determinism-two-machine.sh` on a real SSH peer before declaring the two-machine milestone closed.

## §20.4 handoff note

Current local handoff evidence is `out/readiness/final-ready-20260530/`: `validation-lane.sh full` exits 0, Appendix B is 7/7 PASS with committed byte payloads, `mneme-crossref` reproduces the vectors without `mneme-*` dependencies, and `bench-recall-optional.sh` records **191–227 µs** `recall_verified` @ 10k under the strict `<1 ms` gate. SSH cross-host two-machine proof still requires `MNEME_SECOND_HOST` (dual-workspace isolation passes locally).
