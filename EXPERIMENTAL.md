# MNEME Experimental Roadmap

Status: roadmap after separation. Non-core code has been moved under
`experimental/` or put behind explicit default-off features. Nothing has been
deleted.

Lean core stays focused on:

- Signed provenance chain.
- Fail-closed read-time verification with quarantine attribution.
- Crypto-shred erasure receipt plus proof-of-absence.

The public product API is the MCP four-call surface:

- `record-with-provenance`
- `recall-with-signed-chain`
- `erase-with-receipt-and-proof-of-absence`
- `verify`

CLI `audit`, `init`, and `determinism` are operator-only behind
`mneme-cli/operator_tools`. They are not part of the public product API.

## Deferred Areas

| Area | Current paths | Default flag | Why deferred |
|---|---|---:|---|
| Semantic/ANN retrieval | `experimental/semantic-retrieval/mneme-verify-semantic.rs`; `experimental/semantic-retrieval/mneme-index-{commit,distance,hnsw-backend,provenance,receipt,semantic,verify,wire,zkann}.rs`; semantic branches in `crates/mneme-store/src/{lib,recall,recall_at,scoped_recall}.rs` | off | Beyond exact record lookup; receipts prove procedure-faithfulness, not optimality. |
| Bench support helpers | `experimental/bench-support/mneme-store-bench.rs`; `tests/bench_recall.rs` invoked only by bench scripts | off | Perf harness support, not product API. |
| Cognition certificates | `experimental/cognition-cert/mneme-index-cognition-cert.rs`; `experimental/cognition-cert/cognition_cert_v1.rs`; `crates/mneme-cli/src/cert.rs`; `crates/mneme-store/src/certify.rs` | off | Broader context/output certification, not lean record API. |
| Context Gate | `experimental/context-gate/mneme-context`; `experimental/context-gate/mneme-gate`; `experimental/context-gate/mneme-core-enclave.rs`; `experimental/context-gate/mneme-index-context-gate.rs`; `crates/mneme-store/src/context_gate.rs`; `experimental/sync-crdt/mnemed/src/context_gate.rs` | off | Production TEE/attestation ops are external to this local slice. |
| Attestation export/parser | `crates/mneme-cli/src/attest.rs`; `experimental/attestation/mneme-attest` | off | Root statement export and non-production evidence parser. |
| External action accountability | `experimental/action-accountability/mneme-account-sign.rs`; `experimental/action-accountability/mneme-store-action.rs`; Phase III policy tests | off | Human-sanctioned external actions are roadmap; core `ForgetProof` erasure receipt is separate. |
| Redaction | `experimental/redaction/mneme-crypto-chameleon.rs`; `experimental/redaction/mneme-forget-redact.rs`; redaction hooks in `crates/mneme-smt/src/tree.rs` | off | Lean deletion is crypto-shred plus tombstone/proof-of-absence; chameleon redaction is accountable redaction, not deletion. |
| CRDT sync and daemon | `experimental/sync-crdt/mneme-crdt`; `experimental/sync-crdt/mneme-store-merge.rs`; `experimental/sync-crdt/mnemed`; CLI `merge`/`sync` | off | Multi-agent merge/anti-entropy is roadmap. |
| Federation/A2A | `experimental/federation/mneme-index-federation-cert.rs`; federation fuzz targets | off | Federation is not required for single-store compliance-of-record. |
| ZK/privacy retrieval | `experimental/zk-privacy/mneme-index-{commitment-binding,pedersen-schnorr-zk,semantic-zk}.rs`; ZK tests/vectors | off | 12-month proof path, not v1 exact record lookup. |
| Bi-temporal / point-in-time recall | `crates/mneme-store/src/recall_at.rs`; `recall_verified_at`; per-commit snapshot in `commit_root_inner`; `layout::{snapshot,load}_key_index_at_seq`; `tests/e2e/phase_i_gates.rs` bi-temporal tests | off | Sole consumer of per-commit full key-index snapshots (O(N) write, O(N×writes) disk). Not in the MCP four-call surface, so deferred behind `bitemporal_recall`. `AsOf` stays in frozen `mneme-core`. |
| Crossref reference implementation | `crates/mneme-crossref` | off runtime | Assurance/standardization infrastructure, not runtime TCB. |

## Feature Map

Experimental features:

- `experimental_semantic`
- `experimental_attest`
- `experimental_cognition_cert`
- `experimental_sync_crdt`
- `experimental_redaction`
- `experimental_action_accountability`
- `experimental_context_gate`
- `cognition_cert`
- `context_gate`
- `federation`
- `commitment_binding`
- `pedersen_schnorr_zk`
- `bitemporal_recall`
- `bench_support`
- `internal_test_support`
- `operator_tools`

Core support feature:

- `erasure_receipt`: enabled by `mneme-mcp` so
  `erase-with-receipt-and-proof-of-absence` returns a verified `ForgetProof`
  plus SMT absence proof.

Compatibility aliases:

- `phase_iii_bind` aliases `experimental_action_accountability`.
- `phase_iii_prove_forget` aliases `erasure_receipt`.
- `phase_iii_verify` remains the verifier gate needed by the erasure receipt
  path.

## Cut Candidates — resolved 2026-06-06

Reviewed and acted on. Two were genuinely dead and were **deleted**; two were
found to be **active** (a passing gate / a real test) and were **kept** — cutting
them would have reduced coverage, the opposite of the goal.

| Candidate | Decision |
|---|---|
| `experimental/research/mneme-index-piop-research.rs` | **DELETED** — default-off research seam, no prover/recall path, no CORE dep (feature `piop_research` + `mod`/`pub use`/guard-test removed). |
| `scripts/piop-flat-prototype` | **DELETED** — excluded prototype; the only caller (`phase-iv-cost-report.sh`) already skips when absent. |
| `scripts/ci/crypto-fault-injection-smoke.sh` | **KEPT** — it is an active, passing step of `validation-lane crypto` (2 `fault_injection` tests exist + run). Not dead; removing it would drop a real gate. |
| `experimental/cognition-cert/cognition_cert_v1.rs` | **KEPT** — a real `[[test]]` target (roundtrip tests, `required-features=["cognition_cert"]`), not a fixture-only helper. |

## Honesty Boundary

Authenticated memory is not truth. MNEME proves integrity, provenance,
authorization, and deletion of the memory-and-record layer. Model-side
parametric residue is statistical attestation only, never cryptographic
deletion.
