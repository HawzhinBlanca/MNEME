# MNEME Lean Core Classification

Status: classification after local separation work. No CUT item has been
deleted. The DEFER separation is a **relocation, not a deletion**: the 62 files
removed from `crates/` are all staged as git renames to `experimental/` (59 at
≥90% similarity; 3 edited-moves — two `Cargo.toml` path-dep fixups and
`piop_research.rs` with an added honesty header — at 78–87%). Zero orphan
deletes. The lean product is one audit-grade compliance-of-record layer with
three public guarantees:

1. Signed provenance chain: prove what the AI knew and why.
2. Fail-closed read-time verification: prove integrity and quarantine attribution.
3. Crypto-shred erasure receipt plus proof-of-absence: prove deletion of the
   memory-and-record layer and never claim cryptographic deletion of model
   parametric residue.

Bucket meanings:

- CORE: required for the three guarantees, their TCB, or their core gates.
- DEFER: real/working roadmap code not needed for lean v1.
- CUT: dead, scaffold-only, demo-only, or not a real exercised core gate. Do not
  delete before review.
- UNCERTAIN: still needs operator decision before movement or deletion.

Build-scope precision: "DEFER" is an organizational state, not a build
exclusion. The relocated standalone crates (`mnemed`, `mneme-crdt`,
`mneme-attest`, `mneme-context`, `mneme-gate`) remain `[workspace] members`
under `experimental/...` and still compile and test under
`cargo {build,test} --workspace`. Only `default-members =
["crates/mneme-store"]` narrows a bare `cargo build`, and only the
feature-gated `#[path = "../../../experimental/..."]` includes inside core
crates are truly default-off. A `--workspace` green therefore proves the whole
tree builds, **not** that the lean core builds in isolation — that isolation is
proven separately by building/testing the core crates without the experimental
members and with default features.

Source anchors:

- `MNEME_BLUEPRINT.md:31-35`: verified recall, attributable writes, provable
  forget, deterministic merge, fail-closed runtime.
- `MNEME_BLUEPRINT.md:39-44`: no new vector search, LLM runtime verification,
  blockchain, scratch ZK, or exact-NN claims.
- `MNEME_BLUEPRINT.md:91-99`: honesty boundary.
- `MNEME_BLUEPRINT.md:411`: `mneme-verify` is the verifier TCB.
- `MNEME_BLUEPRINT.md:622`: final four public operations.

## Workspace Crates

| Path | Bucket | Evidence | Status |
|---|---:|---|---|
| `crates/mneme-core` | CORE | Public modules are declared at `crates/mneme-core/src/lib.rs:1-41`; `ForgetProof` is now split into `crates/mneme-core/src/erasure_receipt.rs:1-5`; `ActionReceipt` remains separate at `crates/mneme-core/src/accountability.rs:1-17`. | Core wire crate, with some deferred wire types still exported for compatibility. |
| `crates/mneme-crypto` | CORE | Core crypto modules are exported at `crates/mneme-crypto/src/lib.rs:1-24`; chameleon redaction is included only by `experimental_redaction` at `crates/mneme-crypto/src/lib.rs:4-16`. | Keep AEAD/sign/vault/payload; redaction moved/gated. |
| `crates/mneme-smt` | CORE | SMT proof/tree/wire exports are at `crates/mneme-smt/src/lib.rs:1-17`; redaction hooks are cfg-gated in `crates/mneme-smt/src/tree.rs:3-21`. | Keep membership/non-membership proof core; redaction stays experimental. |
| `crates/mneme-dag` | CORE | DAG head root and checkpoint modules are declared at `crates/mneme-dag/src/lib.rs:1-18`. | Required for provenance chain. |
| `crates/mneme-root` | CORE | Signed root and stored checkpoint types are at `crates/mneme-root/src/lib.rs:1-28`; atomic writes at `crates/mneme-root/src/atomic.rs:1-20`. | Required for signed roots, replay floor, fsync durability. |
| `crates/mneme-cap` | CORE | Capability permissions and trust tiers are declared at `crates/mneme-cap/src/lib.rs:1-23`; wire codec at `crates/mneme-cap/src/wire.rs:1-18`. | Required for authorization/quarantine attribution. |
| `crates/mneme-index` | CORE default / DEFER features | Default key-only export is documented in `crates/mneme-index/src/lib.rs:1-5`; experimental modules are re-included from `experimental/` at `crates/mneme-index/src/lib.rs:10-65`; key exports are at `crates/mneme-index/src/lib.rs:67-77`. | Default core is exact record lookup. Semantic/ANN/ZK/cert/context/federation are deferred. |
| `crates/mneme-forget` | CORE default / DEFER redaction | Shred/absence exports are at `crates/mneme-forget/src/lib.rs:1-15`; redaction module is included only by `experimental_redaction` at `crates/mneme-forget/src/lib.rs:7-13`. | Core deletion is shred + tombstone + absence proof. |
| `crates/mneme-account` | CORE ForgetProof / DEFER ActionReceipt | Forget proof mint/verify paths are at `crates/mneme-account/src/forget.rs:1-78` and `crates/mneme-account/src/verify.rs:35-75`; ActionReceipt signing is moved to `experimental/action-accountability/mneme-account-sign.rs` and included at `crates/mneme-account/src/lib.rs:16-25`. | Keep erasure receipt support; external action accountability is roadmap. |
| `crates/mneme-verify` | CORE | Default TCB modules are `proof`, `recall`, `root`, `store` at `crates/mneme-verify/src/lib.rs:4-21`; semantic verifier is re-included only with `experimental_semantic` at `crates/mneme-verify/src/lib.rs:7-17`. | TCB shrank to 481 production lines. |
| `crates/mneme-store` | CORE default / DEFER features | Store feature gates are at `crates/mneme-store/Cargo.toml:32-57`; test-only public hooks require `internal_test_support` at `crates/mneme-store/Cargo.toml:64-86`; action/bench/merge modules are path-gated at `crates/mneme-store/src/lib.rs:8-29`. | Default store is the kernel; helper surfaces are hidden behind support features. |
| `crates/mneme-mcp` | CORE | MCP public tool list is exactly four calls at `crates/mneme-mcp/src/protocol.rs:133-183`; erase returns `ForgetProof` + absence proof in `crates/mneme-mcp/src/handlers.rs:120-148`. | Lean public product API. |
| `crates/mneme-cli` | OPERATOR / CORE-adjacent | Product commands are `verify`, `recall`, `remember`, `forget` at `crates/mneme-cli/src/main.rs:44-95`; `audit`, `init`, `determinism` require `operator_tools` at `crates/mneme-cli/src/main.rs:54-56` and `crates/mneme-cli/src/main.rs:132-140`; roadmap commands are cfg-gated at `crates/mneme-cli/src/main.rs:96-131`. | Decision made: CLI audit/init/determinism are operator-only, not public product API. |
| `crates/mneme-crossref` | DEFER | Independent reference implementation declared at `crates/mneme-crossref/src/lib.rs:1-4`. | Assurance/standardization, not runtime TCB. |
| `experimental/context-gate/mneme-context` | DEFER | Context assembly crate declares Phase II purpose at `experimental/context-gate/mneme-context/src/lib.rs:1-8`. | Deferred Context Gate. |
| `experimental/context-gate/mneme-gate` | DEFER | Gate status/scaffolding is declared at `experimental/context-gate/mneme-gate/src/lib.rs:1-19`. | Deferred until real TEE/attestation ops. |
| `experimental/attestation/mneme-attest` | DEFER | Non-production attestor warning at `experimental/attestation/mneme-attest/src/lib.rs:1-6`. | Parser/fuzz work only. |
| `experimental/sync-crdt/mneme-crdt` | DEFER | CRDT modules declared at `experimental/sync-crdt/mneme-crdt/src/lib.rs:1-14`. | Roadmap multi-agent merge/anti-entropy. |
| `experimental/sync-crdt/mnemed` | DEFER | Daemon modules declared at `experimental/sync-crdt/mnemed/src/lib.rs:1-11`. | Not part of four-call public API. |

## Module Classification

### `mneme-core`

| Module | Bucket | Evidence |
|---|---:|---|
| `accountability.rs` | DEFER | ActionReceipt-only wire at `crates/mneme-core/src/accountability.rs:1-17`; signing is outside core. |
| `erasure_receipt.rs` | CORE | Core `ForgetProof` wire at `crates/mneme-core/src/erasure_receipt.rs:1-5` and struct at `crates/mneme-core/src/erasure_receipt.rs:23-40`. |
| `context.rs` | DEFER | Phase II context wire at `crates/mneme-core/src/context.rs:1-4`. |
| `dcbor.rs` | CORE | Deterministic CBOR profile at `crates/mneme-core/src/dcbor.rs:1-8`. |
| `domain.rs` | CORE | Domain tags at `crates/mneme-core/src/domain.rs:1-5`; ActionReceipt tag remains for compatibility at `crates/mneme-core/src/domain.rs:18-36`. |
| `embedding.rs` | DEFER | Semantic embedding support at `crates/mneme-core/src/embedding.rs:1-8`. |
| `error.rs` | CORE | Closed trusted-path error enum at `crates/mneme-core/src/error.rs:1-7`. |
| `hex.rs` | CORE | Strict fixed-width hex parsing at `crates/mneme-core/src/hex.rs:1-8`. |
| `hlc.rs` | CORE | HLC wire/time support at `crates/mneme-core/src/hlc.rs:1-6`. |
| `interface.rs` | UNCERTAIN | Broad frozen interface seam at `crates/mneme-core/src/interface.rs:1-8`. Needs public-contract review. |
| `object.rs` | CORE | Content-addressed object record at `crates/mneme-core/src/object.rs:1-10`. |
| `output.rs` | DEFER | Output binding wire at `crates/mneme-core/src/output.rs:1-8`. |
| `types.rs` | CORE | Compatibility aliases at `crates/mneme-core/src/types.rs:1-3`. |
| `experimental/context-gate/mneme-core-enclave.rs` | DEFER | Enclave placeholder wire is feature-gated from `crates/mneme-core/src/lib.rs:8-10`. |

### `mneme-crypto`

| Module | Bucket | Evidence |
|---|---:|---|
| `aead.rs` | CORE | XChaCha20-Poly1305 seal/open at `crates/mneme-crypto/src/aead.rs:1-13`. |
| `deterministic.rs` | CORE | Gate-only deterministic randomness at `crates/mneme-crypto/src/deterministic.rs:1-5`. |
| `envelope_vault.rs` | CORE | Envelope vault seam at `crates/mneme-crypto/src/envelope_vault.rs:1-6`. |
| `keys.rs` | CORE | Ed25519 keys at `crates/mneme-crypto/src/keys.rs:1-10`. |
| `payload.rs` | CORE | Payload encryption/shred path at `crates/mneme-crypto/src/payload.rs:1-12`. |
| `sign.rs` | CORE | Ed25519 sign/verify at `crates/mneme-crypto/src/sign.rs:1-13`. |
| `types.rs` | CORE | Crypto constants/types at `crates/mneme-crypto/src/types.rs:1-10`. |
| `vault.rs` | CORE | Per-object key vault at `crates/mneme-crypto/src/vault.rs:1-14`. |
| `experimental/redaction/mneme-crypto-chameleon.rs` | DEFER | Included only by `experimental_redaction` at `crates/mneme-crypto/src/lib.rs:4-16`. |

### `mneme-smt`, `mneme-dag`, `mneme-root`, `mneme-cap`

| Module | Bucket | Evidence |
|---|---:|---|
| `mneme-smt/src/defaults.rs` | CORE | Re-exported at `crates/mneme-smt/src/lib.rs:10`. |
| `mneme-smt/src/proof.rs` | CORE | Re-exported at `crates/mneme-smt/src/lib.rs:11`. |
| `mneme-smt/src/tree.rs` | CORE default / DEFER redaction | Core tree at `crates/mneme-smt/src/tree.rs:40-57`; redaction APIs gated at `crates/mneme-smt/src/tree.rs:144-183`. |
| `mneme-smt/src/wire.rs` | CORE | Strict proof wire parsing exported at `crates/mneme-smt/src/lib.rs:15-17`. |
| `mneme-dag/src/lib.rs` | CORE | Provenance DAG root at `crates/mneme-dag/src/lib.rs:1-18`. |
| `mneme-dag/src/checkpoint.rs` | CORE | Checkpoint support declared by `crates/mneme-dag/src/lib.rs:6-8`. |
| `mneme-root/src/lib.rs` | CORE | Signed root types at `crates/mneme-root/src/lib.rs:1-28`. |
| `mneme-root/src/atomic.rs` | CORE | fsync + atomic rename at `crates/mneme-root/src/atomic.rs:1-20`. |
| `mneme-root/src/checkpoint.rs` | CORE | Append-only log/replay floor at `crates/mneme-root/src/checkpoint.rs:1-56`. |
| `mneme-root/src/wire.rs` | CORE | Root wire used by `StoredRoot` at `crates/mneme-root/src/lib.rs:75-80`. |
| `mneme-cap/src/lib.rs` | CORE | Capability model at `crates/mneme-cap/src/lib.rs:1-23`. |
| `mneme-cap/src/wire.rs` | CORE | Capability canonical wire at `crates/mneme-cap/src/wire.rs:1-18`. |

### `mneme-index`

| Module | Bucket | Evidence |
|---|---:|---|
| `error.rs` | CORE | Default export at `crates/mneme-index/src/lib.rs:69`. |
| `key_index.rs` | CORE | Default export at `crates/mneme-index/src/lib.rs:71`. |
| `key_index_load.rs` | CORE | Default export at `crates/mneme-index/src/lib.rs:72`. |
| `procedure.rs` | CORE default / DEFER semantic | Key procedure export at `crates/mneme-index/src/lib.rs:75`; semantic branches cfg-gated in `crates/mneme-index/src/procedure.rs:3-36`. |
| `experimental/semantic-retrieval/mneme-index-*.rs` | DEFER | Re-included only by `experimental_semantic` at `crates/mneme-index/src/lib.rs:13-48`. |
| `experimental/cognition-cert/mneme-index-cognition-cert.rs` | DEFER | Re-included only by `cognition_cert` at `crates/mneme-index/src/lib.rs:10-12`. |
| `experimental/context-gate/mneme-index-context-gate.rs` | DEFER | Re-included only by `context_gate` at `crates/mneme-index/src/lib.rs:16-18`. |
| `experimental/federation/mneme-index-federation-cert.rs` | DEFER | Re-included only by `federation` at `crates/mneme-index/src/lib.rs:23-25`. |
| `experimental/zk-privacy/mneme-index-*.rs` | DEFER | Re-included by ZK features at `crates/mneme-index/src/lib.rs:51-61`. |
| `experimental/research/mneme-index-piop-research.rs` | CUT candidate | Research-only seam re-included only by `piop_research` at `crates/mneme-index/src/lib.rs:63-65`; current code reports no prover. |

### `mneme-forget`, `mneme-account`

| Module | Bucket | Evidence |
|---|---:|---|
| `mneme-forget/src/absent.rs` | CORE | Absence proof support at `crates/mneme-forget/src/absent.rs:1-12`. |
| `mneme-forget/src/shred.rs` | CORE | Crypto-shred/tombstone support at `crates/mneme-forget/src/shred.rs:1-13`. |
| `experimental/redaction/mneme-forget-redact.rs` | DEFER | Included only by `experimental_redaction` at `crates/mneme-forget/src/lib.rs:7-13`. |
| `mneme-account/src/forget.rs` | CORE | `ForgetProofWitness` and minting at `crates/mneme-account/src/forget.rs:1-78`. |
| `mneme-account/src/verify.rs` | CORE ForgetProof / DEFER ActionReceipt | `verify_forget_proof` at `crates/mneme-account/src/verify.rs:35-75`; `verify_action_receipt` at `crates/mneme-account/src/verify.rs:11-33`. |
| `experimental/action-accountability/mneme-account-sign.rs` | DEFER | Re-included only by `phase_iii_bind_action` at `crates/mneme-account/src/lib.rs:16-25`. |

### `mneme-verify`

| Module | Bucket | Evidence |
|---|---:|---|
| `lib.rs` | CORE | `#![forbid(unsafe_code)]` and TCB line budget at `crates/mneme-verify/src/lib.rs:1-21`. |
| `proof.rs` | CORE | Membership proof verifier exported at `crates/mneme-verify/src/lib.rs:12`. |
| `recall.rs` | CORE | Fail-closed recall verifier exported at `crates/mneme-verify/src/lib.rs:13`. |
| `root.rs` | CORE | Root verifier exported at `crates/mneme-verify/src/lib.rs:14`. |
| `store.rs` | CORE | Store verifier exported at `crates/mneme-verify/src/lib.rs:18-19`. |
| `experimental/semantic-retrieval/mneme-verify-semantic.rs` | DEFER | Re-included only by `experimental_semantic` at `crates/mneme-verify/src/lib.rs:7-17`. |

### `mneme-store`

| Module | Bucket | Evidence |
|---|---:|---|
| `atomic.rs` | CORE | Store durability module declared at `crates/mneme-store/src/lib.rs:15`. |
| `forget.rs` | CORE default / DEFER redaction/action | Erasure receipt feature gates at `crates/mneme-store/src/forget.rs:15-19`; action and redaction cfgs at `crates/mneme-store/src/forget.rs:4-14`. |
| `layout.rs` | CORE | Tombstone layout exported at `crates/mneme-store/src/lib.rs:98`. |
| `pause.rs` | CORE test support | Pause hooks exported only with `internal_test_support` at `crates/mneme-store/src/lib.rs:102-107`. |
| `recall.rs` | CORE default / DEFER semantic | Key recall default at `crates/mneme-store/src/recall.rs:1-56`; semantic branch cfg-gated at `crates/mneme-store/src/recall.rs:105`. |
| `recall_at.rs` | DEFER | Bi-temporal `recall_verified_at`; whole module gated by `bitemporal_recall` at `crates/mneme-store/src/lib.rs:31-32`. Sole consumer of per-commit key-index snapshots (O(N) write-amplification); off in lean default. |
| `scoped_recall.rs` | CORE default / DEFER semantic | Semantic imports cfg-gated at `crates/mneme-store/src/scoped_recall.rs:6-16`. |
| `certify.rs` | DEFER | Module compiled only by `experimental_cognition_cert` at `crates/mneme-store/src/lib.rs:21-22`. |
| `context_gate.rs` | DEFER | Module compiled only by `context_gate` at `crates/mneme-store/src/lib.rs:6-7` and `crates/mneme-store/src/lib.rs:23-24`. |
| `experimental/action-accountability/mneme-store-action.rs` | DEFER | Re-included only by `experimental_action_accountability` at `crates/mneme-store/src/lib.rs:8-14`. |
| `experimental/bench-support/mneme-store-bench.rs` | DEFER | Re-included only by `bench_support` at `crates/mneme-store/src/lib.rs:16-20`. |
| `experimental/sync-crdt/mneme-store-merge.rs` | DEFER | Re-included only by `experimental_sync_crdt` at `crates/mneme-store/src/lib.rs:27-29`. |

### Public/API Layers

| Module | Bucket | Evidence |
|---|---:|---|
| `mneme-mcp/src/protocol.rs` | CORE | Four-tool list at `crates/mneme-mcp/src/protocol.rs:133-183`; dispatch at `crates/mneme-mcp/src/protocol.rs:185-246`. |
| `mneme-mcp/src/handlers.rs` | CORE | Record/recall/erase/verify handlers at `crates/mneme-mcp/src/handlers.rs:54-153`; erase evidence at `crates/mneme-mcp/src/handlers.rs:275-315`. |
| `mneme-mcp/src/honesty.rs` | CORE | Public honesty text exported from `crates/mneme-mcp/src/lib.rs:17-21`. |
| `mneme-mcp/src/server.rs` | CORE | MCP transport exported at `crates/mneme-mcp/src/lib.rs:9-13`. |
| `mneme-mcp/src/store_open.rs` | CORE | Runtime store open exported at `crates/mneme-mcp/src/lib.rs:21`. |
| `mneme-cli/src/main.rs` | OPERATOR / CORE-adjacent | Product calls at `crates/mneme-cli/src/main.rs:44-95`; operator-only audit/init/determinism at `crates/mneme-cli/src/main.rs:54-56` and `crates/mneme-cli/src/main.rs:132-140`. |
| `mneme-cli/src/determinism.rs` | OPERATOR | Included only by `operator_tools` at `crates/mneme-cli/src/main.rs:7-8`. |
| `mneme-cli/src/attest.rs` | DEFER | Included only by `experimental_attest` at `crates/mneme-cli/src/main.rs:3-4`. |
| `mneme-cli/src/cert.rs` | DEFER | Included only by `experimental_cognition_cert` at `crates/mneme-cli/src/main.rs:5-6`. |
| `experimental/sync-crdt/mnemed/src/*.rs` | DEFER | Daemon modules exported at `experimental/sync-crdt/mnemed/src/lib.rs:1-11`. |

### Tests, Gates, Scripts

| Surface | Bucket | Evidence |
|---|---:|---|
| `scripts/ci/validation-lane.sh` | CORE | Main validation ladder at `scripts/ci/validation-lane.sh:1-6`. |
| `scripts/ci/bench-recall-optional.sh` | CORE perf gate | Release recall/erasure benchmark command at `scripts/ci/bench-recall-optional.sh:1-20`. |
| `scripts/ci/determinism-*.sh` | OPERATOR CORE gate | Determinism commands now invoke CLI with `operator_tools`; see `scripts/ci/determinism-two-machine.sh:1-20`. |
| `scripts/ci/kill-resume-smoke.sh` | CORE | Kill/resume durability smoke at `scripts/ci/kill-resume-smoke.sh:1-20`. |
| `tests/tamper_suite.rs` | CORE | Store tamper suite at `tests/tamper_suite.rs:1-20`; requires `internal_test_support` in `crates/mneme-store/Cargo.toml:70-74`. |
| `tests/chaos/mod.rs` | CORE | Disk-full/corruption/random-kill chaos suite at `tests/chaos/mod.rs:1-20`; requires `internal_test_support` in `crates/mneme-store/Cargo.toml:82-86`. |
| `tests/bench_recall.rs` | CORE perf gate | Ignored by default and explicitly invoked by bench scripts; test target requires `bench_support,internal_test_support` at `crates/mneme-store/Cargo.toml:76-80`. |
| `fuzz/` | CORE + DEFER mix | Fuzz crate explicitly enables experimental index features for experimental fuzz lanes at `fuzz/Cargo.toml:14`. |
| `scripts/ci/crypto-fault-injection-smoke.sh` | CUT candidate | Scaffold/fault-injection smoke is not a real core acceptance gate. |
| `scripts/piop-flat-prototype` | CUT candidate | Excluded research prototype; not workspace core. |

## Explicit CUT Candidates Pending Review

No CUT candidate is deleted in this branch.

| Candidate | Bucket | Why |
|---|---:|---|
| `experimental/research/mneme-index-piop-research.rs` | CUT candidate | Research seam with no prover or recall path. |
| `scripts/piop-flat-prototype` | CUT candidate | Excluded prototype, not a core gate. |
| `scripts/ci/crypto-fault-injection-smoke.sh` scaffold | CUT candidate | Not a real typed forgery/fault-injection gate. |
| Fixture dump helpers under `experimental/cognition-cert` | CUT candidate | Generator helpers, not acceptance tests. |

## Remaining Uncertain Items

1. Whether `mneme-crossref` should stay DEFER standardization or be promoted to
   CORE assurance infrastructure.
2. Whether "deletion propagated" for v1 means signed tombstone propagation
   within one store lineage only, or a multi-peer CRDT propagation guarantee.
   The user classified CRDT sync as DEFER, so this branch keeps multi-peer
   propagation out of core.
3. Whether broad compatibility exports in `mneme-core::interface` should be
   hidden before a public Rust SDK is declared.
4. Whether the `mneme-account` crate should be renamed/split so core erasure
   receipt support no longer shares a crate with deferred external
   `ActionReceipt` accountability.

## Review Rule

No CUT deletion until this classification is reviewed. Every DEFER item is
separated or feature-gated; any future cut needs a green core gate and proof
that no CORE test depended on it.
