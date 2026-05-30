# Integration Agent Reality-Based Report

**Assessment date:** 2026-05-31  
**Auditor:** adversarial readiness (clean-room, guilty-until-proven)  
**Source of truth:** `MNEME_BLUEPRINT.md`  
**Evidence root:** `out/readiness/adversarial-audit-20260531/`  
**Prior `READINESS.md` READY claims:** ignored — reproduced independently

---

## Top-line verdict

# NOT READY

**Blocker count:** 14 (file:line cited below)  
**Quality rating:** B− (strong single-host kernel; incomplete 12-month scope)  
**Production readiness:** NEEDS WORK  
**Revision cycle required:** YES (expected 2–3 cycles for 12-month closure)

MNEME's **single-host cryptographic kernel** (verifier TCB, tamper suite, Appendix B cross-impl, kill/resume, killer-demo A-DB/A-INJ store paths) is substantively implemented and tested. Claims of **complete** or **12-month READY** are **disproven**: ZK/Plonky2 is stubbed, SSH two-machine determinism is unproven, live MCP agent path is harness-only, fuzz is 16-run smoke, `verify_store_head` skips object verification, and a public unverified `Store::recall()` bypass surface exists for direct callers.

---

## Reality check validation

| Step | Command / script | Log | Exit |
|---|---|---|---|
| fmt | `cargo fmt --check` | `01-fmt-check.log` | 0 |
| clippy | `cargo clippy --workspace --all-targets -- -D warnings` | `02-clippy.log` | 0 |
| build | `cargo build --workspace` | `03-build.log` | 0 |
| TCB lines + forbidden grep | `wc -l crates/mneme-verify/src/*.rs` + rg | `04-tcb-lines.log`, `04-tcb-forbidden.log` | 0 |
| Tamper suite | `cargo test -p mneme-verify --test tamper_*` + `cargo test --test tamper_suite` | `05-tamper-suite.log` | 0 |
| Forgery | `cargo test -p mneme-verify --test forgery_verifiers` | `06-forgery.log` | 0 |
| Kill/resume | `scripts/ci/kill-resume-smoke.sh` | `07-kill-resume.log` | 0 |
| Fuzz smoke | `scripts/ci/fuzz-smoke.sh` | `08-fuzz.log` | 0 |
| Determinism | `check-foundation-digests.sh` ×2 + `determinism-two-machine.sh` | `09-determinism.log` | 0 |
| CRDT | `cargo test -p mneme-crdt` | `10-crdt.log` | 0 |
| Appendix B | primary + crossref + `cross-implementation-vectors.sh` | `11-cross-impl.log` | 0 |
| Killer demo §21 | `scripts/demo/killer-demo.sh` + bypass harness | `12-killer-demo.log`, `14-killer-bypass.log` | 0 |
| Bench recall | `scripts/ci/bench-recall-optional.sh` | `13-bench-recall.log` | 0 |
| TCB guard | `tcb_guard` + `tcb_budget` | `15-tcb-guard.log` | 0 |
| Two-peer sync | `cargo test -p mnemed --test two_peer_sync` | `16-two-peer-sync.log` | 0 |

**Isolated target:** `export CARGO_TARGET_DIR=$PWD/out/readiness/adversarial-audit-20260531/target`

---

## TCB audit (`mneme-verify`)

| Metric | Value |
|---|---|
| Line count | **499 / 500** budget (`04-tcb-lines.log`) |
| `#![forbid(unsafe_code)]` | Present (`lib.rs:1`) |
| Forbidden in `src/` | **none** — no `unsafe`, `unwrap`, `expect`, `anyhow`, `todo!`, `unimplemented!`, `unreachable!`, `panic!` |
| CI guard | `tcb_guard_no_forbidden_patterns` PASS, `verify_tcb_stays_reviewable` PASS |

**Verdict:** TCB is **REAL** and within budget. This is the strongest evidence in the tree.

---

## Per-crate classification

| Crate | Status | Non-REAL evidence (file:line) |
|---|---|---|
| `mneme-core` | **REAL** (minor PARTIAL) | `hlc.rs:10` `expect("getrandom")` on `NodeId::random()`; `object.rs:244-249` `expect("checked")` on encode branches |
| `mneme-crypto` | **REAL** | — |
| `mneme-smt` | **PARTIAL** | `tree.rs:117,177,346-352` `expect` on cache/merge production paths |
| `mneme-dag` | **PARTIAL** | `lib.rs:46` `expect("checkpoint sequence fits in u64")` production |
| `mneme-root` | **REAL** | — |
| `mneme-cap` | **REAL** | — |
| `mneme-index` | **PARTIAL / STUBBED ZK** | `semantic.rs:93-94` `expect` on merkle path; `commitment_binding.rs:1-58` BLAKE3 binding only — **not Plonky2/SNARK** (blueprint §19 12-month) |
| `mneme-verify` | **REAL** | — |
| `mneme-forget` | **REAL** | — |
| `mneme-crdt` | **REAL** | — |
| `mneme-store` | **PARTIAL** | `recall.rs:14-73` pub unverified `recall()`; `lib.rs:442` `expect("genesis root")` |
| `mneme-mcp` | **PARTIAL** | Harness-only tests; no live Claude/MCP CI path (`README.md:51`) |
| `mneme-cli` | **REAL** | — |
| `mnemed` | **PARTIAL** | `main.rs:20-21,32` `expect` startup; `sync.rs:88,95,103` `expect` on lock/encode |
| `mneme-crossref` | **REAL** | Independent reference; Appendix B byte-exact PASS |

---

## Anti-fake blockers (file:line)

Each item is a **BLOCKER** against "complete" / production READY.

| # | Finding | file:line |
|---|---|---|
| B1 | **`verify_store_head` accepts signed root only** — no object re-hash, provenance, or index consistency; hardcoded `object_count: 0` | `crates/mneme-verify/src/store.rs:20-25` |
| B2 | **Public unverified recall bypass surface** — `Store::recall()` returns untrusted `Recall` without `verify_recall`; any caller skipping `recall_verified` violates INV-5 | `crates/mneme-store/src/recall.rs:14-73` |
| B3 | **ZK privacy backend STUBBED** — tagged BLAKE3 envelope only; blueprint §19 12-month requires Plonky2/V3DB-style opt-in ZK | `crates/mneme-index/src/commitment_binding.rs:1-58`, `Cargo.toml` feature `zk = ["commitment_binding"]` |
| B4 | **Two-machine determinism unproven** — `MNEME_SECOND_HOST` unset → dual-workspace isolation on same host, **not SSH cross-host** | `scripts/ci/determinism-two-machine.sh` (logged in `09-determinism.log`) |
| B5 | **Live MCP semantic agent path not CI-gated** — JSON-RPC harness only; no live agent recall proof | `README.md:51`, `crates/mneme-mcp/tests/mcp_tools.rs` (in-process dispatch only) |
| B6 | **Fuzz is smoke theater** — `-runs=16` per target; not meaningful sustained fuzz | `scripts/ci/fuzz-smoke.sh` → `08-fuzz.log` |
| B7 | **Killer demo incomplete vs §21 spec** — no Agent-A vs Agent-B comparison; store e2e subset only | `scripts/demo/killer-demo.sh:28-36` |
| B8 | **A-INJ structural bypass (by design, still blocks "complete")** — quarantine poison **readable** at `min_tier=Quarantine` | `crates/mneme-mcp/tests/handler_harness.rs:49-53` |
| B9 | **Production `expect` outside TCB** — daemon startup panics | `crates/mnemed/src/main.rs:20-21,32` |
| B10 | **Production `expect` on sync wire** | `crates/mnemed/src/sync.rs:88,95,103` |
| B11 | **Production `expect` on SMT cache** | `crates/mneme-smt/src/tree.rs:117,177,346-352` |
| B12 | **Production `expect` on semantic merkle path** | `crates/mneme-index/src/semantic.rs:93-94` |
| B13 | **Production `expect` on genesis root** | `crates/mneme-store/src/lib.rs:442` |
| B14 | **Blueprint §19 internal status stale** — blueprint body still cites 556–948 ms recall @ 10k; measured **221.667 µs** this audit (`13-bench-recall.log`) — doc drift within spec artifact | `MNEME_BLUEPRINT.md:757` vs `tests/bench_recall.rs:51-60` |

**No production `src/` hits for:** `todo!()`, `unimplemented!()`, `unreachable!()`, `assert!(true)`, `anyhow::` (repo-wide `src/` grep).

---

## Tamper suite (≥150 executed)

**Total executed:** **960** (not inventory claims)

| Suite | Executed | Log |
|---|---|---|
| `mneme-verify` `tamper_suite` | 60 | `05-tamper-suite.log` |
| `tamper_cap` | 28 | `05-tamper-suite.log` |
| `tamper_semantic` | 32 | `05-tamper-suite.log` |
| `tamper_tombstone` | 10 | `05-tamper-suite.log` |
| workspace `tamper_suite` generative | **830** | `05-tamper-suite.log` |

### Verify tamper pass list (60)

`tamper_inventory_matches_executed_verify_tests`, `tamper_object_byte_0`, `tamper_object_byte_1`, `tamper_object_byte_2`, `tamper_object_byte_3`, `tamper_object_byte_4`, `tamper_object_byte_mid`, `tamper_object_byte_last`, `tamper_object_truncated`, `tamper_object_garbage_appended`, `tamper_below_tier_policy`, `tamper_checkpoint_prev_root_zeroed`, `tamper_checkpoint_sequence_zero`, `tamper_forgotten_tombstone`, `tamper_membership_proof_each_element_checked`, `tamper_path_depth_0`, `tamper_path_depth_1`, `tamper_path_depth_2`, `tamper_path_depth_4`, `tamper_path_depth_8`, `tamper_path_depth_12`, `tamper_path_depth_16`, `tamper_path_depth_24`, `tamper_path_depth_32`, `tamper_path_depth_64`, `tamper_path_depth_96`, `tamper_path_depth_100`, `tamper_path_depth_128`, `tamper_path_depth_200`, `tamper_path_depth_255`, `tamper_path_truncated`, `tamper_path_root_mismatch`, `tamper_provenance_missing_parent`, `tamper_receipt_leaf_index`, `tamper_receipt_key_index_root`, `tamper_receipt_logical_key`, `tamper_receipt_membership_tombstone_value`, `tamper_receipt_object_id`, `tamper_receipt_root_bound`, `tamper_receipt_root_bound_last`, `tamper_root_chain_break`, `tamper_root_dag_head_mismatch`, `tamper_root_hlc_max_byte`, `tamper_root_hlc_replay`, `tamper_root_key_index_mismatch`, `tamper_root_preimage_hash`, `tamper_root_semantic_commit_mismatch`, `tamper_root_sequence_regression`, `tamper_root_signature`, `tamper_root_version_unsupported`, `tamper_root_version_without_preimage_update`, `tamper_root_version_zero`, `tamper_stored_root_checkpoint_byte`, `tamper_tombstone_membership_proof_stale`, `tamper_tombstone_then_recall`, `tamper_unauthorized_writer`, `tamper_verify_root_bad_sig`, `tamper_verify_store_incomplete_marker`, `tamper_verify_store_multibyte_key_index_schema_drift`, `tamper_verify_store_multibyte_key_index_tombstone_schema_drift`

### Cap tamper pass list (28)

`cap_issuer_swap`, `cap_kinds_tamper`, `cap_namespace_tamper`, `cap_sig_byte_0` … `cap_sig_byte_15`, `cap_sig_byte_31`, `cap_sig_byte_63`, `cap_sig_truncated`, `cap_sig_garbage_appended`, `cap_permissions_widened`, `cap_expired_not_after`, `cap_attenuated_sig_chain_tamper`, `cap_subject_swap`, `cap_tier_max_inflated`

### Semantic tamper pass list (32)

`sem_candidate_embedding_commit`, `sem_candidate_distance`, `sem_candidate_object_id`, `sem_candidate_second_embedding`, `sem_candidate_second_object_id`, `sem_honesty_on_procedure_mismatch`, `sem_node_commit_0`, `sem_node_commit_0_byte_15`, `sem_node_commit_0_byte_31`, `sem_node_commit_1`, `sem_node_commit_2`, `sem_node_commit_2_byte_5`, `sem_node_commit_garbage`, `sem_path_extra_sibling`, `sem_path_node0_depth0`, `sem_path_node0_depth1`, `sem_path_node1_depth0`, `sem_path_node1_depth1`, `sem_path_truncated`, `sem_receipt_procedure_id`, `sem_receipt_procedure_id_byte_1`, `sem_receipt_procedure_id_byte_8`, `sem_receipt_procedure_id_byte_16`, `sem_receipt_procedure_id_byte_31`, `sem_receipt_query_commit`, `sem_receipt_result_id_0`, `sem_receipt_result_id_last`, `sem_receipt_root_bound`, `sem_receipt_semantic_commit`, `sem_root_semantic_mismatch`, `sem_valid_roundtrip`, `sem_wrong_procedure`

### Tombstone tamper pass list (10)

`tomb_conflicting_key_byte_0`, `tomb_conflicting_key_byte_31`, `tomb_conflicting_key_mismatch`, `tomb_conflicting_live_value`, `tomb_conflicting_tombstone_wrong_key_hash`, `tomb_conflicting_value_byte_flip`, `tomb_conflicting_value_not_tombstone`, `tomb_missing_conflicting_when_tombstone`, `tomb_path_depth_0`, `tomb_path_depth_255`

### Store generative (830)

`tamper_suite_generative_byte_mutations` — **830 cases passed** (`05-tamper-suite.log`)

---

## Forgery per verifier (hand-crafted)

All 8 tests PASS with **correct typed `MnemeError`** (`06-forgery.log`):

| Test | Expected variant | Result |
|---|---|---|
| `forgery_membership_proof_replays_valid_path_under_wrong_root` | `IndexPathInvalid` | PASS |
| `forgery_membership_proof_empty_path_with_claimed_depth` | `IndexPathInvalid` | PASS |
| `forgery_root_signed_by_untrusted_operator` | `RootSigInvalid` | PASS |
| `forgery_recall_swaps_object_id_while_reusing_membership_path` | `IndexPathInvalid` | PASS |
| `forgery_store_head_accepts_no_objects_but_rejects_bad_sig` | `RootSigInvalid` | PASS |
| `forgery_semantic_receipt_binds_to_alien_semantic_commit` | `ReceiptRootMismatch` | PASS |
| `forgery_semantic_recall_swaps_object_bytes_under_valid_receipt` | `ObjectTampered` | PASS |
| `forgery_verify_store_signed_head_mismatched_key_index_sidecar` | `RootInconsistent` | PASS |

**Note on B1:** `forgery_store_head_accepts_no_objects_but_rejects_bad_sig` **documents** that `verify_store_head` does not inspect objects — forgery of object bytes under a valid head signature would not be caught by `verify_store_head` alone.

---

## Kill/resume (§17.3)

`07-kill-resume.log` — **6 tests PASS:**

- `e2e_incomplete_transaction_fails_closed_on_open`
- `e2e_kill_resume_recovery_after_marker_removal`
- `e2e_kill_resume_merge_recovery_after_marker_removal`
- `e2e_kill_resume_remember_at_every_write_boundary`
- `e2e_kill_resume_forget_at_write_boundaries`
- `e2e_kill_resume_merge_at_write_boundaries`

---

## Fuzz (§17.4)

Targets run (`08-fuzz.log`), all **16 runs**, **0 crashes**:

| Target | Seed corpus runs | Exit |
|---|---|---|
| `dcbor_parse` | 1237 | 0 |
| `smt_parse` | 41 | 0 |
| `cap_parse` | 1544 | 0 |
| `receipt_parse` | 48 | 0 |
| `index_wire` | 38 | 0 |
| `sync_message_parse` | 1617 | 0 |

**Finding:** smoke-only; does not satisfy "meaningful runs" for production certification (B6).

---

## Determinism (§17.7)

### Same machine ×2

`check-foundation-digests.sh` run twice → both **PASS** (`pinned digests match report run_a`).

### Golden digests (pinned `proof/digests/foundation-gate.v1.json`)

| Field | Hex |
|---|---|
| `head_bytes_hex` | `a90101025820e974b1934370338f4d561b55ab342a53df861354b4f48cb41da1689b6730d54f03582079150dc4f251b743d90929601fcb151ffb7143cd07fc4b8ea12a7653b0a75ca8045820cb84a95c083ee6df82d254c80049162e89988f0ef8ff84581b04a17af6159099054e0400000000000000000000000101065820b59c4c5525ed34877cf19dc117e2abf553fbcfe7e26525ca47040be71cd13886075820c2b9dbfda40b466168599a18393b4b8e441b5deced15b1424f0ef303bef9837f0858409ce0ae1bf037c8199f0350bb888608c054ca5eccfe173ad524da132a4ad25189db93f69d1a5421bd013aa615eb2c972a9916aaaf8b245303cc279508a41ec1070905` |
| `root_preimage_hex` | `c2b9dbfda40b466168599a18393b4b8e441b5deced15b1424f0ef303bef9837f` |
| `receipt_digest_hex` | `aebbb7c86000ce2977f0832b4a4bcfcfea92279fb21324fe9a71b5a9fa743355` |
| `absent_proof_digest_hex` | `b479944e1b1c76a1628c4d8a6f3544fb690882124aeee3cf2ca2db91f5db1d88` |
| `semantic_digest_hex` | `cb84a95c083ee6df82d254c80049162e89988f0ef8ff84581b04a17af6159099` |

**Fixture crypto mode** (deterministic nonces/keys — not production `OsRng`).

### Second environment

`determinism-two-machine.sh` → **dual-workspace isolation** (same physical host, temp clone). Workspace-a vs workspace-b digests **byte-identical** to pinned values above.

**Real SSH second machine:** **N/A — not executed** (B4). `MNEME_SECOND_HOST` unset.

---

## CRDT (§17.5)

`10-crdt.log` — **9/9 PASS**, including:

- `merge_convergence_property_n_agents_conflicting_keys` (random orderings → identical root)
- `appendix_b_mst_convergence_vector_matches_fixture`

`16-two-peer-sync.log` — `two_peer_stores_anti_entropy_converges_keys` PASS (single-process two stores; not two machines).

---

## Cross-implementation Appendix B (§17.8)

`11-cross-impl.log` — **ALL PASS:**

- Primary: `appendix_b_dcbor_edge_cases_match_manifest`, `appendix_b_object_id_vectors_match_manifest`, SMT/roots/caps/receipts/crdt vectors
- `mneme-crossref`: 8/8 byte-exact tests PASS
- `cross-implementation-vectors.sh` exit 0

---

## Killer demo §21 + bypass attempts

### Transcript (`12-killer-demo.log`)

```
e2e_killer_demo_storage_tamper_rejected_at_read ... ok   → MnemeError::ObjectTampered
e2e_quarantine_entry_blocked_from_trusted_recall ... ok   → BelowTierPolicy / CapDenied
e2e_promote_requires_promote_capability ... ok           → PromoteDenied
```

### Bypass attempts (`14-killer-bypass.log`)

| Attempt | Result |
|---|---|
| A-DB: OOB object byte tamper → `recall_verified` @ Trusted | **BLOCKED** (`ObjectTampered`) |
| A-INJ: quarantine poison → `recall_verified` @ Trusted | **BLOCKED** (`BelowTierPolicy`) |
| A-INJ: same poison → `recall` @ Quarantine via MCP handler | **ALLOWED** (by design — §3 honesty) |
| Caller uses `Store::recall()` directly, skips `verify_recall` | **BYPASS POSSIBLE** (B2) — adoption APIs use `recall_verified` |
| `verify_store_head` on tampered objects with valid sig | **BYPASS POSSIBLE** (B1) — no object scan |
| HTTP/gRPC/MCP/Unix recall paths | Use `recall_verified_default` — no bypass found in those surfaces |

**§21 gap:** Demo does not run two-agent comparison (conventional vector-DB Agent-A vs MNEME Agent-B) as blueprint narrative describes.

---

## Honesty boundary (§3)

**PASS** in README, MCP tool strings, and verifier exports:

- `README.md:7-17` — authenticated ≠ true; procedure-faithfulness ≠ exact-NN
- `HONESTY_PROCEDURE`, `BINDING_HONESTY` — no SNARK/ZK overclaim in binding path
- `MnemeError::ZkProofInvalid` message: "not a SNARK verifier" (`error.rs:22-23`)

**Doc drift:** README §19 table marks several 12-month items PASS that this audit blocks (two-machine, ZK). Blueprint §19 footer still lists old recall latency figures (B14).

---

## Performance (§19 v0 `<1 ms` @ 10k)

`13-bench-recall.log`:

- Populate 10k entries: **105.17 s**
- `recall_verified` (release, warmed): **221.667 µs** — **PASS** strict `<1000 µs` gate
- Prior README reference 191–227 µs — consistent with this run

---

## WHAT'S LEFT (exhaustive)

### Stubs / unimplemented (blueprint scope)

1. **Plonky2 / ZK retrieval backend** — integrate prover behind feature flag; replace BLAKE3 binding-only path (`commitment_binding.rs`)
2. **Real SSH two-machine determinism** — configure `MNEME_SECOND_HOST`, reproduce golden digests on second host
3. **Live MCP agent CI** — end-to-end Claude recall with verifying receipt in CI
4. **Full §21 demo** — script Agent-A (unverified memory) vs Agent-B side-by-side with audit event output

### Unproven claims

- "Complete" / "12-month READY" — disproven (this report)
- Cross-host CRDT convergence — only single-host dual-workspace + in-process two-peer
- Sustained fuzz coverage — 16-run smoke only
- `verify_store_head` as boot gate — does not prove store integrity

### Assumptions documented but not production-validated

- Fixture-mode deterministic crypto in foundation gate (not `OsRng` production path)
- Operator key custody (out of scope)
- Trapdoor custody for chameleon redact (`TRAPDOOR_CUSTODY.md` exists; ops not audited)

### §22 kill-criteria watch

| Criterion | Status |
|---|---|
| Platform ships equivalent fail-closed memory | Not observed — N/A |
| Recall overhead unacceptable at scale | **Not triggered** — 221 µs @ 10k this host |
| ADS receipt too weak for buyers needing exact-NN | **Still applies** — honesty boundary; not a bug |

### Smallest changes to prove each gap closed

| Gap | Smallest proof |
|---|---|
| B1 `verify_store_head` | Remove or delegate to `verify_store`; add forgery test that bad object bytes + good head → `ObjectTampered` |
| B2 unverified `recall()` | Make `recall` `pub(crate)` or deprecate; grep CI guard that no external crate calls it without verify |
| B3 ZK | Land Plonky2 prover stub with one Appendix B vector; feature-gate in CI |
| B4 two-machine | One successful `MNEME_SECOND_HOST=... determinism-two-machine.sh` log with divergent workspace paths |
| B5 live MCP | One CI job invoking `mneme-mcp` stdio against fixture store with receipt assertion |
| B6 fuzz | `-runs=10000` nightly job with crash=0 artifact retention |
| B7 killer demo | Extend `killer-demo.sh` with scripted Agent-A failure narrative |
| B8 A-INJ Quarantine read | Document in demo transcript as **expected**; add policy lint if agents must not recall @ Quarantine for action prompts |
| B9–B13 expect/panic | Replace with typed `MnemeError` on daemon/SMT/semantic paths |
| B14 doc drift | Update blueprint §19 status footer to match measured bench |

---

## Deployment readiness assessment

**Status:** NEEDS WORK

**Required before production consideration:**

1. Close B4 (real second machine) for multi-agent milestone
2. Close B3 or explicitly defer ZK from "complete" claims
3. Close B1/B2 bypass surfaces or document enforced call graph in CI
4. Live MCP path CI (B5)
5. Extend fuzz beyond smoke (B6)

**Timeline estimate:** 4–8 weeks for 12-month milestone closure on a small team; 1–2 weeks for honest "90-day single-host kernel READY" label if scope is narrowed explicitly.

**Re-assessment required:** After B1–B6 addressed; evidence to `out/readiness/adversarial-audit-<date>/`.

---

*Integration Agent: RealityIntegration · Evidence: `out/readiness/adversarial-audit-20260531/`*
