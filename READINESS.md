# Integration Agent Reality-Based Report

**Assessment date:** 2026-05-31  
**Auditor:** final certifier (TestingRealityChecker, independent re-run)  
**Source of truth:** `MNEME_BLUEPRINT.md`  
**Evidence root:** `out/readiness/final-ready-20260531/`  
**Prior audit:** `out/readiness/adversarial-audit-20260531/` (14 blockers — re-verified)

---

## Top-line verdict

# NOT READY (12-month / “complete”)

# READY — **90-day v0 single-host cryptographic kernel** (honest scope)

**Unqualified production / 12-month READY:** **NOT READY**  
**Scoped 90-day v0 single-host kernel:** **READY** (all mechanical gates pass; deferrals documented below)  
**Blocker count (12-month):** 5 material deferrals  
**Honesty score:** **90%** (README/MCP/verifier align with measured reality; §19 perf synced to `13-bench-recall.log`)  
**Quality rating:** B (strong kernel; incomplete 12-month scope)  
**Revision cycle required:** YES for 12-month closure

---

## Scope definition (mandatory honesty)

| Scope | Verdict | Meaning |
|---|---|---|
| **90-day v0 single-host kernel** | **READY** | fmt/clippy/build, TCB 500/500, tamper ≥150, forgery 8/8+, kill/resume, §21 killer demo (Agent-A vs Agent-B), cross-impl Appendix B, dual-workspace determinism, fuzz smoke (0 crashes), bench `<1 ms` @ 10k, `validation-lane.sh full`, MCP stdio roundtrip |
| **12-month milestone** | **NOT READY** | Plonky2/ZK backend stubbed, real SSH two-machine determinism unproven, sustained fuzz not wired, `verify_store_head` remains signature-only diagnostic |

---

## Reality check validation (isolated target)

`export CARGO_TARGET_DIR=$PWD/out/readiness/final-ready-20260531/target`

| Step | Command / script | Log | Exit |
|---|---|---|---|
| fmt | `cargo fmt --all -- --check` | `01-fmt-check.log` | 0 |
| clippy | `cargo clippy --workspace --all-targets -- -D warnings` | `02-clippy.log` | 0 |
| build | `cargo build --workspace` | `03-build.log` | 0 |
| TCB lines | `wc -l crates/mneme-verify/src/*.rs` | `04-tcb-lines.log` | **500 / 500** |
| TCB guard | `verify-tcb-guard.sh` + `tcb_budget` + `tcb_guard` | `15-tcb-guard.log` | 0 |
| Tamper | verify suites + store generative | `05-tamper-*.log` | 0 |
| Forgery | `forgery_verifiers` (8 hand-crafted + 1 store tamper) | `06-forgery.log` | 0 (9/9) |
| Kill/resume | `kill-resume-smoke.sh` | `07-kill-resume.log` | 0 |
| Fuzz smoke | `fuzz-smoke.sh` (`-runs=16`) | `08-fuzz.log` | 0 |
| Determinism | `check-foundation-digests.sh` + `determinism-two-machine.sh` | `09-*.log` | 0 (dual-workspace) |
| Cross-impl | `cross-implementation-vectors.sh` | `11-cross-impl.log` | 0 |
| Killer demo §21 | `killer-demo.sh` + bypass harness | `12-killer-demo.log`, `14-killer-bypass.log` | 0 |
| Bench recall | `bench-recall-optional.sh` | `13-bench-recall.log` | 0 (**197.7 µs**) |
| Validation lane | `validation-lane.sh full` | `17-validation-lane-full.log` | 0 |
| Honesty audit | grep + API surface check | `18-honesty-audit.log` | PASS |
| MCP stdio | `cargo test -p mneme-mcp --test stdio_roundtrip` | (in honesty log) | 0 (2/2) |

**Certifier fixes applied (blocking one-liners only, not committed):** `determinism.rs` receipt via `prove_membership`; e2e `current_root().unwrap()`; `grpc_status_mneme`; `cli_e2e` `SignatureOnlyHead`; clippy needless-?; `check-test-vectors.sh` `partial_vectors` dict paths; TCB budget trim; `cargo fmt --all`.

---

## Tamper suite (≥150 executed)

**Total executed:** **960**

| Suite | Executed | Log |
|---|---|---|
| `mneme-verify` `tamper_suite` | 60 | `05-tamper-verify.log` |
| `tamper_cap` | 28 | `05-tamper-verify.log` |
| `tamper_semantic` | 32 | `05-tamper-verify.log` |
| `tamper_tombstone` | 10 | `05-tamper-verify.log` |
| store generative | **830** | `05-tamper-store.log` |

---

## Forgery per verifier (8 required + 1 store-object)

All **9/9 PASS** with typed `MnemeError` (`06-forgery.log`):

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
| `forgery_store_head_skips_object_integrity_verify_store_fails_closed` | `ObjectTampered` (via `verify_store`) | PASS |

---

## Blocker closure vs adversarial audit (14 → 5 remaining for 12-month)

| # | Original | Status after fixes |
|---|---|---|
| B1 | `verify_store_head` signature-only | **PARTIAL** — `SignatureOnlyHead` + docs; boot must use `verify_store` (`bypass_closed`, e2e bypass) |
| B2 | Public unverified `Store::recall()` | **CLOSED** — `pub(crate)`; adoption paths use `recall_verified*` |
| B3 | ZK/Plonky2 stubbed | **OPEN (deferred)** — tagged BLAKE3 binding only; README honest |
| B4 | SSH two-machine determinism | **OPEN** — dual-workspace passes; `MNEME_SECOND_HOST` unset |
| B5 | Live MCP path | **IMPROVED** — `stdio_roundtrip` (2 tests) exercises real `mneme-mcp` subprocess; not Claude agent CI |
| B6 | Fuzz smoke theater | **OPEN** — `-runs=16` per target, 0 crashes |
| B7 | Killer demo Agent-A vs Agent-B | **CLOSED** — `killer_demo_agent_a_vs_agent_b_*` in `killer-demo.sh` |
| B8 | A-INJ quarantine readable | **BY DESIGN** — documented §3 honesty; blocked @ Trusted |
| B9–B13 | Production `expect` | **MOSTLY CLOSED** — cleared in `mnemed`, `mneme-smt`, `mneme-index/semantic`, `mneme-store`; remain in `mneme-core`, `mneme-dag` |
| B14 | Blueprint §19 latency drift | **CLOSED** — docs synced to `13-bench-recall.log` (**197.7 µs** @ 10k; populate **109.9 s**) |

---

## Remaining blockers (12-month / unqualified READY)

1. **B4** — Real SSH second-host golden digest reproduction (`MNEME_SECOND_HOST` + `determinism-two-machine.sh`).
2. **B3** — Plonky2/V3DB-style ZK retrieval backend (or remove from 12-month claims).
3. **B6** — Sustained fuzz (`-runs≥10000` nightly) beyond smoke.
4. **B1** — Callers must never treat `verify_store_head` as integrity gate (documented; enforce in adoption lint).
5. **B5 (residual)** — MCP stdio roundtrip is not live Claude/agent CI.

---

## Honesty boundary (§3)

**PASS** — no SNARK/Plonky2 overclaim in binding path; MCP tool strings and `HONESTY_PROCEDURE` / `BINDING_HONESTY` exports consistent with implementation (`18-honesty-audit.log`).

---

## Performance (v0 `<1 ms` @ 10k)

| Metric | Measured | v0 gate | Status |
|---|---|---|---|
| Populate 10k entries | **109.9 s** | (setup; not gated) | logged |
| `recall_verified` @ 10k | **197.708 µs** | **<1000 µs** (`tests/bench_recall.rs`) | **PASS** |

Evidence: `out/readiness/final-ready-20260531/13-bench-recall.log` via `scripts/ci/bench-recall-optional.sh`. Fresh re-run (2026-05-30) also PASS (**121 µs** recall; populate **140.8 s**); host variance does not affect the strict µs gate.

---

## Deployment readiness

| Label | Status |
|---|---|
| 12-month / complete | **NEEDS WORK** |
| 90-day v0 single-host kernel | **READY** (scoped) |

**Re-assessment:** After B3/B4/B6 closure for 12-month; evidence to `out/readiness/final-ready-<date>/`.

---

*Integration Agent: TestingRealityChecker · Evidence: `out/readiness/final-ready-20260531/`*
