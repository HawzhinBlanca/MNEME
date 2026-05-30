# MNEME — Adversarial Readiness Report (Reality-Checked)

**Assessment date:** 2026-05-30
**Assessor:** TestingRealityChecker (integration / final reality check)
**Authority:** `MNEME_BLUEPRINT.md` — this file is team-owned and defaults to **NOT READY** until every load-bearing claim reproduces on the committed tree.
**Evidence root:** `out/readiness/continue-hard-20260530T122918Z/`
**Prior independent audit:** `AUDIT_INDEPENDENT_VERDICT.md` + `out/audit/independent-20260530T111657Z/` (7 findings: 1 High, 4 Medium, 2 Low).

---

## Top-line verdict

# Unqualified / 12-month / multi-machine: **NOT READY**
# 90-day v0 **single-host** cryptographic kernel: **READY** (scoped) — **conditional on committing 3 working-tree files** (F-2 closed, all mechanical gates green on the *working* tree)

**Honesty caveat (read first):** the full lane is **exit 0 on the WORKING tree**, which is HEAD `f21885e` **plus three uncommitted files**: `READINESS.md`, `AUDIT_INDEPENDENT_VERDICT.md`, and — load-bearing — `scripts/ci/check-test-vectors.sh`. The committed tree `f21885e` by itself is **RED**: `cross-implementation-vectors` fails with `receipts partial: missing .../receipts/zk` because the committed `check-test-vectors.sh` treats the `zk/` *directory* partial-vector entry as a single file. Proven this run by swapping the committed script back in. **Until those files are committed, F-1's "green on the committed tree" is NOT satisfied.** No commit was made (per instruction).

**Why the split is honest:** the headline mission includes *multi-agent, two-machine* convergence (§11 object sync, §17.7 cross-host determinism). Those are **not implemented** (see F-4/F-5 below) — `mnemed` gossips root hashes only and "two-machine" is a same-host dual-workspace digest check. As a **single-host verifiable-memory kernel**, the substrate is now defensible: the High-severity replay hole (F-2) is fixed and proven through the public CLI, the TCB is back under budget, and the lanes pass on the working tree.

| Scope | Verdict |
|---|---|
| 90-day v0 single-host kernel | **READY (conditional)** — all gates green on working tree; **must commit the 3 files above** to make the committed tree green (F-2 fixed) |
| 12-month / "complete" / multi-machine | **NOT READY** — §11 object sync absent, §17.7 cross-host unproven, Plonky2/ZK stubbed |

---

## F-2 (High) — A-REPLAY cold-open rollback — **FIXED & PROVEN**

**Threat (INV-6, §2.4):** an A-DB adversary rolls `roots/HEAD` back to a fully self-consistent, validly-signed *older* snapshot while the newer checkpoint is still on disk; the kernel must reject it.

**Before (HEAD `84fac33`, pre-fix) — VULNERABLE** (`attacks/replay-before.log`):
```
mneme verify <rolled-back>  → verify ok: root seq 2 objects 1   (exit 0)   ← ACCEPTED
mneme recall secret         → VALUE-1                            (exit 0)   ← stale served as truth
```

**After (this tree) — FAIL-CLOSED** (`attacks/replay-after.log`):
```
mneme verify <rolled-back>  → mneme: verify failed                         (exit 4)
mneme recall secret         → mneme: root replayed (older than last seen HLC) (exit 5, RootReplayed)
control (legit seq3 store)  → VALUE-2                                       (exit 0)  ← no false positive
```

**Fix (minimal, correct):**
- `mneme-root::max_signed_checkpoint()` scans the append-only checkpoint log (`roots/<seq>.root.cbor`), verifying each file's Ed25519 signature under the operator key, and returns `(max_seq, hlc_max)`.
- `Store::open` **and** `verify_store` (TCB) now: reject when an on-disk signed checkpoint sequence **exceeds** HEAD (`RootReplayed`), and pin `last_seen_hlc` from the log's max so `check_replay` enforces the monotonic floor.
- The `.incomplete` transaction guard covers the `append→write_head` crash window, so the new check only fires on a genuine rollback (kill/resume gate stays green — 5/5).
- **Public-path test** (not unit trust injection): `cli_e2e::f2_replay_rollback_to_signed_snapshot_rejected_through_public_paths` drives the real `mneme` binary + `Store::open`; red before the fix, green after. The pre-existing `hostile_areplay_rollback_resurrects_forgotten_entry_on_cold_open` now asserts `RootReplayed` at cold open.

**Downgrade-policy honesty (out-of-band trust):** the *delete-the-newer-checkpoint* variant (attacker removes `roots/3.root.cbor` entirely) produces a tree byte-indistinguishable from a legitimate seq-2 store. It **cannot** be rejected at cold open from the filesystem alone; defending it requires an out-of-band pinned trusted root/HLC. The CLI still exposes no trust-pin flag — this is the documented residual (see Remaining blockers). The fix closes the on-disk-detectable rollback (the F-2 attack as reproduced) completely.

---

## Reality-check gates (working tree = HEAD f21885e + 3 uncommitted files, isolated target)

Evidence: `out/readiness/continue-hard-20260530T122918Z/logs/`.

| Gate | Command / script | Result | Log |
|---|---|---|---|
| fmt | `cargo fmt --all -- --check` | **exit 0** | `fmt-before.log` |
| clippy | `cargo clippy --workspace --all-targets -- -D warnings` | **exit 0** (after fixing 4 pre-existing lints) | `clippy.log` |
| build | `cargo build --release --workspace` | **exit 0** | `build.log` |
| TCB lines | `wc -l crates/mneme-verify/src/*.rs` | **456 / 500** (was 510 — over budget — on committed tree) | `tcb.log` |
| TCB guard | `verify-tcb-guard.sh` + `tcb_budget` + `tcb_guard` | **exit 0** | `tcb.log` |
| Tamper inventory | verify suites + `tamper_inventory_matches_executed_verify_tests` | **147** (60+28+17+32+10), inventory test PASS | `tamper-forgery.log` |
| Forgery per verifier | `forgery_verifiers` | **9/9** (8 required + store-object), typed errors | `tamper-forgery.log` |
| Kill/resume | `kill-resume-smoke.sh` | **exit 0** (5/5 boundaries) | `kill-resume.log` |
| Fuzz smoke | `fuzz-smoke.sh` (6 targets) | **exit 0**, 0 crashes | `fuzz-smoke.log` |
| Foundation-gate ×2 | `validation-lane.sh determinism` + `check-foundation-digests.sh` | **exit 0**, byte-identical, pinned digests match | `determinism.log` |
| Cross-impl vectors | `cross-implementation-vectors.sh` | **exit 0** (after fixing committed `check-test-vectors.sh` dir-partial bug) | `cross-impl.log` |
| Killer demo §21 | `killer-demo.sh` | **exit 0** (Agent-A vs Agent-B + A-DB/A-INJ + bypass) | `killer-demo.log` |
| Replay attack re-test | `attacks/replay-{before,after}.log` | **FAIL-CLOSED after fix** (see F-2) | `attacks/` |
| Bench recall @ 10k | `bench-recall-optional.sh` | **305.79 µs** < 1000 µs gate (populate 208 s, not gated) | `bench-recall.log` |
| Validation lane | `validation-lane.sh full` | see footer / `validation-lane-full.log` | `validation-lane-full.log` |

### Pre-existing regressions found and fixed (the committed tree did NOT reproduce the prior "all green")
The independent audit measured `499/500` TCB and a clean tree; the committed tree had since drifted. This run found and corrected:
1. **TCB over budget — 510/500** (`tcb_budget` was RED): removed a dead `#[deprecated] verify_store_head` shim from the TCB and relocated the non-trust-critical key-index reconstruction to `mneme-index::load_key_index_tree` (its SMT root is still checked against the signed root, so it is not trust-bearing). TCB → **456/500**.
2. **clippy `--all-targets` RED**: `tests/bench_recall.rs` `match_result_ok`; `tests/chaos/helpers.rs` `too_many_arguments`, `field_reassign_with_default`, `permissions_set_readonly_false`.
3. **`check-test-vectors.sh` RED** (hence `cross-implementation-vectors.sh` and the `full` lane fail-closed): `partial_vectors` directory entries (`receipts/zk/`) were validated as files; now validated as non-empty directories.

These were genuine "claimed-green-does-not-reproduce" defects — fixed, not papered over.

---

## F-4 / F-5 (Medium) — sync & two-machine claims **DOWNGRADED to honest scope**

**F-4 — `mnemed` is a root-gossip stub, not §11 object sync.** `crates/mnemed/src/sync.rs` implements only `0x01 Hello`, `0x02 RootProof`, `0x07 Bye`. There is **no** `0x03 DiffReq / 0x04 DiffResp / 0x05 WantObjects / 0x06 HaveObjects`, **no object transfer**, and therefore **no per-object re-hash/re-verify-on-receipt over the wire**. The only convergence proof (`two_peer_sync.rs`) is `Store::merge_from_path` — a **local-filesystem** directory merge on one host. Multi-agent object convergence over the network is **NOT delivered**. We chose honest docs over a fake sync wire (§11 deferred).

**F-5 — "two-machine determinism" is same-host dual-workspace CI reproducibility, not §17.7 cross-host.** `determinism-two-machine.sh` reproduces byte-identical digests in dual-workspace mode but the script itself states this is "NOT §17.7 cross-host proof" and gates the real proof behind `MNEME_SECOND_HOST` (unset here). Cross-host determinism is **OPEN**.

---

## Remaining blockers (brutal)

**Blocks even the scoped single-host READY (do this first):**
0. **The committed tree `f21885e` is RED.** The green `validation-lane full` run depends on three **uncommitted** files (`READINESS.md`, `AUDIT_INDEPENDENT_VERDICT.md`, `scripts/ci/check-test-vectors.sh`). Re-checked this run by restoring the committed `check-test-vectors.sh`: `cross-implementation-vectors` fails (`receipts partial: missing .../receipts/zk`). **Commit those three files, then re-run `validation-lane.sh full` on the committed checkout** before claiming F-1. No commit was performed (per instruction), so this remains OPEN.

**For unqualified / 12-month READY (all OPEN):**
1. **§11 network object sync** — implement `DiffReq/DiffResp/WantObjects/HaveObjects` + receive-time re-hash/re-verify, or keep `mnemed` honestly labelled "root gossip only." Until then multi-agent convergence is single-host file-merge only. (F-4)
2. **§17.7 cross-host determinism** — real second physical host (`MNEME_SECOND_HOST` + `determinism-two-machine.sh`); dual-workspace does not close it. (F-5)
3. **Plonky2/ZK retrieval** — `commitment_binding` is a tagged BLAKE3 envelope (honestly labelled "not ZK / not SNARK / not Plonky2"); the 12-month ZK backend is a fail-closed stub. (B3)
4. **Sustained fuzz** — only smoke + `fuzz-meaningful` (≥30s/target) are wired; no nightly `-runs≥10000` corpus soak. (B6)
5. **Live agent/MCP CI** — `mcp-agent-sim` exercises the real stdio subprocess, not a live Claude agent loop.

**Residual for the single-host kernel (defense-in-depth, not blocking the scoped READY):**
6. **A-REPLAY downgrade policy (F-2 residual)** — the delete-newer-checkpoint variant needs an out-of-band trust pin; CLI exposes no `--pin-root`/`--last-seen-hlc` flag. On-disk-detectable rollback is fully closed.
7. **F-3** — checkpoint-log files other than HEAD are not re-verified field-by-field against HEAD (HEAD is signature-gated; low impact).
8. **F-6** — TCB `verify_recall` returns ciphertext labelled `plaintext` and omits the missing-key=Forgotten check (done one layer out in `mneme-store`); agent path is safe via tombstone gate.
9. **F-7** — no perf gate on the semantic/ANN recall path; the <1 ms figure is the key-index path only.

---

## Honesty boundary (§3)

**PASS** — `commitment_binding`/`zk` alias is explicitly "not zero-knowledge / not SNARK / not Plonky2 / not truth" in error strings, API, and docs, with enforcement tests. No `todo!`/`unimplemented!` on production paths; no fabricated metrics in this report — every number traces to a log under the evidence root.

---

## Deployment readiness

| Label | Status |
|---|---|
| 90-day v0 single-host kernel | **READY** (scoped; F-2 closed, gates green) |
| 12-month / complete / multi-machine | **NOT READY** |

**Re-assessment trigger:** §11 object sync + §17.7 cross-host proof + sustained fuzz; evidence to a fresh `out/readiness/<date>/`.

---

*TestingRealityChecker · default = NOT READY · evidence over claims · `out/readiness/continue-hard-20260530T122918Z/`*
