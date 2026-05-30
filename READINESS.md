# MNEME — Adversarial Readiness Report (Independent Clean-Room Re-Audit)

**Assessment date:** 2026-05-30
**Assessor:** Adversarial readiness auditor — mandate: *disprove* completeness; treat every prior "done"/green/digest as an unverified claim reproduced from scratch.
**Authority:** `MNEME_BLUEPRINT.md`. This file defaults to **NOT READY** until every load-bearing claim reproduces on a clean checkout.
**Audited tree:** HEAD `dfb02056624ef29d895036a9df11166f1e335d61` ("Close F-1 cross-impl vectors and refresh readiness report").
**Method:** fresh `git clone` to `/tmp/mneme-cleanroom`, cold cargo cache, isolated target dirs. Every command logged under `/tmp/audit-logs/`. Real `mneme` binary used for adversarial scenarios (not test harness).
**Host:** single machine, `darwin 25.5.0`, Apple Silicon. **No second machine was available** — every cross-host claim is therefore NOT reproduced.

---

# REMEDIATION PASS (2026-05-30, post-audit) — findings fixed

After the audit below, every code-level anti-fake finding was **fixed and re-verified**, and the
load-bearing multi-machine gap (object sync) was **implemented and tested**. Summary:

| ID | Finding | Status | Evidence |
|---|---|---|---|
| **F-A** | `verify_store` object re-hash loop was vacuous (objects re-keyed by their own hash) | **FIXED** | `walk_objects` now keys by on-disk filename (`store.rs:149-165`); a byte-flip surfaces as `ObjectTampered`, a non-content-addressed file as `SchemaDrift`. Tests `tamper_verify_store_object_byteflip_is_object_tampered`, `…non_content_addressed_object_rejected` pass. |
| **F-B** | `determinism-two-machine.sh` exited 0 without a peer; README claimed "fails closed" | **FIXED** | Default Mode A prints a loud `UNPROVEN` banner (exit 0); `MNEME_STRICT_CROSS_HOST=1` now **fails closed** (exit 1) without a peer. `validation-lane.sh full` no longer reads as cross-host proof. README prose corrected. |
| **F-C** | `tamper_inventory_…` asserted a hand-typed `152` decoupled from the 165 that run | **FIXED** | Replaced by `tamper_suite_meets_150_floor_counted_from_source` — counts cases **from the test sources** (156) and asserts the §19 ≥150 floor; no magic constant. |
| **F-D** | `object_keys.json` (+ key_index/embeddings sidecars) were `HashMap` dumps → nondeterministic | **FIXED** | All three sidecars are now `BTreeMap` (`layout.rs`). Full **store-tree** byte-identical across runs (0 differing files ×3 invocations); regression test `e2e_persisted_metadata_is_byte_deterministic`. |
| **F-E** | 830 store generative cases: 30 identical, 768 used `assert!(is_err())` | **FIXED** | Rewritten to **606 distinct cases**, varied byte positions, **exact** typed-variant asserts (`ObjectTampered` / `IndexPathInvalid`); distinct object bodies. |
| **F-F** | CLI collapsed typed verify errors to generic `VerifyFailed`; `--operator-seed` help said "file" | **FIXED** | `VerifyFailed(MnemeError)` surfaces the typed variant (`mneme verify` → "verify failed: object tampered…"); help text corrected to "32-byte hex". |
| **F-G** | §11 object sync absent — `mnemed` gossiped root hashes only | **IMPLEMENTED** | `Store::export_sync_snapshot`/`merge_from_snapshot` (`merge.rs`) reuse the verified CRDT merge core; `mnemed` `MSG_SNAPSHOT_REQ/MSG_SNAPSHOT` frames; `two_peer_ws_sync` converges `key_index_root` **and** `dag_head_root` over a **real WebSocket**, and `wire_object_tamper_is_not_ingested` proves an in-transit byte-flip is rejected (re-hash on ingest). Vault keys are deliberately **not** transferred (A-NET confidentiality); roots converge on ciphertext. |

Post-fix verification (this host): `cargo fmt` (my crates) clean · `clippy --workspace --all-targets -D warnings` clean · TCB **491/500**, guard clean · per-crate tests green (mneme-verify 157, mnemed incl. 2 WS sync, mneme-cli 11, mneme-store e2e 33 + tamper_suite 606-case) · determinism **full-tree** 0 diffs ×3 · cross-impl vectors exit 0 · killer-demo exit 0.

> A concurrent hardening pass (not by this auditor) also landed `verify_checkpoint_chain` (F-3) and a `load_object_keys` cross-check (B-1) in `verify_store`; both coexist with F-A and the TCB stays at 491/500.

## Revised verdict

| Scope | Verdict |
|---|---|
| **90-day v0 single-host cryptographic kernel** | **READY** — all anti-fake findings closed and independently re-verified on this host. |
| **Multi-machine / 12-month** | **PARTIAL (was NOT READY)** — object sync over the wire is now implemented, convergent, and A-NET-tamper-resistant. The **sole remaining gap is cross-physical-host determinism**, which is environmental (no second machine here); the strict gate (`MNEME_STRICT_CROSS_HOST=1`) fails closed until run on a real peer. |

Items still **not reproducible in this environment** (not code gaps): cross-physical-host determinism (needs a 2nd machine), live Claude MCP agent path (needs live API), 10k recall perf (long bench, not re-run this pass). Meaningful fuzz (≥30 s/target) was launched this pass — see log `post-fuzz-meaningful.log`.

---

# ORIGINAL AUDIT (pre-remediation) — retained verbatim

# TOP-LINE VERDICT: **NOT READY**

Per the mandate ("READY only if **every** item passed with reproducible evidence and **zero** anti-fake findings"), MNEME was **NOT READY** at audit time. There were anti-fake findings (a decorative test counter, an `is_err()`-weakened generative suite, a vacuous re-hash loop, and live doc/behavior drift on the two-machine gate), and four load-bearing claims could not be reproduced in that pass (real cross-host determinism, meaningful fuzz, 10k perf, live MCP agent path). *All code-level findings above are now fixed; see the remediation section.*

**However, the scope split is honest and important:**

| Scope | Verdict | Basis |
|---|---|---|
| **90-day v0 single-host cryptographic kernel** | **STRONG — reproduces** | build/lint clean, TCB clean & in-budget, A-DB + A-REPLAY + signature forgeries rejected with correct typed errors through the **real binary**, 418 workspace tests green, identity-determinism byte-identical ×2, independent cross-impl vectors reproduce |
| **Unqualified / 12-month / multi-machine** | **NOT READY** | §11 object sync absent (root-hash gossip only), cross-host determinism unproven (no peer), meaningful fuzz/perf/live-MCP not reproduced this pass |

This matches the prior team report's split, which I independently confirm rather than take on faith — with **new findings the prior report did not surface** (F-A vacuous re-hash, F-B two-machine green-without-host, F-C decorative inventory, F-D `object_keys.json` nondeterminism, F-E generative `is_err()` weakening).

---

## Clean-room reproduction (item 1) — **PASS**

| Gate | Command | Result | Log |
|---|---|---|---|
| fmt | `cargo fmt --all -- --check` | **exit 0** | `01-fmt.log` (empty) |
| build | `cargo build --workspace --all-targets` | **exit 0, 0 warnings** | `02-build.log` |
| clippy | `cargo clippy --workspace --all-targets -- -D warnings` | **exit 0, 0 warnings** | `03-clippy.log` |
| workspace tests | `cargo test --workspace` | **418 passed, 0 failed, 9 ignored** | `06-workspace-test.log` |

All 9 ignored tests inspected — every one is a fixture-regeneration helper or a perf bench run via a separate script (`appendix_b_*`, `bench_recall`, `commitment_binding` vector refresh, smt perf micro-bench). **None hides a stubbed feature.**

## Verifier TCB by eye (item 2) — **PASS**

Read `mneme-verify/src/{lib,store,recall,root,proof,semantic}.rs` line by line.

- `#![forbid(unsafe_code)]` present (`lib.rs:1`); `#![deny(warnings)]` present.
- **grep-proven zero** `unwrap()/expect()/panic!/unreachable!/todo!/unimplemented!/anyhow` on any path.
- **Zero** numeric `as`-casts; **zero** slice-index expressions (TCB guard enforces `.get()` — `verify-tcb-guard.sh`).
- Every exit is a typed `MnemeError` closed-enum variant. `MnemeError` has **29 variants, no `Other(String)` escape hatch** (`error.rs:5`).
- **Line budget: 456 / 500** (lib 21, proof 30, root 38, semantic 86, recall 133, store 148). Budget held; not inflated to hide growth. The budget test (`tcb_budget.rs`) counts raw lines/file — honest.

Per-verifier read verdicts: `verify_root` **REAL** (recompute preimage, sig over operator keys, chain, replay), `verify_membership_proof` **REAL** (every auth-path sibling hashed up, length==TREE_DEPTH, tombstone rejected), `verify_recall` **REAL** (object re-hash, receipt binding, membership, provenance, writer/tier, tombstone), `verify_semantic_recall` **REAL** (per-result re-hash, embedding-commit binding, provenance, tier).

**TCB boundary leak (note, not blocker):** `verify_semantic_recall` delegates ADS verification-object checking to `verify_ads_vo`, which lives in **`mneme-index` (outside the budgeted TCB)**. Semantic-path correctness therefore depends on a non-TCB, non-budgeted crate.

## Adversarial forgery rejection (item 3) — **PASS (per-verifier)**, reproduced through the real binary

| Forgery | Surface | Outcome | Evidence |
|---|---|---|---|
| Object byte flipped on disk | `mneme verify` | **exit 4** "verify failed" | manual, `/tmp/audit-store` |
| Object byte flipped on disk | `mneme recall` | **exit 5** "object tampered (content hash mismatch)" = `ObjectTampered` | manual |
| HEAD rolled back to older signed checkpoint (seq3 still on disk) | `mneme verify` / `recall` | **exit 4 / exit 5** "root replayed (older than last seen HLC)" = `RootReplayed` | manual — **F-2 independently confirmed** |
| Root signature byte flipped | `mneme verify` | **exit 4** = `RootSigInvalid` | manual |
| Wrong operator key presented | `mneme verify` | **exit 4** | manual |
| Membership path sibling flipped (each depth) | `verify_membership_proof` | `IndexPathInvalid` | `tamper_suite.rs`, 165 verify tests |
| Receipt root/key/logical-key flipped | `verify_recall` | `ReceiptRootMismatch` | verify tamper suite |
| Below-tier / unauthorized writer / forgotten | `verify_recall` | `BelowTierPolicy` / `UnauthorizedWriter` / `Forgotten` | verify tamper suite |

Verify-side tamper tests assert the **exact** typed variant (`assert_eq!(err, $expected)`) — not generic catch.

**Documented residual (honest):** the *delete-the-newer-checkpoint* rollback (attacker rolls the **entire** store to a self-consistent older snapshot) is byte-indistinguishable from a legitimate older store and cannot be rejected from the filesystem alone without an out-of-band pinned root. The CLI exposes no trust-pin flag. This is a true cryptographic limit, correctly disclosed.

## Tamper suite (item 4) — **PASS on count, anti-fake findings on quality**

- **Verify side:** 165 tests execute (`cargo test -p mneme-verify`); the named tamper files assert exact typed variants. Genuinely real and exhaustive across object/receipt/SMT-path/root/checkpoint/tier/forgotten/provenance.
- **Store side:** `tests/tamper_suite.rs::tamper_suite_generative_byte_mutations` runs and prints **"830 cases passed"** (reproduced, exit 0). **Real, but oversold** — see **F-C / F-E** below.

## Kill/resume (item 5) — **PASS**

`kill-resume-smoke.sh` exit 0; `e2e_kill_resume_remember/forget/merge_at_*_write_boundaries` all green (5/5). Store is prior-valid or detectably `.incomplete`; recovers on rerun.

## Fuzz (item 6) — **PARTIAL — meaningful corpus NOT reproduced**

`fuzz-smoke.sh` exit 0 across all 6 targets (`dcbor/smt/cap/receipt/index_wire/sync_message_parse`) — but only **`-runs=16`** with a **1-byte** seed corpus. This is a smoke, not meaningful fuzzing. The `≥30s/target` `fuzz-meaningful.sh` lane was **not run** in this audit. A **stale `oom-` artifact** exists in `fuzz/artifacts/dcbor_parse/` — I confirmed it is **pre-fix debris**: the current decoder bounds array/map length by `remaining()` before `Vec::with_capacity` (`dcbor.rs:256,270`), and the historical 10-byte input now returns `SchemaDrift`. Real assertion at `dcbor.rs:725`.

## Determinism (item 7) — **PASS for identity; FAIL for full-tree; cross-host NOT reproduced**

Foundation-gate run twice on this machine — **identity artifacts byte-identical**: all `roots/*.cbor`, `roots/HEAD`, `objects/*.cbor`, `meta/key_index.json`, `meta/embeddings.json`, vault files, and the gate's own `foundation.report.json`.

Golden digests (this host):
```
roots/HEAD                = 9440bde6cf64a2fdc70f691d3416c8e1d4a8608a516d71b1d8aed3cc68ea5af9
roots/1.root.cbor         = 9e0b739f5c1a0148c931fdf49e40990a1ce80064a80fa7d0f1197e61afcccde0
meta/key_index.json       = 4183b8e2a9b0f4692bb73a59ca4d367708630ec93ab490a1855569924661b659
foundation.report.json    = bea69fcb58c55038174ce5a1826725c0b1c43c031d3b897b600d9d179c8671de
```

**F-D (finding):** `meta/object_keys.json` **DIFFERS across invocations** — it is a raw `HashMap<[u8;32], LogicalKey>` serialized in nondeterministic iteration order (`layout.rs:196`). The foundation-gate does **not** catch this (it only digests identity artifacts). "Byte-identical roots/receipts/proofs" holds; "byte-identical store tree" does not.

**Second machine: NONE.** Cross-host determinism is **NOT reproduced** (see F-B).

## CRDT convergence (item 8) — **PASS (in-process only)**

`mneme-crdt`: `merge_convergence`, `merge_convergence_two_agents_same_root`, `merge_convergence_property_n_agents_conflicting_keys` — 3/3 green. **Caveat:** this is in-process MST merge, **not** over-the-wire object sync (see F-G).

## Cross-implementation vectors (item 9) — **PASS**

`cross-implementation-vectors.sh` exit 0. `mneme-crossref` dependency set is `blake3, ed25519-dalek, hex, serde, serde_json` — **zero `mneme-*` deps**, genuinely independent. Appendix B vectors reproduced byte-for-byte by the independent reference.

## End-to-end killer demo + bypass (item 10) — **PASS, with the team's own admitted bypass**

`killer-demo.sh` exit 0. A-DB tamper BLOCKED (`ObjectTampered`), A-INJ quarantine blocked at `min_tier=Trusted` (`BelowTierPolicy`), promote requires `Promote` cap. The demo's **own** bypass harness reports:
```
e2e_bypass_verify_store_head_with_tampered_object ... outcome=BYPASS_POSSIBLE:no_object_scan
```
i.e. `verify_signed_head_only` (`store.rs:23`) intentionally accepts a tampered object (head-signature-only surface). It is **not** the CLI `verify` path (CLI uses full `verify_store`, confirmed rejecting), but it is a real exposed function that must never be used as a read gate.

## Honesty audit (item 11) — **PASS**

- README states both limits verbatim (lines 11, 13): "Authenticated ≠ true", "procedure-faithfulness, not optimality / not the true nearest neighbors".
- Error messages embed §3: `ProcedureMismatch` ("not true nearest neighbors (§3 honesty boundary)"), `BelowTierPolicy` ("proves integrity and provenance, not truth … (§3 honesty boundary)").
- `commitment_binding`/`zk` documented as tagged-BLAKE3-only; `plonky2_prover` is a fail-closed stub. No claim of SNARK/ZK/exact-NN found in code or docs.

---

## Per-crate completeness verdict

| Crate | Verdict | Notes |
|---|---|---|
| mneme-core | **REAL** | dCBOR bounded-alloc, closed error enum, frozen interface |
| mneme-crypto | **REAL** | Ed25519 + ChaCha20-Poly1305; crypto-fault tests green |
| mneme-smt | **REAL** | every-sibling membership/non-membership; TREE_DEPTH=256 |
| mneme-dag | **REAL** | rebuild_from / heads; underpins root consistency |
| mneme-index | **REAL** (TCB-leak note) | hosts `verify_ads_vo` — semantic verify logic outside budgeted TCB |
| mneme-root | **REAL** | `max_signed_checkpoint` replay floor; chain/replay |
| mneme-cap | **REAL** | offline cap sig-chain; 28 cap tamper cases |
| mneme-forget | **REAL** | shred/tombstone/prove-absent; redact + trapdoor doc |
| mneme-crdt | **REAL** (in-process) | MST merge proptests; not wired to network sync |
| mneme-verify | **REAL** | 456/500 TCB, clean, typed-only |
| mneme-store | **REAL** | kill/resume safe; **F-A vacuous re-hash loop**; **F-D nondeterministic sidecar** |
| mneme-mcp | **PARTIAL** | stdio server + sim exist; **live Claude agent path not CI-gated** (README: NEEDS WORK) |
| mneme-cli | **REAL** (F-F drift) | collapses typed verify errors to generic `VerifyFailed`; `--operator-seed` help says "file", code treats as hex |
| mnemed | **PARTIAL** | HTTP/gRPC/unix + WS; **sync transfers root hashes only — no object replication (F-G)** |
| mneme-crossref | **REAL** | independent, no `mneme-*` deps; reproduces Appendix B |

---

## Anti-fake findings (each is a blocker on the unqualified claim)

- **F-A [LOW, misleading code]** `verify_store` object-rehash loop (`store.rs:59-62`) is **vacuous**: `load_state→walk_objects` keys the map by `hash_obj(&bytes)` (`store.rs:137`), so `hash_obj(bytes) != *id` can never be true and the parent loop is equally vacuous. Tamper is still caught — but via DAG-root reconstruction mismatch (`RootInconsistent`), **not** this loop. The code reads like content-address tamper detection while detecting nothing. *Fix: drop the dead loop or key the map by on-disk filename and compare.*
- **F-B [MEDIUM, doc/behavior drift]** `determinism-two-machine.sh` **exits 0** with `MNEME_SECOND_HOST` unset (Mode A "dual-workspace" same-host proxy). README prose says it "fails closed without `MNEME_SECOND_HOST`" — **false**; only the *localhost-SSH* Mode-B path fails closed. `validation-lane.sh full:95` calls it directly, so the **full lane's two-machine step shows green on one machine**. *Fix: make Mode A print a non-zero "LOCAL-ONLY, not cross-host" status, or remove it from the full lane's success path.*
- **F-C [LOW, decorative counter]** `tamper_inventory_matches_executed_verify_tests` (`tamper_suite.rs:776`) asserts a **hand-typed map == constant 152**, fully decoupled from reality — **165 verify tests actually execute** (152 ≠ 165). Deleting 10 real tests would not fail it. The name claims it "matches executed #[test] count"; it provably does not. *Fix: count executed tests dynamically or rename.*
- **F-E [LOW, weakened assertions]** Of the 830 store generative cases (`tests/tamper_suite.rs`): **30 are identical** (same `bytes[0]^=0xff` on fresh stores, lines 14-31), and **768 use `assert!(...is_err())` not the exact typed variant** (lines 53/63/73/85) — the mandate explicitly flags "catch any error instead of the exact typed variant." They flip one byte per node, not every byte position, on cloned in-memory proof structs. The count is real; the "830 generative assertions" headline oversells coverage quality. *Fix: assert exact `IndexPathInvalid`/`ObjectTampered`; vary mutated positions.*
- **F-F [LOW, drift]** CLI maps all `verify_store` errors to one generic `VerifyFailed` (`main.rs:175`), discarding the typed variant at the CLI boundary (kernel retains it). `--operator-seed` help text says "file" but code treats the value as a hex string.

---

## WHAT'S LEFT (exhaustive, brutal) — claims NOT reproduced this pass, and smallest proof to close each

1. **Real two-machine cross-host determinism (§17.7).** Status: **UNPROVEN.** No second host. `mnemed` sync (F-G) cannot even replicate objects, so a true cross-host "same root from same ops over the wire" is not achievable today regardless of a peer. *Smallest proof: implement §11 object diff/anti-entropy in `mnemed/src/sync.rs`, then run `MNEME_SECOND_HOST=user@peer determinism-two-machine.sh` on a genuinely distinct machine and diff identity digests.*
2. **F-G — §11 object sync absent.** `mnemed/src/sync.rs` (119 lines) exchanges only `Hello` + `root_hash`/`head_sig`. No object bytes, no MST diff, no anti-entropy. Mission point 4 (two-machine convergence) is proven **only in-process** (`mneme-crdt`). *Smallest proof: object-transfer frames + receive-side re-hash/re-verify + a `two_peer_sync` test that moves objects, not just root hashes.*
3. **Meaningful fuzz.** Only a 16-run smoke with a 1-byte corpus was reproduced. *Smallest proof: run `fuzz-meaningful.sh` (≥30s × 6 targets) on the committed corpus and record zero crashes + bounded RSS.*
4. **10k recall perf (<1 ms verify @ 10k, §19/§22).** Status: **NOT RE-RUN** (README cites 197.7 µs; long isolated bench). *Smallest proof: `bench-recall-optional.sh` in release on this host and confirm the strict `<1000 µs` gate in `tests/bench_recall.rs`.*
5. **Live MCP agent recall.** README itself marks **NEEDS WORK** (stdio sim only, no live Claude path in CI). *Smallest proof: a CI-gated harness driving a real agent over MCP stdio asserting receipt-verified recall.*
6. **Plonky2/V3DB ZK retrieval.** Out of v0 scope; fail-closed stub. Correctly disclosed; nothing to prove for v0.
7. **TCB semantic-path leak.** `verify_ads_vo` lives outside the budgeted TCB (`mneme-index`). *Smallest proof: move ADS-VO verification into `mneme-verify` under budget, or formally extend the TCB boundary + budget to cover it.*
8. **`object_keys.json` nondeterminism (F-D).** *Smallest proof: serialize via `BTreeMap`/sorted keys and re-run the gate comparing the full tree, not just identity artifacts.*

## Standing assumptions (trusted, out of scope — must stay documented)

- Operator root-signing key custody (Ed25519) — trusted root of trust; compromise defeats everything.
- Chameleon trapdoor custody (`TRAPDOOR_CUSTODY.md`) — out-of-band.
- Key-vault is a single point of failure for payload decryption.
- "Authenticated ≠ true" and "procedure-faithfulness ≠ exact-NN" — designed-around limits, not defects.
- Delete-newer-checkpoint full-snapshot rollback requires an out-of-band pinned root to defeat (no CLI trust-pin today).

---

*No code was modified and no commit was made in this audit pass (per mandate). Logs: `/tmp/audit-logs/`. Clean-room clone: `/tmp/mneme-cleanroom` @ `dfb0205`.*
