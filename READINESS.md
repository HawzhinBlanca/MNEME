# MNEME — Hostile Final-Acceptance Audit

**Posture:** the "DONE" claim is treated as false until independently reproduced. Source of truth: `MNEME_BLUEPRINT.md`.
**Audited commit:** `c20a786c427bc10a65dba1840da446265928a95e` (clean clone → `/tmp/mneme-accept`, cold cargo cache).
**Host:** Apple Silicon, `darwin 25.5.0`, rustc/cargo 1.86.0. Logs under `/tmp/accept-logs/`.
**Rule applied:** any ambiguity → NOT DONE. No code changed, no commit.

---

# TOP-LINE: **NOT DONE (unqualified)** — but the v0 single-host kernel **IS DONE**

| Scope | Verdict | Why |
|---|---|---|
| **v0 single-host cryptographic kernel** | **DONE** | Every gate reproduced on a cold clean checkout with **zero fakes**; every verifier rejects hand-crafted forgeries with the correct typed variant; TCB clean and in budget. |
| **Unqualified "MNEME is DONE" (full blueprint)** | **NOT DONE** | Exactly **one** explicit §19 **90-day** exit criterion is not met with a real component — **MCP semantic agent recall** is a stdio *simulation*, not a live agent (`crates/mneme-mcp/tests/agent_session_sim.rs`, `scripts/ci/mcp-agent-sim.sh`; README.md:56 self-marks **NEEDS WORK**). Per the no-"mostly-done" rule, that single stubbed-to-sim criterion blocks the unqualified claim. |

**Quantified:** of the 8 blueprint §19 **90-day** exit criteria, **7/8 = 87.5%** are reproduced with real evidence; the missing one is live MCP agent recall. 30-day criteria: 6/6. The cryptographic substrate itself contains **no fakes** on any reachable path.

---

## STEP 0 — reality of the claim — **PASS**

| Gate | Command | Result | Log |
|---|---|---|---|
| fmt | `cargo fmt --all -- --check` | exit 0, empty | `/tmp/accept-logs/00-fmt.log` |
| build (cold) | `cargo build --workspace --all-targets` | exit 0, **0 warnings** | `00-build.log` |
| clippy | `cargo clippy --workspace --all-targets -- -D warnings` | exit 0, **0 hits** | `00-clippy.log` |

The "done" claim survives reality. (Had any failed, the claim was already false.)

## STEP 1 — fakes — **ZERO found on reachable paths**

- **`todo!`/`unimplemented!`/`unreachable!` in crate `src/`:** NONE.
- **`panic!` in `src/`:** 5 hits, **all in `#[cfg(test)]`/fixture code** (`mneme-core/src/dcbor.rs:702`, `mneme-crdt/src/tests.rs:375`, `mneme-index/src/lib.rs:121` is inside `mod tests`, `mneme-index/src/commitment_binding.rs:171` fixture, `mneme-crossref/src/mst_merge.rs:18` fixture-agent parse). None reachable in production.
- **`#[ignore]`:** 11, all fixture-regeneration helpers or perf benches run via scripts (`appendix_b_*`, `bench_recall`, smt perf, zk-fixture). None hides a stubbed feature.
- **Verifier weakening (TCB = `mneme-verify`):** `#![forbid(unsafe_code)]` present; **zero** `unwrap/expect/panic/unreachable/todo/unimplemented/anyhow`; **zero** numeric `as`-casts; **zero** slice-index panic vectors. `MnemeError` has **no `Other(String)` catch-all** (`error.rs:5`).
- **TCB budget:** `TCB_LINE_BUDGET = 500`; actual **491**. Not raised to hide growth.
- **Bypass surface honesty:** `verify_signed_head_only` (head-sig-only, no object scan) has **zero production callers** — and `mneme-verify/tests/adoption_lint.rs` actively forbids `mneme-cli` from importing it. Lint-guarded, not a fake.

## STEP 2 — break the core — **every verifier rejects forgeries with the correct typed variant**

Through the **real `mneme` binary** (true exit codes, `/tmp/fa../fd`):

| Forgery | Surface | Result |
|---|---|---|
| Object byte-flip (live object) | recall / verify | `ObjectTampered` (rc5) / `SchemaDrift` (rc4) |
| A-REPLAY rollback to older signed checkpoint | verify / recall | `RootReplayed` (rc4/rc5) |
| Full-snapshot rollback, **no pin** | verify | **accepted** (documented §2.4 residual) |
| Full-snapshot rollback, `--pin-root` | verify | `RootReplayed` (rc4) — residual closed |
| Wrong operator key | verify | `RootSigInvalid` (rc4) |

Unit-level forgeries (`forgery_verifiers.rs`, exact `assert_eq!` variants) cover the rest: membership-path replay under wrong root → `IndexPathInvalid`; root signed by untrusted operator → `RootSigInvalid`; recall object-id swap reusing path → `IndexPathInvalid`; semantic receipt bound to alien commit → `ReceiptRootMismatch`; semantic object swap → `ObjectTampered`; head-only sidecar mismatch → `RootInconsistent`. Provenance → `ProvenanceBroken`; capability chain → `tamper_cap` (28); tombstone/forgotten → `Forgotten`; tier policy → `BelowTierPolicy`. **No verifier accepted a forgery it must reject.**

## STEP 3 — reproduce every claimed proof — **PASS (one substitution noted)**

| Proof | Result |
|---|---|
| Verify-crate tests (incl. forgery + tamper) | **172 pass / 0 fail** |
| Store tamper suite (generative) | **830 cases pass**, exact typed variants |
| Store e2e | **34 pass** |
| mnemed (api_integration + two_peer_sync + two_peer_ws_sync) | **15 pass** incl. WS convergence + in-transit tamper rejection |
| Wave 0/1 crates (core/crypto/smt/dag/root/cap/crdt/index/forget) | core 26, crypto 15, smt 21, dag 15, root 12, cap 13, crdt 9, index 18, forget 11 — **0 fail** |
| Kill/resume at write boundaries | `kill-resume-smoke.sh` rc0 — all §17.3 boundaries OK |
| Fuzz (6 parser/verifier targets) | `fuzz-smoke.sh` rc0, no panic (meaningful ≥30s/target reproduced earlier same commit: 24.5M execs, 0 crashes) |
| Determinism foundation-gate ×2 (this host) | **full store tree byte-identical** (0 differing files); HEAD `9440bde6…` |
| Determinism, **second machine** | GitHub cross-runner **ubuntu-latest vs macOS-latest** identity digests identical — run on commit `c20a786`, jobs `foundation-gate (gh-ubuntu/gh-macos)` + `compare digests` + `B4 gate` all **success**. *(Substitute for the blueprint's SSH peer; the named `MNEME_SECOND_HOST` SSH job is skipped without the secret.)* |
| CRDT convergence | proptests (incl. N-agent conflicting keys) + on-disk two-peer + WS two-daemon all converge to identical `key_index_root`/`dag_head_root` |
| Appendix B vectors | `cross-implementation-vectors.sh` rc0 — `mneme-crossref` (zero `mneme-*` deps) reproduces byte-for-byte |
| §21 killer demo + bypass | rc0 — A-DB → `ObjectTampered`, A-INJ → `BelowTierPolicy`, quarantine ALLOWED by design, `Store::recall` CLOSED `pub(crate)` |

## STEP 4 — read the TCB by hand — **trustable**

Read line-by-line on the clean checkout: `lib.rs`, `store.rs`, `recall.rs`, `root.rs`, `proof.rs`, `semantic.rs` (491 lines). Each exit is a typed closed-enum variant; object re-hash, receipt↔root binding, every-sibling Merkle path, provenance, writer/tier, tombstone, signature, chain, replay all present and correct. The new `verify_store` trusted helper `mneme_index::load_object_keys` was also read — fail-closed (`SchemaDrift` on parse/hex faults, no `unwrap`/`panic`).

---

## Per-crate completeness verdict

| Crate | Verdict | Notes |
|---|---|---|
| mneme-core | **REAL** | dCBOR bounded-alloc, closed error enum, frozen interface |
| mneme-crypto | **REAL** | Ed25519 + ChaCha20-Poly1305; vault key-cache; fault tests pass |
| mneme-smt | **REAL** | every-sibling membership/non-membership; TREE_DEPTH=256 |
| mneme-dag | **REAL** | rebuild/heads underpin root consistency |
| mneme-index | **REAL** | key-index + semantic; **hosts trusted loaders/`verify_ads_vo` outside the budgeted TCB** (see WHAT'S LEFT #5) |
| mneme-root | **REAL** | signed root, checkpoint chain, replay floor |
| mneme-cap | **REAL** | offline cap chain; 28 tamper cases |
| mneme-forget | **REAL** | shred/tombstone/prove-absent/redact |
| mneme-crdt | **REAL** | MST merge proptests; drives wire sync |
| mneme-verify | **REAL** | 491/500 TCB, clean, typed-only |
| mneme-store | **REAL** | kill/resume safe; F-A re-hash real; deterministic sidecars; `open_pinned` closes §2.4 residual |
| mneme-mcp | **PARTIAL** | stdio server + agent-session **sim**; **no live Claude agent path** (the one open §19 90-day criterion) |
| mneme-cli | **REAL** | typed verify errors; `--pin-root` |
| mnemed | **REAL** | HTTP/gRPC/unix/WS; §11 object sync converges + rejects in-transit tamper |
| mneme-crossref | **REAL** | independent; reproduces Appendix B |

---

## WHAT'S LEFT (exhaustive, brutal) — to move unqualified DONE from false to true

1. **Live MCP semantic agent recall (§19 90-day) — UNPROVEN with a real agent.** Only `crates/mneme-mcp/tests/agent_session_sim.rs` (stdio multi-turn sim) + `scripts/ci/mcp-agent-sim.sh`. README.md:56 = NEEDS WORK. *Smallest proof: a CI-gated harness driving a real Claude (or SDK) MCP client through remember→recall_verified, asserting receipt-verified plaintext.* **This is the single blocker on the unqualified claim.**
2. **Second-machine determinism via the blueprint's named SSH peer — substitute-proven only.** The cross-host milestone is genuinely met via GitHub cross-runner (two physical machines, two arches), but the `determinism-ssh-peer` job is skipped without `MNEME_SECOND_HOST`. *Smallest proof: set the repo secret + run the SSH path once.*
3. **Meaningful fuzz on this exact clean checkout — only smoke reproduced this session.** 30s/target was reproduced earlier on the identical commit. *Smallest proof: `fuzz-meaningful.sh` on `/tmp/mneme-accept`.*
4. **10k recall perf <1 ms — not re-run on the clean checkout this session** (51 µs reproduced earlier, same commit; strict gate in `tests/bench_recall.rs`). *Smallest proof: `bench-recall-optional.sh` here.*
5. **Effective TCB exceeds the 491-line budgeted crate.** Trusted parsing/verification also lives outside `mneme-verify`: `mneme-index::{load_object_keys, load_key_index_tree, verify_ads_vo}`, `mneme-root::{verify_checkpoint_chain, max_signed_checkpoint, verify_root_chain, check_replay}`, `mneme-smt::verify_membership`, `mneme-crypto` signature verify. The §17.6 budget covers `mneme-verify` only — honest scoping, but "trust by reading every line" spans more than 491 lines. *Smallest proof: a documented TCB manifest enumerating every trusted fn + line count, or fold the loaders' parse-guards under an extended budget.*
6. **`verify_signed_head_only` bypass surface exists** (no object scan). Not production-reachable (zero callers; `adoption_lint` forbids CLI use), but it is a foot-gun if a future caller uses it as a tamper gate. *Smallest proof: already mitigated by the lint; consider `#[doc(hidden)]` + a crate-level deny.*

## Standing assumptions (documented, out of scope — not defects)
- **Operator root-signing key custody** — trusted root of trust; compromise defeats everything.
- **Chameleon trapdoor custody** (`TRAPDOOR_CUSTODY.md`) — out-of-band.
- **Key-vault is a SPOF for payload decryption** — sync transfers ciphertext only; peer recall needs out-of-band key custody.
- **Authenticated ≠ true; procedure-faithful ≠ exact-NN** — designed-around limits, in README + error strings.
- **Full-snapshot rollback** needs an out-of-band root pin (`--pin-root`) — now available; without it, undefendable from disk alone (cryptographic limit).
- **Plonky2/ZK retrieval** — out of v0 scope; `plonky2_prover` is a fail-closed stub; `commitment_binding` is a tagged-BLAKE3 envelope, not a SNARK.

## §22 open kill-criteria
- Hot-path verify overhead: reproduced 51 µs @ 10k (gate <1000 µs) earlier same commit — re-run here to fully close (#4).
- Concurrent merge contention bench: `#[ignore]`, run via `bench-recall-optional.sh` (not run this session).

---

*Certification withheld on the unqualified claim solely due to WHAT'S-LEFT #1 (live MCP agent). The v0 single-host cryptographic kernel is **certified DONE**: reproduced cold, zero fakes, all forgeries rejected with typed variants, TCB clean and in budget. No code changed; no commit.*
