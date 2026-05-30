# AUDIT — INDEPENDENT VERDICT (auditor-owned)

> This file is owned by an **external** security auditor with zero prior MNEME
> involvement. It is **not** the team `READINESS.md` and intentionally disagrees
> with it where independent reproduction did not match. Authority for all
> judgements is `MNEME_BLUEPRINT.md`.

## VERDICT: **NOT READY**

**Date (UTC):** 2026-05-30
**Branch:** `cursor/readiness-adversarial-audit-not-ready`
**Evidence root:** `out/audit/independent-20260530T111657Z/` (`REPORT.md`, `FINDINGS.md`, `READINESS_DELTA.md`, `logs/`, `attacks/`)
**Findings:** 7 total — **1 High, 4 Medium, 2 Low**.

### Why NOT READY (decision rule: READY only if every load-bearing claim reproduces; default NOT READY)

- **F-2 (High):** A-REPLAY rollback to a fully-consistent older signed snapshot is **accepted at cold open** — `mneme verify` returns "verify ok" and `mneme recall` serves stale memory as current truth, even with the newer checkpoint still on disk. This is a core threat-model attack the blueprint claims to *defeat* (INV-6, §2.4). The open path never consults the append-only checkpoint log and pins no `last_seen_hlc`; the replay primitive is unit-tested only with hand-injected trust state.
- **F-1 (Medium):** `cargo fmt --all -- --check` fails (29 hunks, incl. TCB `mneme-verify/src/store.rs`), so the `quick`/`full` validation lanes fail-closed at step 1 — the team's "all lanes OK / Clean" (READINESS rows 1/5/15) does not reproduce.
- **F-4 / F-5 (Medium):** §11 network sync is a root-gossip stub (no object transfer); "two agents on two machines merge" is delivered as a **local filesystem** merge, and "two-machine determinism FULLY PROVED" contradicts the project's own script and §19 status (cross-host §17.7 still open).

### What is genuinely solid (independently reproduced — do not regress)

- `cargo build --release --workspace` clean; **`cargo test --workspace --release` passes with 0 failures**.
- Verifier TCB: 499/500 lines, `#![forbid(unsafe_code)]`, guard clean (no panic/unwrap/anyhow/`as`/slice-index).
- Tamper suite: **147** verify cases + store generative ≥120, all fail-closed; e2e killer/quarantine/promote (30) green.
- A-DB read-time rejection holds (object/HEAD/key-index/delete → correct typed errors).
- A-INJ quarantine tier gate enforced (`BelowTierPolicy`, honest §3 message).
- Determinism foundation-gate digests **byte-identical** and match pinned values.
- `recall_verified` (key-index) **186.75 µs @ 10k** ≪ 1 ms.
- **§3 honesty boundary implemented with strong discipline** — explicit "not ZK / not SNARK / not Plonky2 / not exact-NN / not truth" in error strings, API, docs, with enforcement tests. No fabricated/stub code on production paths.

**Assessment:** This is a high-quality, honestly-scoped cryptographic substrate that is **over-certified**, not fraudulent. It is not "10/10 production ready." Close F-2 and F-1 (blocking) and restate the sync/two-machine claims (F-4/F-5) to reach a defensible READY.

### Conditions to upgrade to READY
1. Wire replay/rollback rejection into `Store::open`/`verify_store` (max-sequence scan of `roots/` + caller trust-pin) with a red→green test through the **public open path**. (F-2)
2. `cargo fmt --all`; demonstrate `validation-lane.sh full` green end-to-end on the committed tree. (F-1)
3. Implement §11 object sync **or** restate `mnemed`/READINESS/§19 as "local file merge; cross-host sync deferred"; mark §17.7 cross-host open. (F-4, F-5)
4. Resolve F-3/F-6/F-7 (checkpoint-file integrity vs HEAD; decrypt + missing-key=Forgotten inside the TCB or documented; semantic-path latency gate).

— External Independent Auditor

---

## REMEDIATION DELTA (2026-05-30, post-audit — team remediation, verified by reproduction)

> This section records changes made *after* the independent audit above and is **not** a re-issue
> of the external verdict. Evidence: `out/readiness/continue-hard-20260530T122918Z/`.

### Closed (reproduced fail-closed / green on the committed tree)

- **F-2 (High) — CLOSED.** Replay/rollback rejection is now wired into the **production cold-open path**.
  `mneme-root::max_signed_checkpoint` scans the append-only checkpoint log (signature-verified) and
  both `Store::open` and `verify_store` reject a HEAD whose sequence is below an on-disk signed
  checkpoint (`RootReplayed`) and pin `last_seen_hlc` from the log's max. Proven through the **public**
  CLI + `Store::open` + `recall`, not unit trust injection:
  - Before (HEAD `84fac33`): `mneme verify` → `verify ok` (exit 0); `mneme recall` → `VALUE-1` (exit 0).
    See `attacks/replay-before.log`.
  - After: `mneme verify` → exit 4; `mneme recall` → `RootReplayed` (exit 5); legit store unaffected.
    See `attacks/replay-after.log` and `cli_e2e::f2_replay_rollback_to_signed_snapshot_rejected_through_public_paths`.
  - **Residual (documented):** the delete-newer-checkpoint variant is byte-indistinguishable from a
    legitimate older store and requires an out-of-band pinned trusted root; the CLI still exposes no
    trust-pin flag. On-disk-detectable rollback (the F-2 attack as reproduced) is fully closed.

- **F-1 (Medium) — CLOSED.** `cargo fmt --all -- --check` exits 0 on the committed tree; the `quick`/`full`
  lanes no longer fail at step 1. (See validation-lane footer.)

- **Newly-found pre-existing regressions (not in the original 7, fixed) — CLOSED.** The audit's
  "499/500 TCB" and "all green" no longer reproduced on the drifted committed tree:
  1. **TCB was 510/500 (over budget, `tcb_budget` RED).** Removed a dead `#[deprecated] verify_store_head`
     shim and relocated non-trust-critical key-index reconstruction to `mneme-index::load_key_index_tree`
     (SMT root still checked against the signed root → not trust-bearing). TCB → **456/500**.
  2. **clippy `--all-targets -D warnings` RED** (`tests/bench_recall.rs`, `tests/chaos/helpers.rs`).
  3. **`check-test-vectors.sh` RED** (directory-style `partial_vectors` validated as files) → fixed;
     `cross-implementation-vectors.sh` and the `full` lane now green.

### Restated to honest scope (not "closed" — deferred)

- **F-4 (Medium) — RESTATED.** `mnemed` remains a root-gossip stub (`Hello`/`RootProof`/`Bye`); no
  `DiffReq/DiffResp/WantObjects/HaveObjects`, no object transfer, no on-wire re-verify. §11 object sync
  is **deferred**; multi-agent convergence is single-host `merge_from_path` only. READINESS now says so.
- **F-5 (Medium) — RESTATED.** "Two-machine determinism" is same-host dual-workspace CI reproducibility;
  §17.7 cross-host proof remains **OPEN** (`MNEME_SECOND_HOST` unset). READINESS now says so.

### Still open (unchanged from audit)

- **F-3, F-6, F-7 (Low)** — unchanged; documented as defense-in-depth residuals in `READINESS.md`.

### Net effect on verdict

The **High** finding (F-2) and the blocking **F-1** are closed and reproduced; F-4/F-5 are downgraded to
honest deferrals rather than fixed. This moves the **single-host v0 kernel** to a defensible **READY**;
the **unqualified / 12-month / multi-machine** system remains **NOT READY** (§11 + §17.7 + ZK + sustained
fuzz outstanding).

— MNEME team (remediation), reproductions under `out/readiness/continue-hard-20260530T122918Z/`
